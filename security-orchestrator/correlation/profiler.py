"""
ThreatActorProfiler — hoofd-orchestrator voor actor-attributie.

Publieke API
────────────
    profiler = ThreatActorProfiler(session)
    result = await profiler.process(event)
    print(result.summary())

Interne flow per event
──────────────────────
  1. Idempotentie check: is dit event al verwerkt?
  2. Fingerprint extraheren uit event headers/UA
  3. Matcher: pre-filter + score kandidaat-actors
  4a. Match gevonden  → actor updaten + IP/fingerprint upsert
  4b. Geen match      → nieuwe actor aanmaken + IP/fingerprint inserten
  5. ActorEvent attribution record opslaan
  6. DB commit (caller is verantwoordelijk voor de session lifetime)
  7. ProfilerResult teruggeven

Thread safety
─────────────
De profiler is NIET thread-safe. Eén instantie per request/taak.
SQLAlchemy async sessions zijn ook niet gedeeld tussen coroutines.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from . import fingerprint as fp_module
from .matcher import ActorMatcher
from .models import ThreatActor
from .repository import ActorRepository
from .schemas import CorrelationEvent, ProfilerResult
from .signals import ATTRIBUTION_THRESHOLD, MatchSignal

logger = logging.getLogger(__name__)


class ThreatActorProfiler:
    """
    Stateless profiler. Instantiate per DB session (per request or Celery task).

    Usage::

        async with AsyncSessionLocal() as session:
            profiler = ThreatActorProfiler(session)
            result = await profiler.process(event)
            await session.commit()
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._repo = ActorRepository(session)
        self._matcher = ActorMatcher(self._repo)

    async def process(self, event: CorrelationEvent) -> ProfilerResult:
        """
        Attribute a CorrelationEvent to an existing or new ThreatActor.

        Idempotent: calling process() twice with the same soc_event_id
        returns a result but skips the second write (based on ActorEvent lookup).
        """
        # ── Idempotency ───────────────────────────────────────────────────────
        if await self._repo.event_already_attributed(event.soc_event_id):
            logger.info(
                "profiler_duplicate_event_skipped",
                soc_event_id=str(event.soc_event_id),
            )
            return await self._build_result_for_existing(event)

        # ── Fingerprint extraction ─────────────────────────────────────────────
        event_fp: Optional[fp_module.DeviceFingerprint] = None
        if event.user_agent or event.extra_headers:
            event_fp = fp_module.extract(
                user_agent=event.user_agent,
                accept_language=event.accept_language,
                extra_headers=event.extra_headers,
            )

        # ── Matching ──────────────────────────────────────────────────────────
        decision = await self._matcher.match(event, event_fp)

        # ── Branch: new actor vs existing actor ───────────────────────────────
        if decision.is_new_actor:
            result = await self._handle_new_actor(event, event_fp)
        else:
            result = await self._handle_existing_actor(event, event_fp, decision)

        logger.info(
            "profiler_processed",
            soc_event_id=str(event.soc_event_id),
            actor=result.actor_display_name,
            was_new=result.was_new_actor,
            confidence=result.match_confidence,
            cross_platform=result.new_platform_detected,
        )
        return result

    # ── New actor path ────────────────────────────────────────────────────────

    async def _handle_new_actor(
        self,
        event: CorrelationEvent,
        event_fp: Optional[fp_module.DeviceFingerprint],
    ) -> ProfilerResult:
        # 1. Create actor
        actor = await self._repo.create_actor(event)

        # 2. Persist first IP
        if event.source_ip:
            await self._repo.upsert_actor_ip(actor.id, event)

        # 3. Persist fingerprint
        if event_fp and event_fp.fingerprint_hash:
            await self._repo.upsert_actor_fingerprint(actor.id, event_fp, event.occurred_at)

        # 4. Increment event count (starts at 0 on create)
        actor.total_events = 1

        # 5. Attribution record — confidence = 100 for new actors
        # (we are certain this event belongs to this actor since we just created it)
        new_actor_signal = MatchSignal(
            name="new_actor_created",
            score=100.0,
            reason="No existing actor matched — new actor profile created",
        )
        await self._repo.record_attribution(
            actor_id=actor.id,
            event=event,
            match_confidence=100.0,
            signals=[new_actor_signal],
            was_new_actor=True,
        )

        return ProfilerResult(
            actor_id=actor.id,
            actor_display_name=actor.display_name,
            actor_threat_level=actor.threat_level.value,
            actor_confidence_score=actor.confidence_score,
            match_confidence=100.0,
            was_new_actor=True,
            signals_fired=[new_actor_signal.to_dict()],
            new_platform_detected=False,
            all_platforms=list(actor.platforms_targeted or []),
        )

    # ── Existing actor path ────────────────────────────────────────────────────

    async def _handle_existing_actor(
        self,
        event: CorrelationEvent,
        event_fp: Optional[fp_module.DeviceFingerprint],
        decision,
    ) -> ProfilerResult:
        best = decision.best_match
        actor = best.actor
        signals = best.signals
        confidence = best.confidence

        # Detect cross-platform event before updating platforms
        platforms_before = list(actor.platforms_targeted or [])
        new_platform = bool(
            event.platform and event.platform not in platforms_before
        )

        # 1. Update actor profile
        await self._repo.update_actor_on_event(actor, event, confidence)

        # 2. Upsert IP
        if event.source_ip:
            await self._repo.upsert_actor_ip(actor.id, event)

        # 3. Upsert fingerprint
        if event_fp and event_fp.fingerprint_hash:
            await self._repo.upsert_actor_fingerprint(actor.id, event_fp, event.occurred_at)

        # 4. Attribution record
        await self._repo.record_attribution(
            actor_id=actor.id,
            event=event,
            match_confidence=confidence,
            signals=signals,
            was_new_actor=False,
        )

        if new_platform:
            logger.warning(
                "cross_platform_actor_detected",
                actor=actor.display_name,
                new_platform=event.platform,
                known_platforms=platforms_before,
                confidence=confidence,
            )

        return ProfilerResult(
            actor_id=actor.id,
            actor_display_name=actor.display_name,
            actor_threat_level=actor.threat_level.value,
            actor_confidence_score=actor.confidence_score,
            match_confidence=confidence,
            was_new_actor=False,
            signals_fired=[s.to_dict() for s in signals],
            new_platform_detected=new_platform,
            all_platforms=list(actor.platforms_targeted or []),
        )

    # ── Idempotency fallback ───────────────────────────────────────────────────

    async def _build_result_for_existing(
        self, event: CorrelationEvent
    ) -> ProfilerResult:
        """
        Called when the event was already processed.
        Look up the existing ActorEvent and return its data.
        """
        from sqlalchemy import select
        from .models import ActorEvent

        result = await self._session.execute(
            select(ActorEvent).where(ActorEvent.soc_event_id == event.soc_event_id)
        )
        actor_event = result.scalar_one_or_none()

        if not actor_event:
            # Should not happen (we checked earlier), but be safe
            return ProfilerResult(
                actor_id=uuid.uuid4(),
                actor_display_name="UNKNOWN",
                actor_threat_level="low",
                actor_confidence_score=0.0,
                match_confidence=0.0,
                was_new_actor=False,
                signals_fired=[],
            )

        actor = await self._repo.get_actor(actor_event.actor_id)

        return ProfilerResult(
            actor_id=actor_event.actor_id,
            actor_display_name=actor.display_name if actor else "UNKNOWN",
            actor_threat_level=actor.threat_level.value if actor else "low",
            actor_confidence_score=actor.confidence_score if actor else 0.0,
            match_confidence=actor_event.match_confidence,
            was_new_actor=actor_event.was_new_actor,
            signals_fired=actor_event.match_signals or [],
        )
