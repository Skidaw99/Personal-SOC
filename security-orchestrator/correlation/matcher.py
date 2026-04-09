"""
ActorMatcher — pre-filter candidate actors en score elk tegen het event.

Werking in twee fasen
─────────────────────
Fase 1 — Pre-filter (via DB index, O(log n)):
  De matcher vraagt de repository om kandidaat-actors op basis van:
    a. Exact IP match             → directe index hit
    b. /24 prefix match           → ip_prefix_24 index
    c. Fingerprint hash match     → fingerprint_hash index

  Alleen deze kandidaten worden naar fase 2 doorgestuurd.
  Actors die geen enkel pre-filter raken worden nooit gescoord.
  Dit houdt de matching schaalbaar ook bij duizenden actors.

Fase 2 — Scoring (in-process, O(k) met k = kandidaten):
  Voor elke kandidaat-actor worden alle match signals geëxtraheerd.
  De signals worden opgeteld tot een confidence score.

Beslissing:
  confidence >= ATTRIBUTION_THRESHOLD (60) → beste kandidaat wint
  confidence < 60                          → nieuwe actor aanmaken

Tie-breaking: als meerdere kandidaten >= threshold scoren, wint degene
met de hoogste confidence.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional
import uuid

from .signals import (
    ATTRIBUTION_THRESHOLD,
    MatchSignal,
    extract_signals,
    total_confidence,
)

if TYPE_CHECKING:
    from .fingerprint import DeviceFingerprint
    from .models import ThreatActor
    from .repository import ActorRepository
    from .schemas import CorrelationEvent

logger = logging.getLogger(__name__)


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass
class MatchResult:
    """Outcome of matching one event against one candidate actor."""
    actor_id: uuid.UUID
    actor: "ThreatActor"
    confidence: float
    signals: list[MatchSignal] = field(default_factory=list)

    @property
    def is_match(self) -> bool:
        return self.confidence >= ATTRIBUTION_THRESHOLD


@dataclass
class MatchDecision:
    """
    Final decision returned to the profiler.

    best_match is set when an existing actor is found.
    is_new_actor is True when no candidate passed the threshold.
    """
    is_new_actor: bool
    best_match: Optional[MatchResult] = None
    all_candidates: list[MatchResult] = field(default_factory=list)


# ── ActorMatcher ───────────────────────────────────────────────────────────────

class ActorMatcher:
    """
    Stateless matching engine. Instantiate once, reuse per request.
    All state lives in the DB via the repository.
    """

    def __init__(self, repository: "ActorRepository") -> None:
        self._repo = repository

    async def match(
        self,
        event: "CorrelationEvent",
        event_fp: Optional["DeviceFingerprint"],
    ) -> MatchDecision:
        """
        Find the best matching actor for the given event.

        Returns a MatchDecision with the best match or is_new_actor=True.
        """
        # ── Phase 1: pre-filter ───────────────────────────────────────────────
        candidates = await self._prefetch_candidates(event, event_fp)

        if not candidates:
            logger.debug(
                "matcher_no_candidates",
                ip=event.source_ip,
                event_type=event.event_type,
            )
            return MatchDecision(is_new_actor=True)

        logger.debug(
            "matcher_candidates_found",
            count=len(candidates),
            ip=event.source_ip,
        )

        # ── Phase 2: score each candidate ─────────────────────────────────────
        results: list[MatchResult] = []
        for actor in candidates:
            signals = extract_signals(event, actor, event_fp)
            conf = total_confidence(signals)
            results.append(MatchResult(
                actor_id=actor.id,
                actor=actor,
                confidence=conf,
                signals=signals,
            ))
            logger.debug(
                "matcher_scored",
                actor=actor.display_name,
                confidence=conf,
                signals=[s.name for s in signals],
            )

        # ── Decision ──────────────────────────────────────────────────────────
        eligible = [r for r in results if r.is_match]
        if not eligible:
            return MatchDecision(is_new_actor=True, all_candidates=results)

        best = max(eligible, key=lambda r: r.confidence)
        logger.info(
            "matcher_attributed",
            actor=best.actor.display_name,
            confidence=best.confidence,
            signals=[s.name for s in best.signals],
        )
        return MatchDecision(
            is_new_actor=False,
            best_match=best,
            all_candidates=results,
        )

    # ── Private ───────────────────────────────────────────────────────────────

    async def _prefetch_candidates(
        self,
        event: "CorrelationEvent",
        event_fp: Optional["DeviceFingerprint"],
    ) -> list["ThreatActor"]:
        """
        Query candidate actors via index hits only.
        Returns a deduplicated list of ThreatActor ORM objects.
        """
        candidate_ids: set[uuid.UUID] = set()
        candidates: list["ThreatActor"] = []

        # ── a. Exact IP match ─────────────────────────────────────────────────
        if event.source_ip:
            ip_actors = await self._repo.find_actors_by_ip(event.source_ip)
            for actor in ip_actors:
                if actor.id not in candidate_ids:
                    candidate_ids.add(actor.id)
                    candidates.append(actor)

        # ── b. /24 prefix match ───────────────────────────────────────────────
        if event.source_ip:
            prefix_24 = _prefix_24(event.source_ip)
            if prefix_24:
                subnet_actors = await self._repo.find_actors_by_ip_prefix_24(prefix_24)
                for actor in subnet_actors:
                    if actor.id not in candidate_ids:
                        candidate_ids.add(actor.id)
                        candidates.append(actor)

        # ── c. Fingerprint hash match ─────────────────────────────────────────
        if event_fp and event_fp.fingerprint_hash:
            fp_actors = await self._repo.find_actors_by_fingerprint(
                event_fp.fingerprint_hash
            )
            for actor in fp_actors:
                if actor.id not in candidate_ids:
                    candidate_ids.add(actor.id)
                    candidates.append(actor)

        return candidates


def _prefix_24(ip: str) -> Optional[str]:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return None
