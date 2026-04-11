"""
EventCorrelator — links events into clusters and threat actors.

Two correlation strategies:

1. IP Clustering
   Same IP across multiple events or platforms → single threat actor.
   Uses the existing ThreatActor profiler (security-orchestrator/correlation/)
   when available, falls back to lightweight IP-based grouping.

2. Attack Pattern Detection
   Multiple events from the same IP within a 5-minute window → attack burst.
   Bumps risk score and marks the cluster on each event.

The correlator operates on SocSecurityEvent records already persisted in the DB.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from soc.models.security_event import (
    SocSecurityEvent,
    SocEventStatus,
    SocSeverity,
)

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
ATTACK_WINDOW_MINUTES = 5
ATTACK_CLUSTER_THRESHOLD = 3       # events in window to flag as attack
ATTACK_RISK_BONUS = 15.0           # added to threat_score for bursts
CROSS_PLATFORM_BONUS = 10.0        # bonus when same IP hits multiple platforms

# Correlation confidence levels
IP_EXACT_MATCH_CONFIDENCE = 80.0
SUBNET_MATCH_CONFIDENCE = 40.0
TEMPORAL_CLUSTER_CONFIDENCE = 60.0


@dataclass
class CorrelationResult:
    """Output of the correlator for a single event."""
    event_id: uuid.UUID
    # Threat actor linkage
    threat_actor_id: Optional[uuid.UUID] = None
    actor_display_name: Optional[str] = None
    was_new_actor: bool = False
    match_confidence: float = 0.0
    # Attack pattern detection
    is_attack_burst: bool = False
    cluster_size: int = 0
    cluster_ips: list[str] = field(default_factory=list)
    platforms_hit: list[str] = field(default_factory=list)
    # Score adjustments
    risk_bonus: float = 0.0


class EventCorrelator:
    """
    Correlates incoming events against existing SOC data.

    Stateless — all state lives in the database.
    """

    async def correlate(
        self,
        session: AsyncSession,
        event: SocSecurityEvent,
        platform: Optional[str] = None,
    ) -> CorrelationResult:
        """
        Run all correlation strategies on the given event.
        Mutates the event in-place (sets threat_actor_id, cluster_size, etc.)
        and returns a CorrelationResult.
        """
        result = CorrelationResult(event_id=event.id)

        if not event.source_ip:
            return result

        # ── 1. Attack pattern detection ──
        await self._detect_attack_pattern(session, event, result)

        # ── 2. IP-based actor clustering ──
        await self._cluster_by_ip(session, event, platform, result)

        # ── 3. Apply risk bonus ──
        total_bonus = result.risk_bonus
        if total_bonus > 0 and event.threat_score is not None:
            event.threat_score = min(100.0, event.threat_score + total_bonus)

        # ── 4. Update event fields ──
        event.cluster_size = result.cluster_size or None
        event.status = SocEventStatus.CORRELATED
        event.correlated_at = datetime.utcnow()

        if result.threat_actor_id:
            event.threat_actor_id = result.threat_actor_id

        await session.flush()

        logger.info(
            "correlation complete: event=%s actor=%s burst=%s cluster=%d bonus=%.1f",
            event.id, result.actor_display_name or "none",
            result.is_attack_burst, result.cluster_size, result.risk_bonus,
        )

        return result

    # ── Attack Pattern Detection ─────────────────────────────────────────────

    async def _detect_attack_pattern(
        self,
        session: AsyncSession,
        event: SocSecurityEvent,
        result: CorrelationResult,
    ) -> None:
        """
        Check if this IP has sent multiple events within the attack window.
        """
        window_start = event.occurred_at - timedelta(minutes=ATTACK_WINDOW_MINUTES)

        # Count events from same IP in the time window
        count_stmt = (
            select(func.count(SocSecurityEvent.id))
            .where(
                and_(
                    SocSecurityEvent.source_ip == event.source_ip,
                    SocSecurityEvent.occurred_at >= window_start,
                    SocSecurityEvent.occurred_at <= event.occurred_at,
                )
            )
        )
        count_result = await session.execute(count_stmt)
        cluster_size = count_result.scalar() or 0

        result.cluster_size = cluster_size

        if cluster_size >= ATTACK_CLUSTER_THRESHOLD:
            result.is_attack_burst = True
            result.risk_bonus += ATTACK_RISK_BONUS

            logger.warning(
                "attack burst detected: ip=%s events=%d window=%dmin",
                event.source_ip, cluster_size, ATTACK_WINDOW_MINUTES,
            )

    # ── IP-Based Actor Clustering ────────────────────────────────────────────

    async def _cluster_by_ip(
        self,
        session: AsyncSession,
        event: SocSecurityEvent,
        platform: Optional[str],
        result: CorrelationResult,
    ) -> None:
        """
        Find or create a threat actor based on IP address matching.

        Strategy:
        1. Find all previous events from the same IP
        2. If any are already linked to a threat actor → link this event too
        3. If unlinked events exist from same IP → create new actor, link all
        4. Check cross-platform: same IP on different platforms → bonus
        """
        # Find previous events from same IP (excluding this one)
        prev_stmt = (
            select(SocSecurityEvent)
            .where(
                and_(
                    SocSecurityEvent.source_ip == event.source_ip,
                    SocSecurityEvent.id != event.id,
                )
            )
            .order_by(SocSecurityEvent.occurred_at.desc())
            .limit(50)
        )
        prev_result = await session.execute(prev_stmt)
        prev_events = list(prev_result.scalars().all())

        if not prev_events:
            return

        # Check if any previous event is already attributed
        existing_actor_id: Optional[uuid.UUID] = None
        for prev in prev_events:
            if prev.threat_actor_id is not None:
                existing_actor_id = prev.threat_actor_id
                break

        # Collect platforms this IP has been seen on
        platforms_seen: set[str] = set()
        if platform:
            platforms_seen.add(platform)
        for prev in prev_events:
            if prev.raw_payload and isinstance(prev.raw_payload, dict):
                p = prev.raw_payload.get("alert_category") or prev.raw_payload.get("platform")
                if p:
                    platforms_seen.add(str(p))

        result.platforms_hit = sorted(platforms_seen)

        if existing_actor_id:
            # Link to existing actor
            result.threat_actor_id = existing_actor_id
            result.match_confidence = IP_EXACT_MATCH_CONFIDENCE
            result.was_new_actor = False

            # Cross-platform bonus
            if len(platforms_seen) > 1:
                result.risk_bonus += CROSS_PLATFORM_BONUS

        elif len(prev_events) >= 1:
            # Multiple events from same IP, no actor yet → create one
            actor_id = uuid.uuid4()
            display_name = self._generate_actor_name(event)

            result.threat_actor_id = actor_id
            result.actor_display_name = display_name
            result.match_confidence = TEMPORAL_CLUSTER_CONFIDENCE
            result.was_new_actor = True

            # Back-link previous unattributed events to this new actor
            for prev in prev_events:
                if prev.threat_actor_id is None:
                    prev.threat_actor_id = actor_id

            logger.info(
                "new threat actor created: %s ip=%s linked_events=%d",
                display_name, event.source_ip, len(prev_events) + 1,
            )

        # Resolve display name for existing actors
        if existing_actor_id and not result.actor_display_name:
            result.actor_display_name = f"ACTOR-{str(existing_actor_id)[:8].upper()}"

    def _generate_actor_name(self, event: SocSecurityEvent) -> str:
        """Generate a human-readable actor display name."""
        prefix_parts = []

        # Anonymization hint
        if event.ip_is_tor:
            prefix_parts.append("TOR")
        elif event.ip_is_vpn:
            prefix_parts.append("VPN")
        elif event.ip_is_proxy:
            prefix_parts.append("PROXY")

        # Event type hint
        type_map = {
            "brute_force": "BF",
            "account_takeover": "ATO",
            "credential_stuffing": "CRED",
            "unauthorized_login": "AUTH",
            "api_abuse": "API",
            "port_scan": "SCAN",
            "exploit_attempt": "EXP",
        }
        event_type_str = event.event_type.value if event.event_type else "UNK"
        type_hint = type_map.get(event_type_str, "EVT")
        prefix_parts.append(type_hint)

        # Random suffix
        suffix = uuid.uuid4().hex[:4].upper()
        prefix = "-".join(prefix_parts) if prefix_parts else "ACTOR"

        return f"{prefix}-{suffix}"

    # ── Utilities ────────────────────────────────────────────────────────────

    async def get_ip_history(
        self,
        session: AsyncSession,
        ip: str,
        limit: int = 20,
    ) -> list[SocSecurityEvent]:
        """Get recent events from a specific IP."""
        stmt = (
            select(SocSecurityEvent)
            .where(SocSecurityEvent.source_ip == ip)
            .order_by(SocSecurityEvent.occurred_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def get_actor_events(
        self,
        session: AsyncSession,
        actor_id: uuid.UUID,
        limit: int = 50,
    ) -> list[SocSecurityEvent]:
        """Get all events attributed to a threat actor."""
        stmt = (
            select(SocSecurityEvent)
            .where(SocSecurityEvent.threat_actor_id == actor_id)
            .order_by(SocSecurityEvent.occurred_at.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
