"""
ActorRepository — alle database operaties voor de Threat Actor Profiler.

Clean separation: de profiler en matcher bevatten geen SQL.
De repository bevat geen business logic.

Alle methodes zijn async (SQLAlchemy async engine).
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .models import (
    ActorEvent,
    ActorFingerprint,
    ActorIp,
    ActorStatus,
    ThreatActor,
    ThreatLevel,
)
from .schemas import CorrelationEvent

logger = logging.getLogger(__name__)

# How many unique IPs to keep in the denormalized known_ips array
_MAX_KNOWN_IPS = 50
# After how many days without events an actor becomes dormant
_DORMANT_AFTER_DAYS = 30


class ActorRepository:
    """
    All read/write operations for threat actor data.
    Instantiated per-request (or per-profiler call) with a DB session.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._db = session

    # ── Lookup — for pre-filter ────────────────────────────────────────────────

    async def find_actors_by_ip(self, ip: str) -> list[ThreatActor]:
        """Return all ACTIVE actors that have this exact IP on record."""
        result = await self._db.execute(
            select(ThreatActor)
            .join(ActorIp, ActorIp.actor_id == ThreatActor.id)
            .where(
                ActorIp.ip_address == ip,
                ThreatActor.status != ActorStatus.CLOSED,
            )
            .options(
                selectinload(ThreatActor.ips),
                selectinload(ThreatActor.fingerprints),
            )
            .distinct()
        )
        return list(result.scalars().all())

    async def find_actors_by_ip_prefix_24(self, prefix: str) -> list[ThreatActor]:
        """Return all ACTIVE actors with an IP in the same /24 subnet."""
        result = await self._db.execute(
            select(ThreatActor)
            .join(ActorIp, ActorIp.actor_id == ThreatActor.id)
            .where(
                ActorIp.ip_prefix_24 == prefix,
                ThreatActor.status != ActorStatus.CLOSED,
            )
            .options(
                selectinload(ThreatActor.ips),
                selectinload(ThreatActor.fingerprints),
            )
            .distinct()
        )
        return list(result.scalars().all())

    async def find_actors_by_fingerprint(self, fp_hash: str) -> list[ThreatActor]:
        """Return all ACTIVE actors that have an exact fingerprint hash match."""
        result = await self._db.execute(
            select(ThreatActor)
            .join(ActorFingerprint, ActorFingerprint.actor_id == ThreatActor.id)
            .where(
                ActorFingerprint.fingerprint_hash == fp_hash,
                ThreatActor.status != ActorStatus.CLOSED,
            )
            .options(
                selectinload(ThreatActor.ips),
                selectinload(ThreatActor.fingerprints),
            )
            .distinct()
        )
        return list(result.scalars().all())

    async def get_actor(self, actor_id: uuid.UUID) -> Optional[ThreatActor]:
        result = await self._db.execute(
            select(ThreatActor)
            .where(ThreatActor.id == actor_id)
            .options(
                selectinload(ThreatActor.ips),
                selectinload(ThreatActor.fingerprints),
            )
        )
        return result.scalar_one_or_none()

    async def get_actor_by_name(self, display_name: str) -> Optional[ThreatActor]:
        result = await self._db.execute(
            select(ThreatActor).where(ThreatActor.display_name == display_name)
        )
        return result.scalar_one_or_none()

    async def event_already_attributed(self, soc_event_id: uuid.UUID) -> bool:
        """Check if a SOC event has already been attributed (idempotency guard)."""
        result = await self._db.execute(
            select(ActorEvent.id).where(ActorEvent.soc_event_id == soc_event_id)
        )
        return result.scalar_one_or_none() is not None

    # ── Write — actor creation ─────────────────────────────────────────────────

    async def create_actor(self, event: CorrelationEvent) -> ThreatActor:
        """
        Create a new ThreatActor from an initial event.
        Generates a deterministic display_name from the new actor's UUID.
        """
        actor_id = uuid.uuid4()
        display_name = _generate_display_name(actor_id, event)

        actor = ThreatActor(
            id=actor_id,
            display_name=display_name,
            threat_level=_initial_threat_level(event),
            confidence_score=50.0,
            status=ActorStatus.ACTIVE,
            first_seen_at=event.occurred_at,
            last_seen_at=event.occurred_at,
            total_events=0,
            known_ips=[event.source_ip] if event.source_ip else [],
            known_countries=[event.source_country] if event.source_country else [],
            primary_country=event.source_country,
            primary_asn=event.source_asn,
            platforms_targeted=[event.platform] if event.platform else [],
            attack_categories=[event.event_type] if event.event_type else [],
            typical_hours=[event.occurred_at.hour],
            is_tor=event.is_tor,
            is_vpn=event.is_vpn,
            uses_automation=None,
            is_cross_platform=False,
            max_ip_threat_score=event.ip_threat_score,
            tags=[],
        )
        self._db.add(actor)
        await self._db.flush()  # get actor.id before adding related records
        return actor

    # ── Write — actor update ───────────────────────────────────────────────────

    async def update_actor_on_event(
        self,
        actor: ThreatActor,
        event: CorrelationEvent,
        match_confidence: float,
    ) -> None:
        """
        Update actor profile after a new event is attributed to it.
        Updates denormalized summary fields only (no re-query needed).
        """
        now = event.occurred_at

        # Last seen + event count
        actor.last_seen_at = now
        actor.total_events = (actor.total_events or 0) + 1

        # Status: reactivate if dormant
        if actor.status == ActorStatus.DORMANT:
            actor.status = ActorStatus.ACTIVE

        # Known IPs (keep latest 50 unique)
        if event.source_ip:
            known = list(actor.known_ips or [])
            if event.source_ip not in known:
                known.append(event.source_ip)
            actor.known_ips = known[-_MAX_KNOWN_IPS:]

        # Known countries
        if event.source_country:
            countries = list(actor.known_countries or [])
            if event.source_country not in countries:
                countries.append(event.source_country)
            actor.known_countries = countries[-20:]
            # Primary country = most frequent (simple: first seen)
            if not actor.primary_country:
                actor.primary_country = event.source_country

        # Platforms targeted
        if event.platform:
            platforms = list(actor.platforms_targeted or [])
            was_cross = len(platforms) >= 1
            if event.platform not in platforms:
                platforms.append(event.platform)
            actor.platforms_targeted = platforms
            if len(platforms) > 1:
                actor.is_cross_platform = True

        # Attack categories
        if event.event_type:
            cats = list(actor.attack_categories or [])
            if event.event_type not in cats:
                cats.append(event.event_type)
            actor.attack_categories = cats

        # Typical hours (keep all unique hours seen)
        hours = list(actor.typical_hours or [])
        if now.hour not in hours:
            hours.append(now.hour)
        actor.typical_hours = sorted(set(hours))

        # Anonymization flags (OR — once confirmed, stays True)
        if event.is_tor:
            actor.is_tor = True
        if event.is_vpn:
            actor.is_vpn = True

        # IP threat score (track maximum)
        if event.ip_threat_score is not None:
            if actor.max_ip_threat_score is None or event.ip_threat_score > actor.max_ip_threat_score:
                actor.max_ip_threat_score = event.ip_threat_score

        # Confidence score: increase slightly on every successful attribution
        actor.confidence_score = min(
            99.0, (actor.confidence_score or 50.0) + _confidence_increment(match_confidence)
        )

        # Threat level upgrade
        actor.threat_level = _compute_threat_level(actor)

        await self._db.flush()

    # ── Write — IP record ──────────────────────────────────────────────────────

    async def upsert_actor_ip(
        self,
        actor_id: uuid.UUID,
        event: CorrelationEvent,
    ) -> ActorIp:
        """Insert or update the ActorIp record for this actor+IP combination."""
        if not event.source_ip:
            return None

        result = await self._db.execute(
            select(ActorIp).where(
                ActorIp.actor_id == actor_id,
                ActorIp.ip_address == event.source_ip,
            )
        )
        actor_ip = result.scalar_one_or_none()

        if actor_ip:
            actor_ip.last_seen = event.occurred_at
            actor_ip.event_count = (actor_ip.event_count or 0) + 1
            if event.ip_threat_score is not None:
                actor_ip.threat_score = event.ip_threat_score
        else:
            actor_ip = ActorIp(
                id=uuid.uuid4(),
                actor_id=actor_id,
                ip_address=event.source_ip,
                ip_prefix_24=_prefix_24(event.source_ip),
                ip_prefix_16=_prefix_16(event.source_ip),
                threat_score=event.ip_threat_score,
                country_code=event.source_country,
                asn=event.source_asn,
                isp=event.source_isp,
                first_seen=event.occurred_at,
                last_seen=event.occurred_at,
                event_count=1,
            )
            self._db.add(actor_ip)

        await self._db.flush()
        return actor_ip

    # ── Write — fingerprint record ─────────────────────────────────────────────

    async def upsert_actor_fingerprint(
        self,
        actor_id: uuid.UUID,
        fp: "fingerprint.DeviceFingerprint",
        now: datetime,
    ) -> Optional[ActorFingerprint]:
        """Insert or update the ActorFingerprint record."""
        from . import fingerprint as fp_module  # avoid circular at module level

        if not fp.fingerprint_hash:
            return None

        result = await self._db.execute(
            select(ActorFingerprint).where(
                ActorFingerprint.actor_id == actor_id,
                ActorFingerprint.fingerprint_hash == fp.fingerprint_hash,
            )
        )
        record = result.scalar_one_or_none()

        if record:
            record.last_seen = now
            record.occurrence_count = (record.occurrence_count or 0) + 1
        else:
            record = ActorFingerprint(
                id=uuid.uuid4(),
                actor_id=actor_id,
                fingerprint_hash=fp.fingerprint_hash,
                user_agent_raw=fp.user_agent_raw,
                browser_family=fp.browser_family,
                browser_version_major=fp.browser_version_major,
                os_family=fp.os_family,
                os_version_major=fp.os_version_major,
                device_type=fp.device_type,
                accept_language=fp.accept_language,
                extra_headers=fp.extra_headers or {},
                first_seen=now,
                last_seen=now,
                occurrence_count=1,
            )
            # Detect automation from device_type
            if fp.device_type == "bot":
                result2 = await self._db.execute(
                    select(ThreatActor).where(ThreatActor.id == actor_id)
                )
                actor = result2.scalar_one_or_none()
                if actor:
                    actor.uses_automation = True

            self._db.add(record)

        await self._db.flush()
        return record

    # ── Write — attribution event ──────────────────────────────────────────────

    async def record_attribution(
        self,
        actor_id: uuid.UUID,
        event: CorrelationEvent,
        match_confidence: float,
        signals: list,
        was_new_actor: bool,
    ) -> ActorEvent:
        """Append an attribution record to actor_events."""
        # Snapshot key event fields for the audit trail
        snapshot = {
            "source_ip": event.source_ip,
            "source_country": event.source_country,
            "event_type": event.event_type,
            "platform": event.platform,
            "severity": event.severity,
            "risk_score": event.risk_score,
            "occurred_at": event.occurred_at.isoformat(),
        }
        if event.description:
            snapshot["description"] = event.description[:500]

        actor_event = ActorEvent(
            id=uuid.uuid4(),
            actor_id=actor_id,
            soc_event_id=event.soc_event_id,
            matched_at=datetime.utcnow(),
            match_confidence=match_confidence,
            match_signals=[s.to_dict() for s in signals],
            was_new_actor=was_new_actor,
            event_snapshot=snapshot,
        )
        self._db.add(actor_event)
        await self._db.flush()
        return actor_event

    # ── Maintenance ────────────────────────────────────────────────────────────

    async def mark_dormant_actors(self) -> int:
        """
        Set actors to DORMANT when not seen for DORMANT_AFTER_DAYS days.
        Returns the number of actors updated.
        Called by a periodic Celery task.
        """
        cutoff = datetime.utcnow() - timedelta(days=_DORMANT_AFTER_DAYS)
        result = await self._db.execute(
            update(ThreatActor)
            .where(
                ThreatActor.last_seen_at < cutoff,
                ThreatActor.status == ActorStatus.ACTIVE,
            )
            .values(status=ActorStatus.DORMANT)
        )
        count = result.rowcount
        if count:
            logger.info("actors_marked_dormant", count=count)
        return count


# ── Helpers ────────────────────────────────────────────────────────────────────

def _generate_display_name(actor_id: uuid.UUID, event: CorrelationEvent) -> str:
    """
    Generate a human-readable display name encoding the attack type and
    a short UUID suffix for uniqueness.

    Examples:
      "TOR-BF-A3F2"   (Tor brute-force actor)
      "ACCT-C12B"     (account takeover)
      "ACTOR-7E4D"    (generic)
    """
    suffix = str(actor_id).replace("-", "").upper()[:4]

    prefix_parts = []
    if event.is_tor:
        prefix_parts.append("TOR")
    elif event.is_vpn:
        prefix_parts.append("VPN")

    type_map = {
        "brute_force": "BF",
        "credential_stuffing": "CS",
        "account_takeover": "ACCT",
        "unauthorized_login": "LOGIN",
        "api_abuse": "API",
        "port_scan": "SCAN",
        "exploit_attempt": "EXPL",
        "data_exfiltration": "EXFIL",
        "suspicious_activity": "SUSP",
    }
    type_abbr = type_map.get(event.event_type or "", "")
    if type_abbr:
        prefix_parts.append(type_abbr)

    prefix = "-".join(prefix_parts) if prefix_parts else "ACTOR"
    return f"{prefix}-{suffix}"


def _initial_threat_level(event: CorrelationEvent) -> ThreatLevel:
    """Determine starting threat level from the first event."""
    sev = event.severity.lower()
    if sev == "critical":
        return ThreatLevel.CRITICAL
    if sev == "high":
        return ThreatLevel.HIGH
    if sev in ("medium", "moderate"):
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


def _compute_threat_level(actor: ThreatActor) -> ThreatLevel:
    """
    Recompute threat level based on actor's accumulated profile.
    Called after every event update.
    """
    score = actor.max_ip_threat_score or 0.0

    # Escalate for specific behaviors
    if actor.is_tor or actor.is_vpn:
        score += 15
    if actor.is_cross_platform:
        score += 20
    if actor.uses_automation:
        score += 10
    if actor.total_events >= 50:
        score += 10
    elif actor.total_events >= 20:
        score += 5

    if score >= 75:
        return ThreatLevel.CRITICAL
    if score >= 50:
        return ThreatLevel.HIGH
    if score >= 25:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


def _confidence_increment(match_confidence: float) -> float:
    """
    How much to increase actor.confidence_score per attribution.
    Higher match confidence → larger increment, diminishing returns.
    """
    if match_confidence >= 90:
        return 3.0
    if match_confidence >= 70:
        return 2.0
    if match_confidence >= 60:
        return 1.0
    return 0.5


def _prefix_24(ip: str) -> Optional[str]:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return None


def _prefix_16(ip: str) -> Optional[str]:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}"
    return None
