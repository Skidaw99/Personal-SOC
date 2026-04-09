"""
Threat Actor Profiler — PostgreSQL ORM models.

Four tables:

  threat_actors          Core actor profile (one row per identified attacker)
  actor_ips              IPs attributed to an actor (many per actor)
  actor_fingerprints     Device fingerprints attributed to an actor
  actor_events           Attribution log: which event was linked to which actor

Design choices
──────────────
- known_ips / known_countries / platforms_targeted are denormalized JSONB
  summaries on threat_actors for fast dashboard rendering without joins.
- actor_ips stores ip_prefix_24 / ip_prefix_16 string columns so the
  matcher can do fast prefix-based subnet pre-filtering via B-tree index.
- actor_events is an append-only attribution log — nothing is deleted or
  updated, only the parent actor record is mutated on re-attribution.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

# Import Base from the shared SOC database module
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from soc.database import Base


# ── Enums ─────────────────────────────────────────────────────────────────────

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActorStatus(str, Enum):
    ACTIVE = "active"       # Seen within the last 30 days
    DORMANT = "dormant"     # No activity 30–180 days
    CLOSED = "closed"       # Analyst manually closed / false positive


# ── ThreatActor ────────────────────────────────────────────────────────────────

class ThreatActor(Base):
    """
    Central profile for an identified threat actor.

    Created on first attribution; updated on every subsequent event match.
    display_name is auto-generated (e.g. "TOR-BF-A3F2"); alias is
    analyst-assigned.
    """
    __tablename__ = "threat_actors"

    # ── Identity ──────────────────────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    display_name = Column(String(64), nullable=False, unique=True)
    alias = Column(String(128), nullable=True)   # analyst-given name

    # ── Threat assessment ─────────────────────────────────────────────────────
    threat_level = Column(
        SAEnum(ThreatLevel), nullable=False, default=ThreatLevel.LOW, index=True
    )
    # 0-100: overall confidence that this is a single real actor
    confidence_score = Column(Float, nullable=False, default=50.0)

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    status = Column(
        SAEnum(ActorStatus), nullable=False, default=ActorStatus.ACTIVE, index=True
    )
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    total_events = Column(Integer, nullable=False, default=0)

    # ── Denormalized observables (fast dashboard queries) ─────────────────────
    # Last 50 unique IPs seen (list[str])
    known_ips = Column(JSONB, nullable=False, default=list)
    # ISO country codes (list[str])
    known_countries = Column(JSONB, nullable=False, default=list)
    primary_country = Column(String(2), nullable=True)
    primary_asn = Column(Integer, nullable=True)
    # Platforms this actor has been seen on (list[str])
    platforms_targeted = Column(JSONB, nullable=False, default=list)
    # Attack categories observed (list[str])
    attack_categories = Column(JSONB, nullable=False, default=list)
    # Hours of day (0-23) this actor is typically active (list[int])
    typical_hours = Column(JSONB, nullable=False, default=list)

    # ── Behavioral flags ──────────────────────────────────────────────────────
    is_tor = Column(Boolean, nullable=True)
    is_vpn = Column(Boolean, nullable=True)
    uses_automation = Column(Boolean, nullable=True)   # bot/scripted UA detected
    is_cross_platform = Column(Boolean, nullable=False, default=False)

    # ── IP intelligence summary (from last enrichment) ────────────────────────
    max_ip_threat_score = Column(Float, nullable=True)

    # ── Analyst fields ────────────────────────────────────────────────────────
    tags = Column(JSONB, nullable=False, default=list)           # list[str]
    analyst_notes = Column(Text, nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────────
    ips = relationship(
        "ActorIp", back_populates="actor",
        cascade="all, delete-orphan", lazy="select"
    )
    fingerprints = relationship(
        "ActorFingerprint", back_populates="actor",
        cascade="all, delete-orphan", lazy="select"
    )
    events = relationship(
        "ActorEvent", back_populates="actor",
        cascade="all, delete-orphan", lazy="select"
    )

    __table_args__ = (
        Index("ix_actor_last_seen", "last_seen_at"),
        Index("ix_actor_threat_level_status", "threat_level", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatActor {self.display_name} "
            f"level={self.threat_level} events={self.total_events}>"
        )

    @property
    def is_active(self) -> bool:
        from datetime import timedelta
        return (
            self.status == ActorStatus.ACTIVE
            and (datetime.utcnow() - self.last_seen_at).days <= 30
        )


# ── ActorIp ───────────────────────────────────────────────────────────────────

class ActorIp(Base):
    """
    An IP address attributed to a ThreatActor.

    ip_prefix_24 and ip_prefix_16 are pre-computed for fast subnet
    pre-filtering during matching (B-tree index, no cast needed).
    """
    __tablename__ = "actor_ips"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id = Column(
        UUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="CASCADE"),
        nullable=False, index=True
    )

    ip_address = Column(String(45), nullable=False)
    # Pre-computed prefixes for fast subnet matching
    ip_prefix_24 = Column(String(32), nullable=True, index=True)  # "185.220.101"
    ip_prefix_16 = Column(String(16), nullable=True, index=True)  # "185.220"

    # From IP intel enrichment
    threat_score = Column(Float, nullable=True)
    country_code = Column(String(2), nullable=True)
    asn = Column(Integer, nullable=True)
    isp = Column(String(256), nullable=True)

    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    event_count = Column(Integer, nullable=False, default=1)

    actor = relationship("ThreatActor", back_populates="ips")

    __table_args__ = (
        # One IP per actor (same IP can appear under different actors before merge)
        UniqueConstraint("actor_id", "ip_address", name="uq_actor_ip"),
        Index("ix_actor_ip_address", "ip_address"),
    )

    def __repr__(self) -> str:
        return f"<ActorIp {self.ip_address} → actor={self.actor_id}>"


# ── ActorFingerprint ──────────────────────────────────────────────────────────

class ActorFingerprint(Base):
    """
    Device fingerprint attributed to a ThreatActor.

    fingerprint_hash is the SHA-256 of the normalized canonical components
    (browser_family + os_family + device_type + accept_language).
    Exact hash match = very strong signal (score 85).
    """
    __tablename__ = "actor_fingerprints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id = Column(
        UUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="CASCADE"),
        nullable=False, index=True
    )

    # SHA-256 of normalized fingerprint components
    fingerprint_hash = Column(String(64), nullable=False, index=True)

    # Parsed UA components (for partial matching and display)
    user_agent_raw = Column(Text, nullable=True)
    browser_family = Column(String(64), nullable=True)
    browser_version_major = Column(Integer, nullable=True)
    os_family = Column(String(64), nullable=True)
    os_version_major = Column(Integer, nullable=True)
    device_type = Column(String(32), nullable=True)   # desktop / mobile / tablet / bot
    accept_language = Column(String(64), nullable=True)
    # Additional HTTP headers that contribute to fingerprint (JSONB)
    extra_headers = Column(JSONB, nullable=True)

    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    occurrence_count = Column(Integer, nullable=False, default=1)

    actor = relationship("ThreatActor", back_populates="fingerprints")

    __table_args__ = (
        UniqueConstraint("actor_id", "fingerprint_hash", name="uq_actor_fp"),
    )

    def __repr__(self) -> str:
        return (
            f"<ActorFingerprint hash={self.fingerprint_hash[:8]}... "
            f"browser={self.browser_family}/{self.os_family}>"
        )


# ── ActorEvent ────────────────────────────────────────────────────────────────

class ActorEvent(Base):
    """
    Append-only attribution log.

    Records which SOC security event was attributed to which actor,
    with what confidence, and which signals fired.
    Never updated — only inserted.
    """
    __tablename__ = "actor_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id = Column(
        UUID(as_uuid=True), ForeignKey("threat_actors.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    # UUID of the originating SocSecurityEvent (or external event)
    soc_event_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    matched_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    # 0-100 confidence that this attribution is correct
    match_confidence = Column(Float, nullable=False)
    # Which signals fired: list[{name, score, reason}]
    match_signals = Column(JSONB, nullable=False, default=list)
    was_new_actor = Column(Boolean, nullable=False, default=False)

    # Snapshot of key event fields at time of attribution (for audit trail)
    event_snapshot = Column(JSONB, nullable=True)

    actor = relationship("ThreatActor", back_populates="events")

    __table_args__ = (
        Index("ix_actor_event_matched_at", "matched_at"),
        # Fast lookup: has this SOC event already been attributed?
        Index("ix_actor_event_soc_id", "soc_event_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ActorEvent actor={self.actor_id} "
            f"event={self.soc_event_id} conf={self.match_confidence:.0f}>"
        )
