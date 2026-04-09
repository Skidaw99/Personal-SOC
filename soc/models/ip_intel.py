"""
IpIntelCache — persistent cache for IP intelligence lookup results.

The IP Intelligence Engine writes here after every provider lookup so that:
  1. Hot IPs are served from Redis (fast, short TTL)
  2. Warm IPs are served from this table (slower, longer TTL — survives restarts)
  3. Cold IPs trigger fresh provider lookups

One row per IP address. On re-lookup the row is upserted in place.
"""
import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB

from soc.database import Base


class IpReputationCategory(str, Enum):
    """High-level reputation bucket derived from the composite threat score."""
    CLEAN = "clean"           # score 0-19
    SUSPICIOUS = "suspicious" # score 20-49
    MALICIOUS = "malicious"   # score 50-74
    CRITICAL = "critical"     # score 75-100


class IpIntelCache(Base):
    """
    Persistent IP intelligence record — one row per unique IP address.

    Composite threat_score (0-100) is computed by scorer.py using
    weighted results from all available providers.
    """
    __tablename__ = "soc_ip_intel_cache"

    # ── Identity ──────────────────────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)

    # ── Composite scoring ─────────────────────────────────────────────────────
    threat_score = Column(Float, nullable=False, default=0.0)
    reputation = Column(String(16), nullable=False, default=IpReputationCategory.CLEAN)

    # ── Geo / network (MaxMind) ────────────────────────────────────────────────
    country_code = Column(String(2), nullable=True)
    country_name = Column(String(128), nullable=True)
    city = Column(String(128), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(Integer, nullable=True)
    isp = Column(String(256), nullable=True)
    org = Column(String(256), nullable=True)

    # ── Anonymization flags (populated by multiple providers) ─────────────────
    is_tor = Column(Boolean, nullable=True, default=False)
    is_vpn = Column(Boolean, nullable=True, default=False)
    is_proxy = Column(Boolean, nullable=True, default=False)
    is_datacenter = Column(Boolean, nullable=True, default=False)

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    abuse_confidence_score = Column(Integer, nullable=True)  # 0-100
    abuse_total_reports = Column(Integer, nullable=True)
    abuse_last_reported_at = Column(DateTime, nullable=True)
    abuse_usage_type = Column(String(128), nullable=True)
    # Full AbuseIPDB response stored for Evidence Builder
    abuse_raw = Column(JSONB, nullable=True)

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt_malicious_votes = Column(Integer, nullable=True)
    vt_suspicious_votes = Column(Integer, nullable=True)
    vt_harmless_votes = Column(Integer, nullable=True)
    vt_undetected_votes = Column(Integer, nullable=True)
    vt_last_analysis_at = Column(DateTime, nullable=True)
    # Tags from VirusTotal community (e.g. "scanner", "bogon", "cdn")
    vt_tags = Column(JSONB, nullable=True)           # list[str]
    vt_raw = Column(JSONB, nullable=True)

    # ── Shodan ────────────────────────────────────────────────────────────────
    shodan_open_ports = Column(JSONB, nullable=True)         # list[int]
    shodan_vulnerabilities = Column(JSONB, nullable=True)    # list[str] CVE IDs
    shodan_hostnames = Column(JSONB, nullable=True)          # list[str]
    shodan_tags = Column(JSONB, nullable=True)               # list[str]
    shodan_last_seen = Column(DateTime, nullable=True)
    shodan_raw = Column(JSONB, nullable=True)

    # ── Lookup metadata ───────────────────────────────────────────────────────
    # Which providers were consulted on the last lookup (bitmask stored as JSON)
    providers_queried = Column(JSONB, nullable=True)         # list[str]
    # Number of times this IP has been looked up (used for rate-limit budgeting)
    lookup_count = Column(Integer, nullable=False, default=1)
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_lookup_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    # Absolute expiry — orchestrator refreshes after this timestamp
    expires_at = Column(DateTime, nullable=False)

    # ── Indexes ───────────────────────────────────────────────────────────────
    __table_args__ = (
        # Dashboard leaderboard: highest-threat IPs
        Index("ix_ip_intel_threat_score", "threat_score"),
        # Expiry sweep: background task finds stale records
        Index("ix_ip_intel_expires_at", "expires_at"),
        # Geo clustering on the globe
        Index("ix_ip_intel_country", "country_code"),
    )

    def __repr__(self) -> str:
        return (
            f"<IpIntelCache ip={self.ip_address} score={self.threat_score} "
            f"rep={self.reputation}>"
        )

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    @property
    def summary(self) -> dict:
        """Lightweight dict for WebSocket push — no raw provider blobs."""
        return {
            "ip": self.ip_address,
            "threat_score": self.threat_score,
            "reputation": self.reputation,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "asn": self.asn,
            "isp": self.isp,
            "is_tor": self.is_tor,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "abuse_confidence_score": self.abuse_confidence_score,
            "vt_malicious_votes": self.vt_malicious_votes,
            "shodan_open_ports": self.shodan_open_ports,
            "last_lookup_at": self.last_lookup_at.isoformat() if self.last_lookup_at else None,
        }
