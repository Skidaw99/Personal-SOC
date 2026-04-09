"""
SOC SecurityEvent — normalized event model for the Security Orchestrator.

This is distinct from the SFD SecurityEvent (backend/models/event.py).
It represents an enriched, correlated event that can originate from multiple
sources: Social Fraud Detector, Suricata, CrowdSec, manual ingestion, etc.
"""
import uuid
from datetime import datetime
from enum import Enum

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    Boolean,
    Enum as SAEnum,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB

from soc.database import Base


class EventSource(str, Enum):
    """Which system produced this raw event."""
    SOCIAL_FRAUD_DETECTOR = "social_fraud_detector"
    SURICATA = "suricata"
    CROWDSEC = "crowdsec"
    MANUAL = "manual"
    API = "api"


class SocEventType(str, Enum):
    """Normalized event type taxonomy across all sources."""
    # Network / host
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    # Authentication
    UNAUTHORIZED_LOGIN = "unauthorized_login"
    CREDENTIAL_STUFFING = "credential_stuffing"
    MFA_BYPASS = "mfa_bypass"
    # Account / social
    ACCOUNT_TAKEOVER = "account_takeover"
    API_ABUSE = "api_abuse"
    SOCIAL_ENGINEERING = "social_engineering"
    # Generic
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    ANOMALY = "anomaly"


class SocSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SocEventStatus(str, Enum):
    NEW = "new"
    ENRICHED = "enriched"       # IP intel lookups done
    CORRELATED = "correlated"   # Linked to an existing threat actor
    ESCALATED = "escalated"     # Forwarded to alert / auto-response
    CLOSED = "closed"


class SocSecurityEvent(Base):
    """
    Normalized, enriched security event stored in the SOC database.

    Lifecycle: NEW → ENRICHED → CORRELATED → ESCALATED / CLOSED
    """
    __tablename__ = "soc_security_events"

    # ── Identity ──────────────────────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Opaque ID of the event in the originating system (e.g., SFD alert UUID)
    external_id = Column(String(128), nullable=True, index=True)
    source = Column(SAEnum(EventSource), nullable=False, index=True)
    event_type = Column(SAEnum(SocEventType), nullable=False, index=True)

    # ── Severity & scoring ────────────────────────────────────────────────────
    severity = Column(SAEnum(SocSeverity), nullable=False, default=SocSeverity.INFO)
    # Raw risk score from the originating system (0-100)
    raw_risk_score = Column(Float, nullable=False, default=0.0)
    # Composite threat score after IP intel enrichment (0-100)
    threat_score = Column(Float, nullable=True)

    # ── Network observables ───────────────────────────────────────────────────
    source_ip = Column(String(45), nullable=True, index=True)   # IPv4 or IPv6
    source_port = Column(Integer, nullable=True)
    destination_ip = Column(String(45), nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)

    # ── Geo & ASN (populated by MaxMind enrichment) ───────────────────────────
    source_country = Column(String(2), nullable=True)           # ISO 3166-1 alpha-2
    source_city = Column(String(128), nullable=True)
    source_asn = Column(Integer, nullable=True)
    source_isp = Column(String(256), nullable=True)
    source_latitude = Column(Float, nullable=True)
    source_longitude = Column(Float, nullable=True)

    # ── Threat intelligence flags (populated by IP Intelligence Engine) ───────
    ip_is_tor = Column(Boolean, nullable=True)
    ip_is_vpn = Column(Boolean, nullable=True)
    ip_is_proxy = Column(Boolean, nullable=True)
    ip_is_datacenter = Column(Boolean, nullable=True)
    ip_abuse_confidence = Column(Integer, nullable=True)        # 0-100 from AbuseIPDB

    # ── Correlation ───────────────────────────────────────────────────────────
    # UUID of the ThreatActor this event has been attributed to (nullable until correlation)
    threat_actor_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    # How many events in the current correlation cluster
    cluster_size = Column(Integer, nullable=True)

    # ── Context ───────────────────────────────────────────────────────────────
    description = Column(Text, nullable=True)
    # Full raw payload from the originating system, stored as JSONB for fast querying
    raw_payload = Column(JSONB, nullable=True)
    # Enrichment results per provider stored as JSONB (keyed by provider name)
    enrichment_data = Column(JSONB, nullable=True)

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    status = Column(SAEnum(SocEventStatus), nullable=False, default=SocEventStatus.NEW, index=True)
    occurred_at = Column(DateTime, nullable=False)
    ingested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    enriched_at = Column(DateTime, nullable=True)
    correlated_at = Column(DateTime, nullable=True)

    # ── Indexes ───────────────────────────────────────────────────────────────
    __table_args__ = (
        # Fast time-range queries on the live ops screen
        Index("ix_soc_events_occurred_at", "occurred_at"),
        # Actor timeline queries
        Index("ix_soc_events_actor_occurred", "threat_actor_id", "occurred_at"),
        # IP timeline queries (enrichment cache hit check)
        Index("ix_soc_events_ip_occurred", "source_ip", "occurred_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<SocSecurityEvent id={self.id} type={self.event_type} "
            f"ip={self.source_ip} score={self.threat_score}>"
        )
