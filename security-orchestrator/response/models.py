"""
Response Engine — PostgreSQL ORM models.

Twee tabellen:

  response_decisions     Beslissing-record: welke acties zijn bepaald voor een event
  response_actions       Immutable, append-only audit trail van uitgevoerde acties

Design keuzes
─────────────
- response_actions is APPEND-ONLY: geen UPDATE of DELETE.
  Elke rij is een onveranderlijk audit record.
- Eén decision kan meerdere actions triggeren (bijv. block + email + webhook).
- action_payload slaat de volledige request/response op voor forensisch bewijs.
- Soft errors (bijv. webhook timeout) worden gelogd als status="failed"
  met error details, maar stoppen de overige acties niet.
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
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from soc.database import Base


# ── Enums ────────────────────────────────────────────────────────────────────

class ActionType(str, Enum):
    """Typen geautomatiseerde response acties."""
    IP_BLOCK = "ip_block"               # CrowdSec ban
    EMAIL_ALERT = "email_alert"         # SMTP notificatie
    WEBHOOK_ALERT = "webhook_alert"     # Webhook POST (Slack/Teams/PagerDuty)
    ACCOUNT_LOCK = "account_lock"       # Platform API account lock
    ACCOUNT_FLAG = "account_flag"       # Account flaggen voor review
    LOG_ONLY = "log_only"               # Alleen audit log, geen externe actie


class ActionStatus(str, Enum):
    """Status van een uitgevoerde actie."""
    PENDING = "pending"       # Gepland, nog niet uitgevoerd
    EXECUTING = "executing"   # Wordt momenteel uitgevoerd
    SUCCESS = "success"       # Succesvol afgerond
    FAILED = "failed"         # Fout tijdens uitvoering
    SKIPPED = "skipped"       # Overgeslagen (bijv. dry-run of duplicate)


class ResponseTier(str, Enum):
    """Response tier bepaald door risk score."""
    CRITICAL = "critical"   # risk >= 90
    HIGH = "high"           # risk >= 70
    MEDIUM = "medium"       # risk >= 50
    LOW = "low"             # risk < 50
    OVERRIDE = "override"   # Speciale regel (bijv. account_takeover)


# ── ResponseDecision ─────────────────────────────────────────────────────────

class ResponseDecision(Base):
    """
    Beslissing-record: welke response tier en acties zijn bepaald.

    Eén decision per event. Bevat de snapshot van de input data
    die de beslissing heeft aangedreven.
    """
    __tablename__ = "response_decisions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Link naar het oorspronkelijke SOC event
    soc_event_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    # Optioneel: link naar de geattribueerde threat actor
    actor_id = Column(UUID(as_uuid=True), nullable=True, index=True)

    # ── Decision context ─────────────────────────────────────────────────────
    event_type = Column(String(128), nullable=False)
    risk_score = Column(Float, nullable=False)
    tier = Column(SAEnum(ResponseTier), nullable=False, index=True)

    # Welke regels hebben gefired (list[{rule_name, reason}])
    rules_matched = Column(JSONB, nullable=False, default=list)
    # Welke actie-typen zijn gepland
    planned_actions = Column(JSONB, nullable=False, default=list)

    # Snapshot van input data voor audit (event + enrichment)
    input_snapshot = Column(JSONB, nullable=True)

    # ── Metadata ─────────────────────────────────────────────────────────────
    is_dry_run = Column(Boolean, nullable=False, default=False)
    decided_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # ── Relationships ────────────────────────────────────────────────────────
    actions = relationship(
        "ResponseAction",
        back_populates="decision",
        cascade="all, delete-orphan",
        lazy="select",
    )

    __table_args__ = (
        Index("ix_decision_event_id", "soc_event_id"),
        Index("ix_decision_tier_time", "tier", "decided_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ResponseDecision tier={self.tier} "
            f"risk={self.risk_score} actions={len(self.planned_actions or [])}>"
        )


# ── ResponseAction (IMMUTABLE AUDIT TRAIL) ───────────────────────────────────

class ResponseAction(Base):
    """
    Immutable, append-only audit log van elke uitgevoerde response actie.

    BELANGRIJK: deze tabel is APPEND-ONLY.
    - Geen UPDATE of DELETE operaties toegestaan.
    - Elke rij is een permanent forensisch record.
    - Bij retry wordt een NIEUWE rij aangemaakt, niet de bestaande geüpdatet.

    action_payload bevat de volledige request/response data zodat
    elke actie forensisch reproduceerbaar is.
    """
    __tablename__ = "response_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    decision_id = Column(
        UUID(as_uuid=True),
        ForeignKey("response_decisions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Action details ───────────────────────────────────────────────────────
    action_type = Column(SAEnum(ActionType), nullable=False, index=True)
    status = Column(SAEnum(ActionStatus), nullable=False, default=ActionStatus.PENDING)

    # Target van de actie (IP, e-mailadres, account ID, etc.)
    target = Column(String(256), nullable=True)
    # Volledige request en response data (forensisch bewijs)
    action_payload = Column(JSONB, nullable=True)

    # ── Timing ───────────────────────────────────────────────────────────────
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Float, nullable=True)

    # ── Error tracking ───────────────────────────────────────────────────────
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)

    # ── Immutability timestamp ───────────────────────────────────────────────
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # ── Relationships ────────────────────────────────────────────────────────
    decision = relationship("ResponseDecision", back_populates="actions")

    __table_args__ = (
        Index("ix_action_type_status", "action_type", "status"),
        Index("ix_action_created", "created_at"),
        Index("ix_action_decision", "decision_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ResponseAction {self.action_type} "
            f"status={self.status} target={self.target}>"
        )
