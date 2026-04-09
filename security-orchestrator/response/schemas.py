"""
Response Engine — decoupled input/output contracts.

ResponseEvent is de single input voor de engine. Het is bewust
ontkoppeld van de SOC ORM models zodat de response module
onafhankelijk getest en gebruikt kan worden.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ResponseEvent:
    """
    Genormaliseerde input voor de Response Engine.

    Vereist: soc_event_id, event_type, risk_score.
    De engine degradeert gracefully als optionele velden ontbreken.
    """

    # ── Identity ─────────────────────────────────────────────────────────────
    soc_event_id: uuid.UUID
    event_type: str                  # bijv. "brute_force", "account_takeover"
    occurred_at: datetime = field(default_factory=datetime.utcnow)

    # ── Risk context ─────────────────────────────────────────────────────────
    risk_score: float = 0.0          # 0-100, bepaalt response tier
    severity: str = "medium"         # info/low/medium/high/critical

    # ── Network observables ──────────────────────────────────────────────────
    source_ip: Optional[str] = None
    source_country: Optional[str] = None

    # ── Actor context ────────────────────────────────────────────────────────
    actor_id: Optional[uuid.UUID] = None
    actor_display_name: Optional[str] = None
    actor_threat_level: Optional[str] = None

    # ── Platform / account ───────────────────────────────────────────────────
    platform: Optional[str] = None
    target_user_id: Optional[str] = None

    # ── Enrichment snapshot ──────────────────────────────────────────────────
    threat_intel: Optional[dict] = None
    description: Optional[str] = None

    def to_snapshot(self) -> dict:
        """Serialiseer naar dict voor opslag in decision.input_snapshot."""
        return {
            "soc_event_id": str(self.soc_event_id),
            "event_type": self.event_type,
            "occurred_at": self.occurred_at.isoformat(),
            "risk_score": self.risk_score,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "source_country": self.source_country,
            "actor_id": str(self.actor_id) if self.actor_id else None,
            "actor_display_name": self.actor_display_name,
            "actor_threat_level": self.actor_threat_level,
            "platform": self.platform,
            "target_user_id": self.target_user_id,
            "description": self.description,
        }


@dataclass
class ActionResult:
    """Resultaat van een uitgevoerde actie (voor de engine, niet voor DB)."""
    action_type: str
    status: str       # "success" | "failed" | "skipped"
    target: Optional[str] = None
    payload: Optional[dict] = None
    error: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class ResponseResult:
    """
    Output van ResponseEngine.process().

    Bevat de beslissing en de resultaten van alle uitgevoerde acties.
    """
    decision_id: uuid.UUID
    tier: str
    risk_score: float
    rules_matched: list[dict]
    actions_executed: list[ActionResult]
    is_dry_run: bool = False

    @property
    def all_succeeded(self) -> bool:
        return all(a.status == "success" for a in self.actions_executed)

    @property
    def has_failures(self) -> bool:
        return any(a.status == "failed" for a in self.actions_executed)

    def summary(self) -> str:
        ok = sum(1 for a in self.actions_executed if a.status == "success")
        fail = sum(1 for a in self.actions_executed if a.status == "failed")
        skip = sum(1 for a in self.actions_executed if a.status == "skipped")
        dry = " [DRY-RUN]" if self.is_dry_run else ""
        return (
            f"[RESPONSE{dry}] tier={self.tier} risk={self.risk_score:.0f} "
            f"actions={len(self.actions_executed)} "
            f"(ok={ok} fail={fail} skip={skip}) "
            f"rules={[r['rule'] for r in self.rules_matched]}"
        )
