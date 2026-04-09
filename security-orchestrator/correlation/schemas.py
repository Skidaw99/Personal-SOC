"""
Correlation schemas — decoupled input/output contracts.

CorrelationEvent is the single input type accepted by the profiler.
It is deliberately lightweight and independent of the SOC ORM models so
the correlation module can be tested and used in isolation.

Callers (e.g. the Security Orchestrator) convert SocSecurityEvent → CorrelationEvent.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class CorrelationEvent:
    """
    Normalized input event for the Threat Actor Profiler.

    Required: soc_event_id, occurred_at, event_type, source.
    Everything else is optional — the profiler degrades gracefully
    when fields are missing.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    soc_event_id: uuid.UUID          # Links back to SocSecurityEvent.id
    occurred_at: datetime
    event_type: str                  # e.g. "brute_force", "account_takeover"
    source: str                      # e.g. "social_fraud_detector", "suricata"

    # ── Network observables ───────────────────────────────────────────────────
    source_ip: Optional[str] = None
    source_country: Optional[str] = None
    source_asn: Optional[int] = None
    source_isp: Optional[str] = None

    # ── Platform / target ─────────────────────────────────────────────────────
    platform: Optional[str] = None   # "twitter", "instagram", "linkedin", etc.
    target_user_id: Optional[str] = None

    # ── Device fingerprint raw material ───────────────────────────────────────
    user_agent: Optional[str] = None
    accept_language: Optional[str] = None
    # Any additional HTTP headers that help fingerprinting (k→v dict)
    extra_headers: dict[str, str] = field(default_factory=dict)

    # ── Threat context ────────────────────────────────────────────────────────
    severity: str = "low"            # info/low/medium/high/critical
    risk_score: float = 0.0
    # IP threat score from the enrichment engine (0-100)
    ip_threat_score: Optional[float] = None
    is_tor: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_proxy: Optional[bool] = None

    # ── Raw payload (stored as snapshot in ActorEvent) ─────────────────────────
    description: Optional[str] = None
    raw_payload: Optional[dict] = None


@dataclass
class ProfilerResult:
    """
    Output of ThreatActorProfiler.process().

    Contains the matched/created actor ID, the confidence level,
    which signals fired, and whether this was a new actor.
    """

    # ── Actor reference ───────────────────────────────────────────────────────
    actor_id: uuid.UUID
    actor_display_name: str
    actor_threat_level: str          # low/medium/high/critical
    actor_confidence_score: float    # 0-100, actor-level certainty

    # ── Attribution result ────────────────────────────────────────────────────
    # Confidence that THIS event belongs to THIS actor (0-100)
    match_confidence: float
    was_new_actor: bool
    # Human-readable list of signals that caused the attribution
    signals_fired: list[dict]        # [{name, score, reason}, ...]

    # ── Cross-platform flag ───────────────────────────────────────────────────
    # True if this event adds a new platform to the actor's profile
    new_platform_detected: bool = False
    # All platforms this actor has now been seen on
    all_platforms: list[str] = field(default_factory=list)

    def summary(self) -> str:
        status = "NEW ACTOR" if self.was_new_actor else f"MATCHED (conf={self.match_confidence:.0f})"
        xp = " [CROSS-PLATFORM]" if self.new_platform_detected else ""
        return (
            f"[{status}]{xp} {self.actor_display_name} "
            f"level={self.actor_threat_level} "
            f"signals={[s['name'] for s in self.signals_fired]}"
        )
