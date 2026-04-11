"""
EventNormalizer — converts raw SFD queue payloads into SOC models.

Input:  JSON dict from the soc:events:ingest Redis queue
Output: SocSecurityEvent ORM instance (unsaved) + CorrelationEvent dataclass

The normalizer never raises on bad data — it returns None and logs a warning.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Optional

from soc.models.security_event import (
    EventSource,
    SocEventType,
    SocSeverity,
    SocEventStatus,
    SocSecurityEvent,
)

logger = logging.getLogger(__name__)

# ── Source → EventSource mapping ─────────────────────────────────────────────
_SOURCE_MAP = {
    "social_fraud_detector": EventSource.SOCIAL_FRAUD_DETECTOR,
    "suricata": EventSource.SURICATA,
    "crowdsec": EventSource.CROWDSEC,
    "manual": EventSource.MANUAL,
    "api": EventSource.API,
}

# ── String → SocEventType mapping ───────────────────────────────────────────
_EVENT_TYPE_MAP = {e.value: e for e in SocEventType}

# ── String → SocSeverity mapping ────────────────────────────────────────────
_SEVERITY_MAP = {s.value: s for s in SocSeverity}


class EventNormalizer:
    """Stateless normalizer. Converts raw queue payloads to ORM objects."""

    def normalize(self, payload: dict[str, Any]) -> Optional[SocSecurityEvent]:
        """
        Convert a raw SFD payload dict into a SocSecurityEvent.

        Returns None if the payload is malformed (logged as warning).
        The returned event is NOT yet added to a session — caller does that.
        """
        try:
            return self._do_normalize(payload)
        except Exception as exc:
            logger.warning(
                "normalizer failed: %s — payload keys: %s",
                exc, list(payload.keys()),
            )
            return None

    def _do_normalize(self, p: dict[str, Any]) -> SocSecurityEvent:
        # Source
        source_str = p.get("source", "api")
        source = _SOURCE_MAP.get(source_str, EventSource.API)

        # Event type
        event_type_str = p.get("event_type", "anomaly")
        event_type = _EVENT_TYPE_MAP.get(event_type_str, SocEventType.ANOMALY)

        # Severity
        severity_str = p.get("severity", "low")
        severity = _SEVERITY_MAP.get(severity_str, SocSeverity.LOW)

        # Occurred at
        occurred_raw = p.get("occurred_at")
        if isinstance(occurred_raw, str):
            try:
                occurred_at = datetime.fromisoformat(occurred_raw)
            except ValueError:
                occurred_at = datetime.utcnow()
        elif isinstance(occurred_raw, datetime):
            occurred_at = occurred_raw
        else:
            occurred_at = datetime.utcnow()

        return SocSecurityEvent(
            id=uuid.uuid4(),
            external_id=p.get("external_id"),
            source=source,
            event_type=event_type,
            severity=severity,
            raw_risk_score=float(p.get("raw_risk_score", 0)),
            source_ip=p.get("source_ip"),
            source_country=p.get("source_country"),
            description=p.get("description"),
            raw_payload=p.get("raw_payload"),
            status=SocEventStatus.NEW,
            occurred_at=occurred_at,
            ingested_at=datetime.utcnow(),
        )

    def to_correlation_input(
        self,
        event: SocSecurityEvent,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build the dict needed to construct a CorrelationEvent.

        Returns a plain dict (not the dataclass) so the orchestrator
        can enrich it with IP intel data before constructing the final object.
        """
        return {
            "soc_event_id": event.id,
            "occurred_at": event.occurred_at,
            "event_type": event.event_type.value,
            "source": event.source.value,
            "source_ip": event.source_ip,
            "source_country": event.source_country,
            "platform": payload.get("platform"),
            "severity": event.severity.value,
            "risk_score": event.raw_risk_score,
            "description": event.description,
            "raw_payload": event.raw_payload,
        }
