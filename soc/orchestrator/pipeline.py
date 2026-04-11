"""
OrchestrationPipeline — main event processing pipeline.

Full flow per event:
  1. Normalize raw payload → SocSecurityEvent
  2. Persist event (status: NEW)
  3. IP Intelligence lookup → enrich event fields
  4. Update event (status: ENRICHED)
  5. Correlate → link to threat actor + detect attack patterns
  6. Compute final risk score (intel + correlation bonuses)
  7. Update event (status: CORRELATED)
  8. Broadcast to WebSocket for live dashboard

Each step is isolated — a failure in enrichment doesn't block correlation.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from soc.intel.engine import IntelEngine
from soc.intel.schemas import IntelResult
from soc.models.security_event import SocSecurityEvent, SocEventStatus, SocSeverity
from soc.orchestrator.normalizer import EventNormalizer
from soc.orchestrator.correlator import EventCorrelator, CorrelationResult

logger = logging.getLogger(__name__)

# ── Risk score weights ───────────────────────────────────────────────────────
# Final score = weighted combination of raw risk + IP intel + correlation
_W_RAW_RISK = 0.35          # weight of the originating system's score
_W_IP_INTEL = 0.45          # weight of IP threat_score from intel engine
_W_CORRELATION = 0.20       # weight of correlation signals

# Severity thresholds for auto-escalation
_ESCALATION_THRESHOLD = 75.0
_CRITICAL_THRESHOLD = 90.0


class OrchestrationPipeline:
    """
    Stateless pipeline — instantiate once, call process() per event.

    Requires:
      - IntelEngine (already started)
      - AsyncSession (per-request)
    """

    def __init__(
        self,
        intel_engine: IntelEngine,
        normalizer: Optional[EventNormalizer] = None,
        correlator: Optional[EventCorrelator] = None,
    ) -> None:
        self._intel = intel_engine
        self._normalizer = normalizer or EventNormalizer()
        self._correlator = correlator or EventCorrelator()

    async def process(
        self,
        session: AsyncSession,
        payload: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        """
        Process a single event through the full pipeline.

        Args:
            session: Active database session (caller manages lifecycle).
            payload: Raw JSON dict from the SFD Redis queue.

        Returns:
            Summary dict for WebSocket broadcast, or None on failure.
        """
        start = time.monotonic()

        # ── 1. Normalize ─────────────────────────────────────────────────────
        event = self._normalizer.normalize(payload)
        if event is None:
            logger.warning("pipeline: normalization failed, skipping")
            return None

        # ── 2. Persist (NEW) ─────────────────────────────────────────────────
        session.add(event)
        await session.flush()

        logger.info(
            "pipeline: ingested event=%s type=%s ip=%s raw_risk=%.1f",
            event.id, event.event_type.value, event.source_ip, event.raw_risk_score,
        )

        # ── 3. IP Intelligence Enrichment ────────────────────────────────────
        intel: Optional[IntelResult] = None
        if event.source_ip:
            try:
                intel = await self._intel.lookup(event.source_ip, session=session)
                self._apply_intel(event, intel)
                event.status = SocEventStatus.ENRICHED
                event.enriched_at = datetime.utcnow()
                await session.flush()
            except Exception as exc:
                logger.warning(
                    "pipeline: enrichment failed for ip=%s: %s",
                    event.source_ip, exc,
                )

        # ── 4. Correlation ───────────────────────────────────────────────────
        correlation: Optional[CorrelationResult] = None
        try:
            platform = payload.get("platform")
            correlation = await self._correlator.correlate(
                session, event, platform=platform,
            )
        except Exception as exc:
            logger.warning("pipeline: correlation failed: %s", exc)

        # ── 5. Final Risk Score ──────────────────────────────────────────────
        self._compute_final_score(event, intel, correlation)

        # ── 6. Auto-escalation ───────────────────────────────────────────────
        if event.threat_score and event.threat_score >= _ESCALATION_THRESHOLD:
            event.status = SocEventStatus.ESCALATED
            if event.threat_score >= _CRITICAL_THRESHOLD:
                event.severity = SocSeverity.CRITICAL
            else:
                event.severity = SocSeverity.HIGH

        # ── 7. Commit ────────────────────────────────────────────────────────
        await session.commit()

        duration_ms = round((time.monotonic() - start) * 1000, 2)
        logger.info(
            "pipeline: complete event=%s score=%.1f status=%s actor=%s duration=%.0fms",
            event.id, event.threat_score or 0,
            event.status.value,
            correlation.actor_display_name if correlation else "none",
            duration_ms,
        )

        # ── 8. Build broadcast payload ───────────────────────────────────────
        return self._build_broadcast(event, intel, correlation, duration_ms)

    def _apply_intel(self, event: SocSecurityEvent, intel: IntelResult) -> None:
        """Write IP intelligence data onto the event record."""
        # Geo
        event.source_country = event.source_country or intel.geo.country_code
        event.source_city = intel.geo.city
        event.source_asn = intel.geo.asn
        event.source_isp = intel.geo.isp
        event.source_latitude = intel.geo.latitude
        event.source_longitude = intel.geo.longitude

        # Anonymization flags
        event.ip_is_tor = intel.is_tor
        event.ip_is_vpn = intel.is_vpn
        event.ip_is_proxy = intel.is_proxy
        event.ip_is_datacenter = intel.is_datacenter
        event.ip_abuse_confidence = intel.abuse_confidence_score

        # Store full enrichment data as JSONB
        event.enrichment_data = intel.to_api_response()

    def _compute_final_score(
        self,
        event: SocSecurityEvent,
        intel: Optional[IntelResult],
        correlation: Optional[CorrelationResult],
    ) -> None:
        """
        Weighted composite risk score:
          35% raw risk from originating system
          45% IP threat score from intel engine
          20% correlation signals (attack burst, cross-platform)
        """
        raw_component = event.raw_risk_score * _W_RAW_RISK

        intel_component = 0.0
        if intel:
            intel_component = intel.threat_score * _W_IP_INTEL

        correlation_component = 0.0
        if correlation:
            # Base: risk_bonus already computed by correlator
            corr_signal = correlation.risk_bonus
            # Cluster size amplifier
            if correlation.cluster_size > 1:
                corr_signal += min(20.0, correlation.cluster_size * 3.0)
            # Confidence bonus
            if correlation.match_confidence >= 80:
                corr_signal += 10.0
            correlation_component = min(100.0, corr_signal) * _W_CORRELATION

        final = raw_component + intel_component + correlation_component
        event.threat_score = round(min(100.0, max(0.0, final)), 2)

    def _build_broadcast(
        self,
        event: SocSecurityEvent,
        intel: Optional[IntelResult],
        correlation: Optional[CorrelationResult],
        duration_ms: float,
    ) -> dict[str, Any]:
        """Build the WebSocket broadcast payload."""
        broadcast: dict[str, Any] = {
            "soc_event_id": str(event.id),
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "risk_score": event.threat_score or event.raw_risk_score,
            "source_ip": event.source_ip,
            "source_country": event.source_country,
            "source_city": event.source_city,
            "source_latitude": event.source_latitude,
            "source_longitude": event.source_longitude,
            "status": event.status.value,
            "occurred_at": event.occurred_at.isoformat(),
            "processing_time_ms": duration_ms,
        }

        # Intel summary
        if intel:
            broadcast["intel"] = {
                "threat_score": intel.threat_score,
                "reputation": intel.reputation,
                "is_tor": intel.is_tor,
                "is_vpn": intel.is_vpn,
                "abuse_confidence": intel.abuse_confidence_score,
                "isp": intel.geo.isp,
                "asn": intel.geo.asn,
                "from_cache": intel.from_cache,
            }

        # Correlation summary
        if correlation:
            broadcast["correlation"] = {
                "threat_actor_id": str(correlation.threat_actor_id) if correlation.threat_actor_id else None,
                "actor_display_name": correlation.actor_display_name,
                "was_new_actor": correlation.was_new_actor,
                "match_confidence": correlation.match_confidence,
                "is_attack_burst": correlation.is_attack_burst,
                "cluster_size": correlation.cluster_size,
                "platforms_hit": correlation.platforms_hit,
            }

        return broadcast
