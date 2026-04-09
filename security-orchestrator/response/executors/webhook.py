"""
Webhook executor — verstuurt alerts als JSON POST naar een configureerbaar endpoint.

Compatibel met Slack Incoming Webhooks, Microsoft Teams, PagerDuty, en
generieke webhook endpoints. Optioneel HMAC-SHA256 signed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime

import httpx

from ..config import response_settings
from ..schemas import ActionResult, ResponseEvent
from .base import BaseExecutor

logger = logging.getLogger(__name__)


class WebhookExecutor(BaseExecutor):
    """Verstuurt alert webhooks als JSON POST."""

    @property
    def action_type(self) -> str:
        return "webhook_alert"

    async def execute(self, event: ResponseEvent) -> ActionResult:
        if not response_settings.webhook_url:
            return ActionResult(
                action_type=self.action_type,
                status="skipped",
                error="No webhook_url configured",
            )

        start = time.monotonic()
        payload = self._build_payload(event)
        payload_bytes = json.dumps(payload, default=str).encode()

        headers = {"Content-Type": "application/json"}

        # Optionele HMAC signing
        if response_settings.webhook_secret:
            signature = hmac.new(
                response_settings.webhook_secret.encode(),
                payload_bytes,
                hashlib.sha256,
            ).hexdigest()
            headers["X-SOC-Signature-256"] = f"sha256={signature}"

        try:
            async with httpx.AsyncClient(
                timeout=response_settings.webhook_timeout
            ) as client:
                resp = await client.post(
                    response_settings.webhook_url,
                    content=payload_bytes,
                    headers=headers,
                )
                resp.raise_for_status()

            elapsed = (time.monotonic() - start) * 1000

            logger.info(
                "webhook_alert_sent",
                url=response_settings.webhook_url,
                status_code=resp.status_code,
                soc_event_id=str(event.soc_event_id),
            )

            return ActionResult(
                action_type=self.action_type,
                status="success",
                target=response_settings.webhook_url,
                payload=payload,
                duration_ms=elapsed,
            )

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            error = f"Webhook POST failed: {exc}"
            logger.error("webhook_send_failed", url=response_settings.webhook_url, error=error)
            return ActionResult(
                action_type=self.action_type,
                status="failed",
                target=response_settings.webhook_url,
                payload=payload,
                error=error,
                duration_ms=elapsed,
            )

    async def is_available(self) -> bool:
        return bool(response_settings.webhook_url)

    @staticmethod
    def _build_payload(event: ResponseEvent) -> dict:
        """Bouw een gestructureerd webhook payload."""
        return {
            "event": "soc_security_alert",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": event.severity.upper(),
            "risk_score": event.risk_score,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "source_country": event.source_country,
            "platform": event.platform,
            "target_user_id": event.target_user_id,
            "actor": {
                "id": str(event.actor_id) if event.actor_id else None,
                "display_name": event.actor_display_name,
                "threat_level": event.actor_threat_level,
            } if event.actor_id else None,
            "soc_event_id": str(event.soc_event_id),
            "description": event.description,
            # Slack-compatible text field
            "text": (
                f":rotating_light: *SOC Alert — {event.severity.upper()}*\n"
                f"*Type:* {event.event_type} | *Risk:* {event.risk_score:.0f}/100\n"
                f"*IP:* {event.source_ip or 'N/A'} "
                f"({event.source_country or '??'})\n"
                f"{event.description or ''}"
            ),
        }
