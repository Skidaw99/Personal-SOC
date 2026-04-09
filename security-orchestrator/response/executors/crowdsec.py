"""
CrowdSec executor — blokkeert IP-adressen via de CrowdSec Local API (LAPI).

Maakt een CrowdSec "decision" aan van type "ban" met configureerbare duratie.
De LAPI endpoint is POST /v1/decisions.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime

import httpx

from ..config import response_settings
from ..schemas import ActionResult, ResponseEvent
from .base import BaseExecutor

logger = logging.getLogger(__name__)


class CrowdSecExecutor(BaseExecutor):
    """Blokkeert IP-adressen via CrowdSec Local API."""

    @property
    def action_type(self) -> str:
        return "ip_block"

    async def execute(self, event: ResponseEvent) -> ActionResult:
        if not event.source_ip:
            return ActionResult(
                action_type=self.action_type,
                status="skipped",
                error="No source_ip available to block",
            )

        start = time.monotonic()
        target = event.source_ip

        # CrowdSec LAPI decision payload
        decision_payload = [
            {
                "duration": response_settings.crowdsec_ban_duration,
                "origin": "soc-orchestrator",
                "scenario": f"soc/{event.event_type}",
                "scope": "ip",
                "type": "ban",
                "value": target,
                "reason": (
                    f"{response_settings.crowdsec_ban_reason} "
                    f"| risk={event.risk_score:.0f} "
                    f"event={event.event_type} "
                    f"soc_event_id={event.soc_event_id}"
                ),
            }
        ]

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{response_settings.crowdsec_lapi_url}/v1/decisions",
                    json=decision_payload,
                    headers={
                        "X-Api-Key": response_settings.crowdsec_lapi_key,
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                response_data = resp.json()

            elapsed = (time.monotonic() - start) * 1000

            logger.info(
                "crowdsec_ip_blocked",
                ip=target,
                duration=response_settings.crowdsec_ban_duration,
                risk_score=event.risk_score,
                soc_event_id=str(event.soc_event_id),
            )

            return ActionResult(
                action_type=self.action_type,
                status="success",
                target=target,
                payload={
                    "request": decision_payload[0],
                    "response": response_data,
                    "crowdsec_url": response_settings.crowdsec_lapi_url,
                },
                duration_ms=elapsed,
            )

        except httpx.ConnectError as exc:
            elapsed = (time.monotonic() - start) * 1000
            error = f"Cannot connect to CrowdSec LAPI at {response_settings.crowdsec_lapi_url}: {exc}"
            logger.error("crowdsec_connection_failed", ip=target, error=error)
            return ActionResult(
                action_type=self.action_type,
                status="failed",
                target=target,
                payload={"request": decision_payload[0]},
                error=error,
                duration_ms=elapsed,
            )

        except httpx.HTTPStatusError as exc:
            elapsed = (time.monotonic() - start) * 1000
            error = f"CrowdSec LAPI error {exc.response.status_code}: {exc.response.text}"
            logger.error("crowdsec_api_error", ip=target, error=error)
            return ActionResult(
                action_type=self.action_type,
                status="failed",
                target=target,
                payload={
                    "request": decision_payload[0],
                    "response_status": exc.response.status_code,
                    "response_body": exc.response.text[:500],
                },
                error=error,
                duration_ms=elapsed,
            )

        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            error = f"CrowdSec executor error: {exc}"
            logger.error("crowdsec_executor_error", ip=target, error=error)
            return ActionResult(
                action_type=self.action_type,
                status="failed",
                target=target,
                error=error,
                duration_ms=elapsed,
            )

    async def is_available(self) -> bool:
        if not response_settings.crowdsec_lapi_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{response_settings.crowdsec_lapi_url}/v1/decisions",
                    headers={"X-Api-Key": response_settings.crowdsec_lapi_key},
                )
                return resp.status_code != 403
        except Exception:
            return False
