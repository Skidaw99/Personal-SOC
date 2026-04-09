"""
Account executor — lockt of flagged accounts via platform API.

Twee modi:
  - LOCK:  Account direct vergrendelen (account_takeover scenario)
  - FLAG:  Account markeren voor handmatige review door analist

Communiceert met een configureerbare platform management API.
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


class AccountLockExecutor(BaseExecutor):
    """Vergrendelt een account via de platform API."""

    @property
    def action_type(self) -> str:
        return "account_lock"

    async def execute(self, event: ResponseEvent) -> ActionResult:
        if not event.target_user_id:
            return ActionResult(
                action_type=self.action_type,
                status="skipped",
                error="No target_user_id available to lock",
            )

        if not response_settings.platform_api_base_url:
            return ActionResult(
                action_type=self.action_type,
                status="skipped",
                error="No platform_api_base_url configured",
            )

        return await self._call_platform_api(
            event=event,
            endpoint="/accounts/lock",
            action_data={
                "user_id": event.target_user_id,
                "reason": "account_takeover_detected",
                "lock_type": "full",
                "initiated_by": "soc-orchestrator",
                "soc_event_id": str(event.soc_event_id),
                "risk_score": event.risk_score,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
        )

    async def is_available(self) -> bool:
        return bool(
            response_settings.platform_api_base_url
            and response_settings.platform_api_key
        )


class AccountFlagExecutor(BaseExecutor):
    """Markeert een account voor review via de platform API."""

    @property
    def action_type(self) -> str:
        return "account_flag"

    async def execute(self, event: ResponseEvent) -> ActionResult:
        if not event.target_user_id:
            return ActionResult(
                action_type=self.action_type,
                status="skipped",
                error="No target_user_id available to flag",
            )

        if not response_settings.platform_api_base_url:
            return ActionResult(
                action_type=self.action_type,
                status="skipped",
                error="No platform_api_base_url configured",
            )

        return await self._call_platform_api(
            event=event,
            endpoint="/accounts/flag",
            action_data={
                "user_id": event.target_user_id,
                "reason": "high_risk_activity_detected",
                "flag_type": "review_required",
                "initiated_by": "soc-orchestrator",
                "soc_event_id": str(event.soc_event_id),
                "risk_score": event.risk_score,
                "event_type": event.event_type,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
        )

    async def is_available(self) -> bool:
        return bool(
            response_settings.platform_api_base_url
            and response_settings.platform_api_key
        )


# ── Shared platform API call logic ──────────────────────────────────────────

async def _call_platform_api(
    self: BaseExecutor,
    event: ResponseEvent,
    endpoint: str,
    action_data: dict,
) -> ActionResult:
    """Gedeelde logica voor platform API calls (lock en flag)."""
    start = time.monotonic()
    url = f"{response_settings.platform_api_base_url.rstrip('/')}{endpoint}"
    target = event.target_user_id

    try:
        async with httpx.AsyncClient(
            timeout=response_settings.platform_api_timeout
        ) as client:
            resp = await client.post(
                url,
                json=action_data,
                headers={
                    "Authorization": f"Bearer {response_settings.platform_api_key}",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            response_data = resp.json()

        elapsed = (time.monotonic() - start) * 1000

        logger.info(
            f"{self.action_type}_success",
            user_id=target,
            platform=event.platform,
            endpoint=endpoint,
        )

        return ActionResult(
            action_type=self.action_type,
            status="success",
            target=target,
            payload={"request": action_data, "response": response_data},
            duration_ms=elapsed,
        )

    except Exception as exc:
        elapsed = (time.monotonic() - start) * 1000
        error = f"Platform API call to {endpoint} failed: {exc}"
        logger.error(f"{self.action_type}_failed", user_id=target, error=error)
        return ActionResult(
            action_type=self.action_type,
            status="failed",
            target=target,
            payload={"request": action_data},
            error=error,
            duration_ms=elapsed,
        )


# Bind the shared method to both classes
AccountLockExecutor._call_platform_api = _call_platform_api
AccountFlagExecutor._call_platform_api = _call_platform_api
