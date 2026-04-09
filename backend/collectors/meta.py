from datetime import datetime, timezone
from typing import Optional
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from collectors.base import BaseCollector, RawEvent
from models.event import EventType
from config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

META_GRAPH_BASE = "https://graph.facebook.com/v21.0"


class MetaCollector(BaseCollector):
    """
    Collects security events from Meta Graph API (Facebook + Instagram).
    Monitors: login activity, connected apps, account setting changes.
    """

    @property
    def platform_name(self) -> str:
        return "meta"

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def fetch_events(self, account_id: str, access_token: str) -> list[RawEvent]:
        events: list[RawEvent] = []

        async with httpx.AsyncClient(timeout=30) as client:
            # Fetch login activity (requires user_security_info permission)
            login_events = await self._fetch_login_activity(client, access_token)
            events.extend(login_events)

            # Fetch connected apps
            app_events = await self._fetch_connected_apps(client, access_token, account_id)
            events.extend(app_events)

            # Fetch recent account setting changes
            setting_events = await self._fetch_setting_changes(client, access_token, account_id)
            events.extend(setting_events)

        return events

    async def _fetch_login_activity(self, client: httpx.AsyncClient, access_token: str) -> list[RawEvent]:
        events = []
        try:
            resp = await client.get(
                f"{META_GRAPH_BASE}/me/security",
                params={"access_token": access_token, "fields": "login_approvals,trusted_browsers,trusted_devices"}
            )
            if resp.status_code != 200:
                logger.warning("meta_login_activity_fetch_failed", status=resp.status_code, body=resp.text)
                return events

            data = resp.json()
            user_id = data.get("id", "unknown")

            # Parse login activity from meta response
            for entry in data.get("login_approvals", {}).get("data", []):
                events.append(RawEvent(
                    platform="facebook",
                    platform_user_id=user_id,
                    event_type=EventType.LOGIN,
                    occurred_at=datetime.fromisoformat(entry.get("created_time", datetime.utcnow().isoformat())),
                    source_ip=entry.get("browser_info", {}).get("ip_address"),
                    source_country=entry.get("browser_info", {}).get("location", {}).get("country"),
                    source_device=entry.get("browser_info", {}).get("device"),
                    description="Login approval activity detected via Meta API",
                    raw_payload=entry,
                ))
        except Exception as e:
            logger.error("meta_login_activity_error", error=str(e))
        return events

    async def _fetch_connected_apps(
        self, client: httpx.AsyncClient, access_token: str, account_id: str
    ) -> list[RawEvent]:
        events = []
        try:
            resp = await client.get(
                f"{META_GRAPH_BASE}/me/permissions",
                params={"access_token": access_token}
            )
            if resp.status_code != 200:
                return events

            data = resp.json()
            user_id = data.get("id", account_id)

            for perm in data.get("data", []):
                if perm.get("status") == "granted":
                    events.append(RawEvent(
                        platform="facebook",
                        platform_user_id=user_id,
                        event_type=EventType.NEW_OAUTH_APP,
                        occurred_at=datetime.now(timezone.utc),
                        client_app=perm.get("permission"),
                        description=f"OAuth permission active: {perm.get('permission')}",
                        raw_payload=perm,
                    ))
        except Exception as e:
            logger.error("meta_connected_apps_error", error=str(e))
        return events

    async def _fetch_setting_changes(
        self, client: httpx.AsyncClient, access_token: str, account_id: str
    ) -> list[RawEvent]:
        events = []
        try:
            resp = await client.get(
                f"{META_GRAPH_BASE}/me",
                params={"access_token": access_token, "fields": "email,name,updated_time"}
            )
            if resp.status_code != 200:
                return events

            data = resp.json()
            updated_str = data.get("updated_time")
            if updated_str:
                updated_at = datetime.fromisoformat(updated_str.replace("Z", "+00:00"))
                events.append(RawEvent(
                    platform="facebook",
                    platform_user_id=data.get("id", account_id),
                    event_type=EventType.PROFILE_CHANGE,
                    occurred_at=updated_at,
                    description="Profile metadata updated on Meta platform",
                    raw_payload=data,
                ))
        except Exception as e:
            logger.error("meta_setting_changes_error", error=str(e))
        return events

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def validate_token(self, access_token: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{META_GRAPH_BASE}/debug_token",
                    params={
                        "input_token": access_token,
                        "access_token": f"{settings.meta_app_id}|{settings.meta_app_secret}",
                    }
                )
                if resp.status_code != 200:
                    return False
                data = resp.json()
                return data.get("data", {}).get("is_valid", False)
        except Exception as e:
            logger.error("meta_token_validation_error", error=str(e))
            return False
