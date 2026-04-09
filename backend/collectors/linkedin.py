from datetime import datetime, timezone
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from collectors.base import BaseCollector, RawEvent
from models.event import EventType
from config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

LINKEDIN_API_BASE = "https://api.linkedin.com/v2"


class LinkedInCollector(BaseCollector):
    """
    Collects security events from LinkedIn API v2.
    LinkedIn has limited security event APIs — we monitor:
    - Token validity (revocation = potential takeover)
    - Profile changes
    - Post activity volume
    LinkedIn does not expose login session data via API, so polling-based detection is used.
    """

    @property
    def platform_name(self) -> str:
        return "linkedin"

    def _headers(self, access_token: str) -> dict:
        return {
            "Authorization": f"Bearer {access_token}",
            "X-Restli-Protocol-Version": "2.0.0",
            "Content-Type": "application/json",
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def fetch_events(self, account_id: str, access_token: str) -> list[RawEvent]:
        events: list[RawEvent] = []

        async with httpx.AsyncClient(timeout=30) as client:
            profile_events = await self._fetch_profile_info(client, access_token)
            events.extend(profile_events)

            post_events = await self._fetch_post_activity(client, access_token)
            events.extend(post_events)

        return events

    async def _fetch_profile_info(self, client: httpx.AsyncClient, access_token: str) -> list[RawEvent]:
        events = []
        try:
            resp = await client.get(
                f"{LINKEDIN_API_BASE}/userinfo",
                headers=self._headers(access_token),
            )
            if resp.status_code == 401:
                logger.warning("linkedin_token_revoked")
                events.append(RawEvent(
                    platform="linkedin",
                    platform_user_id="unknown",
                    event_type=EventType.TOKEN_REFRESH,
                    occurred_at=datetime.now(timezone.utc),
                    description="LinkedIn access token rejected — possible revocation or account takeover",
                    raw_payload={"http_status": 401},
                ))
                return events

            if resp.status_code != 200:
                return events

            data = resp.json()
            user_id = data.get("sub", "unknown")

            events.append(RawEvent(
                platform="linkedin",
                platform_user_id=user_id,
                event_type=EventType.PROFILE_CHANGE,
                occurred_at=datetime.now(timezone.utc),
                description=f"LinkedIn profile polled: {data.get('name', 'unknown')}",
                raw_payload=data,
            ))
        except Exception as e:
            logger.error("linkedin_profile_fetch_error", error=str(e))
        return events

    async def _fetch_post_activity(self, client: httpx.AsyncClient, access_token: str) -> list[RawEvent]:
        events = []
        try:
            resp = await client.get(
                f"{LINKEDIN_API_BASE}/ugcPosts",
                headers=self._headers(access_token),
                params={"q": "authors", "count": 10, "sortBy": "LAST_MODIFIED"},
            )
            if resp.status_code != 200:
                return events

            data = resp.json()
            total = data.get("paging", {}).get("total", 0)

            events.append(RawEvent(
                platform="linkedin",
                platform_user_id="me",
                event_type=EventType.POST_CREATED,
                occurred_at=datetime.now(timezone.utc),
                description=f"LinkedIn post activity check: {total} total posts found",
                raw_payload={"total_posts": total},
            ))
        except Exception as e:
            logger.error("linkedin_post_activity_error", error=str(e))
        return events

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def validate_token(self, access_token: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{LINKEDIN_API_BASE}/userinfo",
                    headers=self._headers(access_token),
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error("linkedin_token_validation_error", error=str(e))
            return False
