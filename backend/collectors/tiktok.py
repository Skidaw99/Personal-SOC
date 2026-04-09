from datetime import datetime, timezone
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from collectors.base import BaseCollector, RawEvent
from models.event import EventType
from config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

TIKTOK_API_BASE = "https://open.tiktokapis.com/v2"


class TikTokCollector(BaseCollector):
    """
    Collects security events from TikTok for Developers API v2.
    Monitors: user info changes, video post volume, token validity.
    TikTok does not expose login/session data via third-party API.
    """

    @property
    def platform_name(self) -> str:
        return "tiktok"

    def _headers(self, access_token: str) -> dict:
        return {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def fetch_events(self, account_id: str, access_token: str) -> list[RawEvent]:
        events: list[RawEvent] = []

        async with httpx.AsyncClient(timeout=30) as client:
            user_events = await self._fetch_user_info(client, access_token, account_id)
            events.extend(user_events)

            video_events = await self._fetch_video_activity(client, access_token)
            events.extend(video_events)

        return events

    async def _fetch_user_info(
        self, client: httpx.AsyncClient, access_token: str, account_id: str
    ) -> list[RawEvent]:
        events = []
        try:
            resp = await client.post(
                f"{TIKTOK_API_BASE}/user/info/",
                headers=self._headers(access_token),
                json={"fields": ["open_id", "union_id", "display_name", "bio_description", "profile_deep_link"]},
            )

            if resp.status_code == 401:
                events.append(RawEvent(
                    platform="tiktok",
                    platform_user_id=account_id,
                    event_type=EventType.TOKEN_REFRESH,
                    occurred_at=datetime.now(timezone.utc),
                    description="TikTok access token rejected — possible revocation or account compromise",
                    raw_payload={"http_status": 401},
                ))
                return events

            if resp.status_code != 200:
                return events

            data = resp.json().get("data", {}).get("user", {})
            user_id = data.get("open_id", account_id)

            events.append(RawEvent(
                platform="tiktok",
                platform_user_id=user_id,
                event_type=EventType.PROFILE_CHANGE,
                occurred_at=datetime.now(timezone.utc),
                description=f"TikTok user info polled: {data.get('display_name', 'unknown')}",
                raw_payload=data,
            ))
        except Exception as e:
            logger.error("tiktok_user_info_error", error=str(e))
        return events

    async def _fetch_video_activity(
        self, client: httpx.AsyncClient, access_token: str
    ) -> list[RawEvent]:
        events = []
        try:
            resp = await client.post(
                f"{TIKTOK_API_BASE}/video/list/",
                headers=self._headers(access_token),
                json={"fields": ["id", "create_time", "share_url"], "max_count": 20},
            )
            if resp.status_code != 200:
                return events

            data = resp.json().get("data", {})
            videos = data.get("videos", [])

            events.append(RawEvent(
                platform="tiktok",
                platform_user_id="me",
                event_type=EventType.POST_CREATED,
                occurred_at=datetime.now(timezone.utc),
                description=f"TikTok video activity: {len(videos)} recent videos",
                raw_payload={"video_count": len(videos)},
            ))
        except Exception as e:
            logger.error("tiktok_video_activity_error", error=str(e))
        return events

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def validate_token(self, access_token: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{TIKTOK_API_BASE}/user/info/",
                    headers=self._headers(access_token),
                    json={"fields": ["open_id"]},
                )
                return resp.status_code == 200
        except Exception as e:
            logger.error("tiktok_token_validation_error", error=str(e))
            return False
