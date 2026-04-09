from datetime import datetime, timezone
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
from collectors.base import BaseCollector, RawEvent
from models.event import EventType
from config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()

YOUTUBE_API_BASE = "https://www.googleapis.com/youtube/v3"
GOOGLE_TOKEN_INFO = "https://oauth2.googleapis.com/tokeninfo"


class YouTubeCollector(BaseCollector):
    @property
    def platform_name(self) -> str:
        return "youtube"

    def _headers(self, access_token: str) -> dict:
        return {"Authorization": f"Bearer {access_token}"}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def fetch_events(self, account_id: str, access_token: str) -> list[RawEvent]:
        events: list[RawEvent] = []
        async with httpx.AsyncClient(timeout=30) as client:
            events.extend(await self._fetch_channel_info(client, access_token, account_id))
            events.extend(await self._fetch_recent_uploads(client, access_token))
            token_event = await self._check_token_scopes(client, access_token, account_id)
            if token_event:
                events.append(token_event)
        return events

    async def _fetch_channel_info(self, client, access_token, account_id) -> list[RawEvent]:
        events = []
        try:
            resp = await client.get(
                f"{YOUTUBE_API_BASE}/channels",
                headers=self._headers(access_token),
                params={"part": "snippet,statistics,status", "mine": "true"},
            )
            if resp.status_code == 401:
                events.append(RawEvent(
                    platform="youtube", platform_user_id=account_id,
                    event_type=EventType.TOKEN_REFRESH,
                    occurred_at=datetime.now(timezone.utc),
                    description="YouTube OAuth token rejected — possible revocation or account takeover",
                    raw_payload={"http_status": 401},
                ))
                return events
            if resp.status_code != 200:
                return events
            items = resp.json().get("items", [])
            if not items:
                return events
            channel = items[0]
            channel_id = channel.get("id", account_id)
            snippet = channel.get("snippet", {})
            stats = channel.get("statistics", {})
            events.append(RawEvent(
                platform="youtube", platform_user_id=channel_id,
                event_type=EventType.PROFILE_CHANGE,
                occurred_at=datetime.now(timezone.utc),
                description=f"YouTube channel polled: {snippet.get('title','unknown')} — {stats.get('subscriberCount',0)} subscribers",
                raw_payload={"snippet": snippet, "statistics": stats},
            ))
        except Exception as e:
            logger.error("youtube_channel_info_error", error=str(e))
        return events

    async def _fetch_recent_uploads(self, client, access_token) -> list[RawEvent]:
        events = []
        try:
            cr = await client.get(
                f"{YOUTUBE_API_BASE}/channels",
                headers=self._headers(access_token),
                params={"part": "contentDetails", "mine": "true"},
            )
            if cr.status_code != 200:
                return events
            items = cr.json().get("items", [])
            if not items:
                return events
            uploads_id = items[0].get("contentDetails", {}).get("relatedPlaylists", {}).get("uploads")
            if not uploads_id:
                return events
            pr = await client.get(
                f"{YOUTUBE_API_BASE}/playlistItems",
                headers=self._headers(access_token),
                params={"part": "snippet,status", "playlistId": uploads_id, "maxResults": 10},
            )
            if pr.status_code != 200:
                return events
            for video in pr.json().get("items", []):
                snippet = video.get("snippet", {})
                pub = snippet.get("publishedAt")
                published_at = datetime.fromisoformat(pub.replace("Z", "+00:00")) if pub else datetime.now(timezone.utc)
                events.append(RawEvent(
                    platform="youtube", platform_user_id=snippet.get("channelId", "unknown"),
                    event_type=EventType.POST_CREATED, occurred_at=published_at,
                    description=f"YouTube video uploaded: {snippet.get('title','unknown')}",
                    raw_payload=snippet,
                ))
        except Exception as e:
            logger.error("youtube_uploads_error", error=str(e))
        return events

    async def _check_token_scopes(self, client, access_token, account_id) -> RawEvent | None:
        try:
            resp = await client.get(GOOGLE_TOKEN_INFO, params={"access_token": access_token})
            if resp.status_code != 200:
                return None
            data = resp.json()
            return RawEvent(
                platform="youtube", platform_user_id=data.get("sub", account_id),
                event_type=EventType.NEW_OAUTH_APP, occurred_at=datetime.now(timezone.utc),
                client_app="Google OAuth",
                description=f"Active OAuth scopes: {data.get('scope','')}",
                raw_payload={"scope": data.get("scope"), "email": data.get("email"), "exp": data.get("exp")},
            )
        except Exception as e:
            logger.error("youtube_token_scope_error", error=str(e))
            return None

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def validate_token(self, access_token: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(GOOGLE_TOKEN_INFO, params={"access_token": access_token})
                return resp.status_code == 200
        except Exception as e:
            logger.error("youtube_token_validation_error", error=str(e))
            return False
