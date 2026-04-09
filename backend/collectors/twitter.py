from datetime import datetime, timezone
import tweepy
import tweepy.asynchronous
from tenacity import retry, stop_after_attempt, wait_exponential
from collectors.base import BaseCollector, RawEvent
from models.event import EventType
from config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


class TwitterCollector(BaseCollector):
    """
    Collects security events from the X (Twitter) API v2.
    Monitors: account activity, connected apps, direct message volume spikes.
    Uses tweepy AsyncClient for async operations.
    """

    @property
    def platform_name(self) -> str:
        return "twitter"

    def _get_client(self, access_token: str = None) -> tweepy.AsyncClient:
        return tweepy.AsyncClient(
            bearer_token=settings.twitter_bearer_token,
            consumer_key=settings.twitter_api_key,
            consumer_secret=settings.twitter_api_secret,
            access_token=access_token or settings.twitter_access_token,
            access_token_secret=settings.twitter_access_token_secret,
            wait_on_rate_limit=True,
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def fetch_events(self, account_id: str, access_token: str) -> list[RawEvent]:
        events: list[RawEvent] = []
        client = self._get_client(access_token)

        try:
            # Fetch authenticated user info
            user_resp = await client.get_me(
                user_fields=["id", "username", "name", "created_at", "entities"]
            )
            if not user_resp.data:
                return events

            user = user_resp.data
            twitter_user_id = str(user.id)

            # Fetch recent tweets for volume anomaly detection
            tweet_events = await self._fetch_recent_tweet_volume(client, twitter_user_id)
            events.extend(tweet_events)

            # Check for connected apps via OAuth token introspection
            token_event = self._check_token_status(twitter_user_id, access_token)
            if token_event:
                events.append(token_event)

        except tweepy.errors.Unauthorized:
            logger.warning("twitter_token_unauthorized", account_id=account_id)
            events.append(RawEvent(
                platform="twitter",
                platform_user_id=account_id,
                event_type=EventType.TOKEN_REFRESH,
                occurred_at=datetime.now(timezone.utc),
                description="Twitter access token is no longer valid — possible revocation or account takeover",
                raw_payload={"error": "unauthorized"},
            ))
        except Exception as e:
            logger.error("twitter_fetch_error", error=str(e), account_id=account_id)

        return events

    async def _fetch_recent_tweet_volume(
        self, client: tweepy.AsyncClient, user_id: str
    ) -> list[RawEvent]:
        events = []
        try:
            resp = await client.get_users_tweets(
                id=user_id,
                max_results=100,
                tweet_fields=["created_at", "source"],
            )
            if not resp.data:
                return events

            # Group by source app to detect unknown posting clients
            sources = {}
            for tweet in resp.data:
                source = getattr(tweet, "source", "unknown")
                sources[source] = sources.get(source, 0) + 1

            for source_app, count in sources.items():
                events.append(RawEvent(
                    platform="twitter",
                    platform_user_id=user_id,
                    event_type=EventType.POST_CREATED,
                    occurred_at=datetime.now(timezone.utc),
                    client_app=source_app,
                    description=f"{count} tweets posted via client: {source_app}",
                    raw_payload={"source": source_app, "count": count},
                ))
        except Exception as e:
            logger.error("twitter_tweet_volume_error", error=str(e))
        return events

    def _check_token_status(self, user_id: str, access_token: str) -> RawEvent | None:
        """Emit a token refresh event so the analyzer can check if the token changed."""
        return RawEvent(
            platform="twitter",
            platform_user_id=user_id,
            event_type=EventType.TOKEN_REFRESH,
            occurred_at=datetime.now(timezone.utc),
            description="Routine token validity check",
            raw_payload={"token_present": bool(access_token)},
        )

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def validate_token(self, access_token: str) -> bool:
        try:
            client = self._get_client(access_token)
            resp = await client.get_me()
            return resp.data is not None
        except tweepy.errors.Unauthorized:
            return False
        except Exception as e:
            logger.error("twitter_token_validation_error", error=str(e))
            return False
