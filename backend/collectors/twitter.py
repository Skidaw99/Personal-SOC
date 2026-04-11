from datetime import datetime, timezone
import tweepy
from tenacity import retry, stop_after_attempt, wait_exponential
from collectors.base import BaseCollector, RawEvent
from models.event import EventType
from config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


class TwitterCollector(BaseCollector):

    @property
    def platform_name(self) -> str:
        return "twitter"

    def _get_client(self, access_token: str = None) -> tweepy.Client:
        return tweepy.Client(
            bearer_token=settings.twitter_bearer_token,
            consumer_key=settings.twitter_api_key,
            consumer_secret=settings.twitter_api_secret,
            access_token=access_token or settings.twitter_access_token,
            access_token_secret=settings.twitter_access_token_secret,
            wait_on_rate_limit=True,
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def fetch_events(self, account_id: str, access_token: str) -> list[RawEvent]:
        import asyncio
        events: list[RawEvent] = []
        client = self._get_client(access_token)

        try:
            user_resp = await asyncio.to_thread(
                client.get_me,
                user_fields=["id", "username", "name"]
            )
            if not user_resp.data:
                return events

            user = user_resp.data
            twitter_user_id = str(user.id)

            tweet_resp = await asyncio.to_thread(
                client.get_users_tweets,
                id=twitter_user_id,
                max_results=100,
                tweet_fields=["created_at", "source"],
            )

            if tweet_resp.data:
                sources = {}
                for tweet in tweet_resp.data:
                    source = getattr(tweet, "source", "unknown")
                    sources[source] = sources.get(source, 0) + 1

                for source_app, count in sources.items():
                    events.append(RawEvent(
                        platform="twitter",
                        platform_user_id=twitter_user_id,
                        event_type=EventType.POST_CREATED,
                        occurred_at=datetime.now(timezone.utc),
                        client_app=source_app,
                        description=f"{count} tweets posted via client: {source_app}",
                        raw_payload={"source": source_app, "count": count},
                    ))

            events.append(RawEvent(
                platform="twitter",
                platform_user_id=twitter_user_id,
                event_type=EventType.TOKEN_REFRESH,
                occurred_at=datetime.now(timezone.utc),
                description="Routine token validity check",
                raw_payload={"token_present": bool(access_token)},
            ))

        except tweepy.errors.Unauthorized:
            logger.warning("twitter_token_unauthorized", account_id=account_id)
            events.append(RawEvent(
                platform="twitter",
                platform_user_id=account_id,
                event_type=EventType.TOKEN_REFRESH,
                occurred_at=datetime.now(timezone.utc),
                description="Twitter access token unauthorized",
                raw_payload={"error": "unauthorized"},
            ))
        except Exception as e:
            logger.error("twitter_fetch_error", error=str(e))

        return events

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=5))
    async def validate_token(self, access_token: str) -> bool:
        import asyncio
        try:
            client = self._get_client(access_token)
            resp = await asyncio.to_thread(client.get_me)
            return resp.data is not None
        except tweepy.errors.Unauthorized:
            return False
        except Exception as e:
            logger.error("twitter_token_validation_error", error=str(e))
            return False
