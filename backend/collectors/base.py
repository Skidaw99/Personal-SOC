from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from models.event import EventType, EventSeverity


@dataclass
class RawEvent:
    """Normalized event emitted by any platform collector."""
    platform: str
    platform_user_id: str
    event_type: EventType
    occurred_at: datetime
    source_ip: Optional[str] = None
    source_country: Optional[str] = None
    source_device: Optional[str] = None
    client_app: Optional[str] = None
    description: str = ""
    raw_payload: dict = field(default_factory=dict)


class BaseCollector(ABC):
    """
    Abstract base class for all platform-specific collectors.
    Each collector is responsible for fetching security-relevant events
    from a specific social platform's API.
    """

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Return the platform identifier string."""
        ...

    @abstractmethod
    async def fetch_events(self, account_id: str, access_token: str) -> list[RawEvent]:
        """
        Poll the platform API and return a list of normalized RawEvent objects.
        Must handle rate limits gracefully using tenacity retry logic.
        """
        ...

    @abstractmethod
    async def validate_token(self, access_token: str) -> bool:
        """
        Verify that the given access token is still valid.
        Returns False if the token has been revoked or expired.
        """
        ...
