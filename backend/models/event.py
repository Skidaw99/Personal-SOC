import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, ForeignKey, Float, Enum as SAEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum
from database import Base


class EventType(str, enum.Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    EMAIL_CHANGE = "email_change"
    PHONE_CHANGE = "phone_change"
    NEW_OAUTH_APP = "new_oauth_app"
    TOKEN_REFRESH = "token_refresh"
    API_CALL_SPIKE = "api_call_spike"
    POST_CREATED = "post_created"
    MESSAGE_SENT = "message_sent"
    FOLLOWER_SPIKE = "follower_spike"
    APP_REVOKED = "app_revoked"
    PROFILE_CHANGE = "profile_change"
    UNKNOWN = "unknown"


class EventSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("social_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[EventType] = mapped_column(SAEnum(EventType), nullable=False, index=True)
    severity: Mapped[EventSeverity] = mapped_column(SAEnum(EventSeverity), default=EventSeverity.INFO, nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=True)
    source_country: Mapped[str] = mapped_column(String(64), nullable=True)
    source_device: Mapped[str] = mapped_column(String(512), nullable=True)
    client_app: Mapped[str] = mapped_column(String(512), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    account: Mapped["SocialAccount"] = relationship("SocialAccount", back_populates="events")
    alert: Mapped["FraudAlert"] = relationship("FraudAlert", back_populates="triggering_event", uselist=False)
