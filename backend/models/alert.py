import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, ForeignKey, Float, Boolean, Enum as SAEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum
from database import Base


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertCategory(str, enum.Enum):
    UNAUTHORIZED_LOGIN = "unauthorized_login"
    ACCOUNT_TAKEOVER = "account_takeover"
    API_TOKEN_MISUSE = "api_token_misuse"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class FraudAlert(Base):
    __tablename__ = "fraud_alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("social_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    triggering_event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True)
    category: Mapped[AlertCategory] = mapped_column(SAEnum(AlertCategory), nullable=False, index=True)
    status: Mapped[AlertStatus] = mapped_column(SAEnum(AlertStatus), default=AlertStatus.OPEN, nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=True)
    email_sent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    webhook_sent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=True)

    account: Mapped["SocialAccount"] = relationship("SocialAccount", back_populates="alerts")
    triggering_event: Mapped["SecurityEvent"] = relationship("SecurityEvent", back_populates="alert")
