import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, Text, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
import enum
from database import Base


class Platform(str, enum.Enum):
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"
    TIKTOK = "tiktok"
    YOUTUBE = "youtube"


class AccountStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    COMPROMISED = "compromised"
    MONITORING = "monitoring"


class SocialAccount(Base):
    __tablename__ = "social_accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    platform: Mapped[Platform] = mapped_column(SAEnum(Platform), nullable=False, index=True)
    platform_user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(512), nullable=True)
    encrypted_access_token: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[AccountStatus] = mapped_column(SAEnum(AccountStatus), default=AccountStatus.ACTIVE, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    last_checked_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    last_known_ip: Mapped[str] = mapped_column(String(64), nullable=True)
    last_known_country: Mapped[str] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=True)

    events: Mapped[list["SecurityEvent"]] = relationship("SecurityEvent", back_populates="account", lazy="select")
    alerts: Mapped[list["FraudAlert"]] = relationship("FraudAlert", back_populates="account", lazy="select")
    baselines: Mapped[list["BehaviorBaseline"]] = relationship("BehaviorBaseline", back_populates="account", lazy="select")
