import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Float, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class BehaviorBaseline(Base):
    """
    Stores per-account behavioral baselines used for anomaly detection.
    Baselines are updated on every polling cycle using a rolling window.
    """
    __tablename__ = "behavior_baselines"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("social_accounts.id", ondelete="CASCADE"), nullable=False, index=True, unique=True)

    # Login patterns
    known_ips: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)         # list of historically seen IPs
    known_countries: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)   # list of historically seen countries
    known_devices: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)     # list of historically seen device strings
    known_apps: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)        # authorized OAuth apps

    # Activity volume baselines (rolling 30-day averages)
    avg_daily_posts: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    avg_daily_messages: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    avg_daily_api_calls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Timing patterns
    typical_active_hours: Mapped[dict] = mapped_column(JSON, default=list, nullable=False)  # list of hours (0-23)
    typical_timezone: Mapped[str] = mapped_column(String(64), nullable=True)

    # Metadata
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    baseline_established: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    account: Mapped["SocialAccount"] = relationship("SocialAccount", back_populates="baselines")
