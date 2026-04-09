from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    database_url: str = Field(..., env="DATABASE_URL")
    postgres_db: str = Field(..., env="POSTGRES_DB")

    # Redis
    redis_url: str = Field(..., env="REDIS_URL")

    # App security
    secret_key: str = Field(..., env="SECRET_KEY")
    encryption_key: str = Field(..., env="ENCRYPTION_KEY")
    dashboard_username: str = Field(..., env="DASHBOARD_USERNAME")
    dashboard_password: str = Field(..., env="DASHBOARD_PASSWORD")

    # Email
    smtp_host: str = Field(default="smtp.gmail.com", env="SMTP_HOST")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_username: str = Field(..., env="SMTP_USERNAME")
    smtp_password: str = Field(..., env="SMTP_PASSWORD")
    alert_from_email: str = Field(..., env="ALERT_FROM_EMAIL")
    alert_to_email: str = Field(..., env="ALERT_TO_EMAIL")

    # Webhook
    webhook_secret: str = Field(..., env="WEBHOOK_SECRET")
    webhook_target_url: str = Field(default="", env="WEBHOOK_TARGET_URL")

    # Meta
    meta_app_id: str = Field(default="", env="META_APP_ID")
    meta_app_secret: str = Field(default="", env="META_APP_SECRET")
    meta_access_token: str = Field(default="", env="META_ACCESS_TOKEN")
    meta_verify_token: str = Field(default="", env="META_VERIFY_TOKEN")

    # Twitter
    twitter_api_key: str = Field(default="", env="TWITTER_API_KEY")
    twitter_api_secret: str = Field(default="", env="TWITTER_API_SECRET")
    twitter_access_token: str = Field(default="", env="TWITTER_ACCESS_TOKEN")
    twitter_access_token_secret: str = Field(default="", env="TWITTER_ACCESS_TOKEN_SECRET")
    twitter_bearer_token: str = Field(default="", env="TWITTER_BEARER_TOKEN")
    twitter_webhook_env_name: str = Field(default="", env="TWITTER_WEBHOOK_ENV_NAME")

    # LinkedIn
    linkedin_client_id: str = Field(default="", env="LINKEDIN_CLIENT_ID")
    linkedin_client_secret: str = Field(default="", env="LINKEDIN_CLIENT_SECRET")
    linkedin_access_token: str = Field(default="", env="LINKEDIN_ACCESS_TOKEN")

    # TikTok
    tiktok_client_key: str = Field(default="", env="TIKTOK_CLIENT_KEY")
    tiktok_client_secret: str = Field(default="", env="TIKTOK_CLIENT_SECRET")
    tiktok_access_token: str = Field(default="", env="TIKTOK_ACCESS_TOKEN")

    # Google / YouTube
    google_client_id: str = Field(default="", env="GOOGLE_CLIENT_ID")
    google_client_secret: str = Field(default="", env="GOOGLE_CLIENT_SECRET")
    google_access_token: str = Field(default="", env="GOOGLE_ACCESS_TOKEN")
    google_refresh_token: str = Field(default="", env="GOOGLE_REFRESH_TOKEN")
    youtube_channel_id: str = Field(default="", env="YOUTUBE_CHANNEL_ID")

    # Polling intervals (seconds)
    polling_interval_meta: int = Field(default=300, env="POLLING_INTERVAL_META")
    polling_interval_twitter: int = Field(default=180, env="POLLING_INTERVAL_TWITTER")
    polling_interval_linkedin: int = Field(default=600, env="POLLING_INTERVAL_LINKEDIN")
    polling_interval_tiktok: int = Field(default=600, env="POLLING_INTERVAL_TIKTOK")
    polling_interval_youtube: int = Field(default=300, env="POLLING_INTERVAL_YOUTUBE")

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()
