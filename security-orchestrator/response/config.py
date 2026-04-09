"""
Response Engine configuratie — CrowdSec, email, webhook, platform API settings.
"""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class ResponseSettings(BaseSettings):
    """
    Configuratie voor de Response Engine.

    Alle waarden kunnen via environment variables worden ingesteld.
    """

    # ── CrowdSec Local API ───────────────────────────────────────────────────
    crowdsec_lapi_url: str = Field(
        default="http://localhost:8080",
        description="CrowdSec Local API base URL",
    )
    crowdsec_lapi_key: str = Field(
        default="",
        description="CrowdSec bouncer API key",
    )
    crowdsec_ban_duration: str = Field(
        default="24h",
        description="Standaard ban duratie voor IP blocks (CrowdSec duration format)",
    )
    crowdsec_ban_reason: str = Field(
        default="SOC automated response — high risk threat detected",
        description="Reden opgenomen in CrowdSec beslissing",
    )

    # ── Email alerts ─────────────────────────────────────────────────────────
    smtp_host: str = Field(default="localhost", description="SMTP server hostname")
    smtp_port: int = Field(default=587, description="SMTP server port")
    smtp_user: str = Field(default="", description="SMTP authenticatie gebruikersnaam")
    smtp_password: str = Field(default="", description="SMTP authenticatie wachtwoord")
    smtp_use_tls: bool = Field(default=True, description="STARTTLS gebruiken")
    alert_from_email: str = Field(
        default="soc-alerts@localhost",
        description="Afzender e-mailadres voor alerts",
    )
    alert_to_emails: str = Field(
        default="",
        description="Komma-gescheiden lijst van ontvangers voor alert emails",
    )

    # ── Webhook ──────────────────────────────────────────────────────────────
    webhook_url: str = Field(
        default="",
        description="Webhook endpoint URL (Slack, Teams, PagerDuty, etc.)",
    )
    webhook_secret: str = Field(
        default="",
        description="HMAC secret voor webhook payload signing",
    )
    webhook_timeout: float = Field(
        default=10.0,
        description="Timeout in seconden voor webhook requests",
    )

    # ── Platform account API ─────────────────────────────────────────────────
    platform_api_base_url: str = Field(
        default="",
        description="Base URL voor platform account management API",
    )
    platform_api_key: str = Field(
        default="",
        description="API key voor platform account lock/flag operaties",
    )
    platform_api_timeout: float = Field(
        default=15.0,
        description="Timeout in seconden voor platform API requests",
    )

    # ── Engine ───────────────────────────────────────────────────────────────
    response_dry_run: bool = Field(
        default=False,
        description="Dry-run modus: log acties maar voer ze niet echt uit",
    )

    model_config = {"env_prefix": "", "case_sensitive": False}


response_settings = ResponseSettings()
