import json
import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from collectors.base import RawEvent
from models.event import SecurityEvent, EventType, EventSeverity
from models.alert import FraudAlert, AlertCategory, AlertStatus
from models.account import SocialAccount, Platform
from models.baseline import BehaviorBaseline
from analyzers.rules import (
    analyze_login_anomaly,
    analyze_token_misuse,
    analyze_account_takeover,
    analyze_suspicious_activity,
)
from utils.logger import get_logger

# ---------------------------------------------------------------------------
# SOC integration — optional Redis forwarding
# Imported lazily so that the SFD engine works even when SOC is not running.
# ---------------------------------------------------------------------------
try:
    import redis as _redis_lib
    from config import get_settings as _get_settings

    _sfd_settings = _get_settings()
    _soc_redis: "_redis_lib.Redis | None" = _redis_lib.from_url(
        _sfd_settings.redis_url, decode_responses=True
    )
    _SOC_QUEUE = "soc:events:ingest"
except Exception:
    _soc_redis = None
    _SOC_QUEUE = "soc:events:ingest"

# ---------------------------------------------------------------------------
# WebSocket broadcaster — optional; works even if the WS module is absent
# ---------------------------------------------------------------------------
try:
    from api.ws_broadcaster import broadcaster as _ws_broadcaster
except Exception:
    _ws_broadcaster = None

logger = get_logger(__name__)

# Risk score threshold above which an alert is created and dispatched
ALERT_THRESHOLD = 30.0

# Map event types to fraud categories
EVENT_TO_CATEGORY = {
    EventType.LOGIN: AlertCategory.UNAUTHORIZED_LOGIN,
    EventType.TOKEN_REFRESH: AlertCategory.API_TOKEN_MISUSE,
    EventType.NEW_OAUTH_APP: AlertCategory.API_TOKEN_MISUSE,
    EventType.APP_REVOKED: AlertCategory.API_TOKEN_MISUSE,
    EventType.PASSWORD_CHANGE: AlertCategory.ACCOUNT_TAKEOVER,
    EventType.EMAIL_CHANGE: AlertCategory.ACCOUNT_TAKEOVER,
    EventType.PHONE_CHANGE: AlertCategory.ACCOUNT_TAKEOVER,
    EventType.PROFILE_CHANGE: AlertCategory.ACCOUNT_TAKEOVER,
    EventType.POST_CREATED: AlertCategory.SUSPICIOUS_ACTIVITY,
    EventType.MESSAGE_SENT: AlertCategory.SUSPICIOUS_ACTIVITY,
    EventType.API_CALL_SPIKE: AlertCategory.SUSPICIOUS_ACTIVITY,
    EventType.FOLLOWER_SPIKE: AlertCategory.SUSPICIOUS_ACTIVITY,
}

RECOMMENDED_ACTIONS = {
    AlertCategory.UNAUTHORIZED_LOGIN: (
        "1. Immediately review active sessions on the platform and revoke any unrecognized sessions.\n"
        "2. Change your password from a trusted device.\n"
        "3. Enable two-factor authentication if not already active."
    ),
    AlertCategory.ACCOUNT_TAKEOVER: (
        "1. Check your recovery email and phone number for unauthorized changes.\n"
        "2. Revoke all active OAuth tokens and re-authorize only trusted apps.\n"
        "3. Contact the platform's support team to report a potential compromise."
    ),
    AlertCategory.API_TOKEN_MISUSE: (
        "1. Review all connected apps and revoke any you do not recognize.\n"
        "2. Rotate your API access tokens immediately.\n"
        "3. Audit recent API activity logs for unauthorized calls."
    ),
    AlertCategory.SUSPICIOUS_ACTIVITY: (
        "1. Review recent posts and messages for content you did not create.\n"
        "2. Revoke access for any third-party automation tools.\n"
        "3. Check your account for signs of bot integration or scheduling tool misuse."
    ),
}


class FraudAnalysisEngine:
    """
    Central analysis engine. Accepts a raw event, runs all applicable
    detection rules, persists the security event, and creates a FraudAlert
    if the risk score exceeds the alert threshold.
    """

    async def process_event(self, db: AsyncSession, raw_event: RawEvent) -> tuple[SecurityEvent, FraudAlert | None]:
        # Resolve account from DB
        account = await self._resolve_account(db, raw_event)
        baseline = await self._get_baseline(db, account.id)

        # Run all detection rules
        login_result = analyze_login_anomaly(raw_event, baseline)
        token_result = analyze_token_misuse(raw_event, baseline)
        takeover_result = analyze_account_takeover(raw_event, baseline)
        activity_result = analyze_suspicious_activity(raw_event, baseline)

        # Pick the highest-risk result
        all_results = [login_result, token_result, takeover_result, activity_result]
        triggered = [r for r in all_results if r.triggered]

        if triggered:
            top = max(triggered, key=lambda r: r.risk_score)
        else:
            top = login_result  # default (non-triggered, score=0)

        # Determine severity
        severity = top.severity if triggered else EventSeverity.INFO

        # Persist security event
        event = SecurityEvent(
            id=uuid.uuid4(),
            account_id=account.id,
            event_type=raw_event.event_type,
            severity=severity,
            risk_score=top.risk_score,
            source_ip=raw_event.source_ip,
            source_country=raw_event.source_country,
            source_device=raw_event.source_device,
            client_app=raw_event.client_app,
            description=raw_event.description,
            raw_payload=raw_event.raw_payload,
            occurred_at=raw_event.occurred_at,
            ingested_at=datetime.utcnow(),
        )
        db.add(event)
        await db.flush()

        # Update baseline with this event
        await self._update_baseline(db, account.id, raw_event, baseline)

        # Create alert if above threshold
        alert = None
        if top.risk_score >= ALERT_THRESHOLD:
            category = EVENT_TO_CATEGORY.get(raw_event.event_type, AlertCategory.SUSPICIOUS_ACTIVITY)
            alert = FraudAlert(
                id=uuid.uuid4(),
                account_id=account.id,
                triggering_event_id=event.id,
                category=category,
                status=AlertStatus.OPEN,
                risk_score=top.risk_score,
                title=f"[{severity.value.upper()}] {category.value.replace('_', ' ').title()} on {raw_event.platform}",
                description=top.reason,
                recommended_action=RECOMMENDED_ACTIONS.get(category, ""),
                evidence=top.evidence,
                email_sent=False,
                webhook_sent=False,
                created_at=datetime.utcnow(),
            )
            db.add(alert)
            await db.flush()
            logger.info("fraud_alert_created", alert_id=str(alert.id), category=category, score=top.risk_score)

            # ── SOC forwarding ──────────────────────────────────────────────
            # Push a lightweight payload to the SOC ingest queue so the
            # Security Orchestrator can enrich and correlate this alert.
            # Fire-and-forget: any failure is logged but never blocks SFD.
            self._forward_to_soc(event=event, alert=alert, raw_event=raw_event)

        await db.commit()

        # ── WebSocket broadcast ─────────────────────────────────────────────
        # Fire-and-forget: failures never affect the SFD core flow.
        if _ws_broadcaster is not None:
            await self._broadcast_ws(event=event, alert=alert, raw_event=raw_event)

        return event, alert

    async def _resolve_account(self, db: AsyncSession, raw_event: RawEvent) -> SocialAccount:
        platform_enum = Platform(raw_event.platform)
        result = await db.execute(
            select(SocialAccount).where(
                SocialAccount.platform == platform_enum,
                SocialAccount.platform_user_id == raw_event.platform_user_id,
            )
        )
        account = result.scalar_one_or_none()
        if account is None:
            account = SocialAccount(
                id=uuid.uuid4(),
                platform=platform_enum,
                platform_user_id=raw_event.platform_user_id,
                username=raw_event.platform_user_id,
                registered_at=datetime.utcnow(),
            )
            db.add(account)
            await db.flush()
        return account

    async def _get_baseline(self, db: AsyncSession, account_id: uuid.UUID) -> BehaviorBaseline | None:
        result = await db.execute(
            select(BehaviorBaseline).where(BehaviorBaseline.account_id == account_id)
        )
        return result.scalar_one_or_none()

    async def _update_baseline(
        self, db: AsyncSession, account_id: uuid.UUID, raw_event: RawEvent, baseline: BehaviorBaseline | None
    ):
        if baseline is None:
            baseline = BehaviorBaseline(
                id=uuid.uuid4(),
                account_id=account_id,
                known_ips=[],
                known_countries=[],
                known_devices=[],
                known_apps=[],
                typical_active_hours=[],
                sample_count=0,
                baseline_established=False,
            )
            db.add(baseline)

        # Update known IPs
        known_ips = list(baseline.known_ips or [])
        if raw_event.source_ip and raw_event.source_ip not in known_ips:
            known_ips.append(raw_event.source_ip)
        baseline.known_ips = known_ips[-50:]  # keep last 50

        # Update known countries
        known_countries = list(baseline.known_countries or [])
        if raw_event.source_country and raw_event.source_country not in known_countries:
            known_countries.append(raw_event.source_country)
        baseline.known_countries = known_countries[-20:]

        # Update known devices
        known_devices = list(baseline.known_devices or [])
        if raw_event.source_device and raw_event.source_device not in known_devices:
            known_devices.append(raw_event.source_device)
        baseline.known_devices = known_devices[-20:]

        # Update known apps
        known_apps = list(baseline.known_apps or [])
        if raw_event.client_app and raw_event.client_app not in known_apps:
            known_apps.append(raw_event.client_app)
        baseline.known_apps = known_apps[-30:]

        # Update typical active hours (rolling)
        typical_hours = list(baseline.typical_active_hours or [])
        hour = raw_event.occurred_at.hour
        if hour not in typical_hours:
            typical_hours.append(hour)
        baseline.typical_active_hours = typical_hours

        baseline.sample_count = (baseline.sample_count or 0) + 1
        if baseline.sample_count >= 20:
            baseline.baseline_established = True

        baseline.updated_at = datetime.utcnow()
        await db.flush()

    # ── WebSocket broadcast ───────────────────────────────────────────────────

    async def _broadcast_ws(
        self,
        event: SecurityEvent,
        alert: "FraudAlert | None",
        raw_event: RawEvent,
    ) -> None:
        """
        Broadcast event (and optional alert) to connected WebSocket clients.
        Catches all exceptions — never raises.
        """
        try:
            # Always broadcast to /ws/events
            event_payload = {
                "id": str(event.id),
                "event_type": event.event_type.value,
                "severity": event.severity.value,
                "risk_score": event.risk_score,
                "source_ip": event.source_ip,
                "source_country": event.source_country,
                "platform": raw_event.platform,
                "occurred_at": event.occurred_at.isoformat(),
                "ingested_at": event.ingested_at.isoformat(),
            }
            await _ws_broadcaster.broadcast_event(event_payload)

            # Broadcast to /ws/alerts only when an alert was created
            if alert is not None:
                alert_payload = {
                    "id": str(alert.id),
                    "triggering_event_id": str(event.id),
                    "category": alert.category.value,
                    "status": alert.status.value,
                    "risk_score": alert.risk_score,
                    "title": alert.title,
                    "description": alert.description,
                    "platform": raw_event.platform,
                    "source_ip": event.source_ip,
                    "source_country": event.source_country,
                    "created_at": alert.created_at.isoformat(),
                }
                await _ws_broadcaster.broadcast_alert(alert_payload)

        except Exception as exc:
            logger.warning("ws_broadcast_failed", error=str(exc))

    # ── SOC integration ───────────────────────────────────────────────────────

    def _forward_to_soc(
        self, event: SecurityEvent, alert: FraudAlert, raw_event: RawEvent
    ) -> None:
        """
        Push a normalized event payload to the SOC Redis ingest queue.

        Non-blocking and failure-safe: if Redis is unavailable or the SOC
        service is down, this logs a warning and returns without raising.
        """
        if _soc_redis is None:
            return

        payload = {
            "source": "social_fraud_detector",
            "external_id": str(alert.id),
            "event_type": _map_alert_category_to_soc_type(alert.category),
            "severity": event.severity.value,
            "raw_risk_score": float(event.risk_score),
            "source_ip": event.source_ip,
            "source_country": event.source_country,
            "description": alert.description,
            "occurred_at": event.occurred_at.isoformat(),
            "platform": raw_event.platform,
            "raw_payload": {
                "alert_title": alert.title,
                "alert_category": alert.category.value,
                "evidence": alert.evidence,
            },
        }

        try:
            _soc_redis.rpush(_SOC_QUEUE, json.dumps(payload))
        except Exception as exc:
            logger.warning(
                "soc_forward_failed",
                alert_id=str(alert.id),
                error=str(exc),
            )


def _map_alert_category_to_soc_type(category: AlertCategory) -> str:
    """Map SFD AlertCategory values to SOC SocEventType string literals."""
    mapping = {
        AlertCategory.UNAUTHORIZED_LOGIN: "unauthorized_login",
        AlertCategory.ACCOUNT_TAKEOVER: "account_takeover",
        AlertCategory.API_TOKEN_MISUSE: "api_abuse",
        AlertCategory.SUSPICIOUS_ACTIVITY: "suspicious_activity",
    }
    return mapping.get(category, "anomaly")
