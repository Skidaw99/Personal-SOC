"""
Incoming webhook receiver.
Social platforms (Meta, Twitter) POST events here in real-time.
Each platform has its own verification mechanism built in.
"""
import hashlib
import hmac
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Response, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from analyzers.engine import FraudAnalysisEngine
from alerting import send_fraud_alert_email, dispatch_webhook
from collectors.base import RawEvent
from models.event import EventType
from models.alert import FraudAlert
from models.account import SocialAccount
from sqlalchemy import select
from config import get_settings
from utils.logger import get_logger

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])
logger = get_logger(__name__)
settings = get_settings()
engine = FraudAnalysisEngine()


# ─────────────────────────────────────────────
# META WEBHOOK
# ─────────────────────────────────────────────

@router.get("/meta")
async def meta_webhook_verify(
    hub_mode: str = None,
    hub_challenge: str = None,
    hub_verify_token: str = None,
):
    """Meta webhook verification challenge (GET)."""
    if hub_mode == "subscribe" and hub_verify_token == settings.meta_verify_token:
        return Response(content=hub_challenge, media_type="text/plain")
    raise HTTPException(status_code=403, detail="Verification token mismatch")


@router.post("/meta")
async def meta_webhook_receive(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive Meta security events (POST)."""
    body = await request.body()

    # Verify X-Hub-Signature-256
    sig_header = request.headers.get("X-Hub-Signature-256", "")
    expected = "sha256=" + hmac.new(
        settings.meta_app_secret.encode(), body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig_header, expected):
        raise HTTPException(status_code=401, detail="Invalid signature")

    payload = json.loads(body)
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            raw = RawEvent(
                platform="facebook",
                platform_user_id=str(entry.get("id", "unknown")),
                event_type=_map_meta_field(change.get("field", "")),
                occurred_at=datetime.now(timezone.utc),
                description=f"Meta webhook event: {change.get('field')}",
                raw_payload=change,
            )
            security_event, alert = await engine.process_event(db, raw)
            if alert:
                await _dispatch_alert(db, alert)

    return {"status": "ok"}


def _map_meta_field(field: str) -> EventType:
    mapping = {
        "security": EventType.LOGIN,
        "permissions": EventType.NEW_OAUTH_APP,
        "name": EventType.PROFILE_CHANGE,
        "email": EventType.EMAIL_CHANGE,
        "password": EventType.PASSWORD_CHANGE,
    }
    return mapping.get(field, EventType.UNKNOWN)


# ─────────────────────────────────────────────
# TWITTER WEBHOOK
# ─────────────────────────────────────────────

@router.get("/twitter")
async def twitter_crc_challenge(crc_token: str):
    """Twitter CRC challenge for Account Activity API."""
    import base64
    digest = hmac.new(
        settings.twitter_api_secret.encode(),
        crc_token.encode(),
        hashlib.sha256,
    ).digest()
    response_token = "sha256=" + base64.b64encode(digest).decode()
    return {"response_token": response_token}


@router.post("/twitter")
async def twitter_webhook_receive(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive Twitter Account Activity events."""
    body = await request.body()
    payload = json.loads(body)

    for_user_id = payload.get("for_user_id", "unknown")

    # Login events
    for login in payload.get("login_event", []):
        raw = RawEvent(
            platform="twitter",
            platform_user_id=for_user_id,
            event_type=EventType.LOGIN,
            occurred_at=datetime.now(timezone.utc),
            description="Twitter login event via Account Activity API",
            raw_payload=login,
        )
        _, alert = await engine.process_event(db, raw)
        if alert:
            await _dispatch_alert(db, alert)

    # Direct message events (volume tracking)
    dm_events = payload.get("direct_message_events", [])
    if dm_events:
        raw = RawEvent(
            platform="twitter",
            platform_user_id=for_user_id,
            event_type=EventType.MESSAGE_SENT,
            occurred_at=datetime.now(timezone.utc),
            description=f"Twitter DM activity: {len(dm_events)} messages",
            raw_payload={"count": len(dm_events)},
        )
        _, alert = await engine.process_event(db, raw)
        if alert:
            await _dispatch_alert(db, alert)

    return {"status": "ok"}


# ─────────────────────────────────────────────
# YOUTUBE PUSH NOTIFICATION
# ─────────────────────────────────────────────

@router.get("/youtube")
async def youtube_pubsub_verify(
    hub_challenge: str = None,
    hub_mode: str = None,
):
    """YouTube PubSubHubbub verification."""
    if hub_mode == "subscribe" and hub_challenge:
        return Response(content=hub_challenge, media_type="text/plain")
    raise HTTPException(status_code=400, detail="Invalid hub request")


@router.post("/youtube")
async def youtube_push_receive(request: Request, db: AsyncSession = Depends(get_db)):
    """Receive YouTube push notifications (Atom feed)."""
    body = await request.body()
    # Parse minimal info from Atom XML
    raw = RawEvent(
        platform="youtube",
        platform_user_id=settings.youtube_channel_id or "unknown",
        event_type=EventType.POST_CREATED,
        occurred_at=datetime.now(timezone.utc),
        description="YouTube push notification: new video activity",
        raw_payload={"raw_xml_length": len(body)},
    )
    _, alert = await engine.process_event(db, raw)
    if alert:
        await _dispatch_alert(db, alert)
    return Response(status_code=204)


# ─────────────────────────────────────────────
# SHARED DISPATCH
# ─────────────────────────────────────────────

async def _dispatch_alert(db: AsyncSession, alert: FraudAlert):
    result = await db.execute(
        select(SocialAccount).where(SocialAccount.id == alert.account_id)
    )
    account = result.scalar_one_or_none()
    if not account:
        return

    email_ok = await send_fraud_alert_email(alert, account)
    webhook_ok = await dispatch_webhook(alert, account)

    alert.email_sent = email_ok
    alert.webhook_sent = webhook_ok
    await db.commit()
