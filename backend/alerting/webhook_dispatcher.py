import hashlib
import hmac
import json
import time
import httpx
from models.alert import FraudAlert
from models.account import SocialAccount
from config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)
settings = get_settings()


def _build_webhook_payload(alert: FraudAlert, account: SocialAccount) -> dict:
    return {
        "event": "fraud_alert",
        "alert_id": str(alert.id),
        "category": alert.category.value,
        "status": alert.status.value,
        "risk_score": alert.risk_score,
        "title": alert.title,
        "description": alert.description,
        "recommended_action": alert.recommended_action,
        "evidence": alert.evidence or {},
        "account": {
            "id": str(account.id),
            "platform": account.platform.value,
            "username": account.username,
            "platform_user_id": account.platform_user_id,
        },
        "timestamps": {
            "alert_created_at": alert.created_at.isoformat(),
            "dispatched_at": __import__("datetime").datetime.utcnow().isoformat(),
        },
    }


def _sign_payload(payload_bytes: bytes) -> str:
    """
    Generate HMAC-SHA256 signature for the webhook payload.
    Your receiving endpoint can verify this using the WEBHOOK_SECRET.
    Signature format: sha256=<hex_digest>
    """
    sig = hmac.new(
        settings.webhook_secret.encode(),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={sig}"


async def dispatch_webhook(alert: FraudAlert, account: SocialAccount) -> bool:
    """
    POST the fraud alert as a signed JSON webhook to the configured target URL.
    Returns True on success (HTTP 2xx), False otherwise.
    """
    if not settings.webhook_target_url:
        logger.warning("webhook_target_url_not_configured")
        return False

    payload = _build_webhook_payload(alert, account)
    payload_bytes = json.dumps(payload, default=str).encode("utf-8")
    signature = _sign_payload(payload_bytes)

    headers = {
        "Content-Type": "application/json",
        "X-SFD-Signature": signature,
        "X-SFD-Timestamp": str(int(time.time())),
        "X-SFD-Alert-ID": str(alert.id),
        "User-Agent": "SocialFraudDetector/1.0",
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                settings.webhook_target_url,
                content=payload_bytes,
                headers=headers,
            )
            if resp.is_success:
                logger.info("webhook_dispatched", alert_id=str(alert.id), status=resp.status_code)
                return True
            else:
                logger.warning("webhook_non_2xx", alert_id=str(alert.id), status=resp.status_code, body=resp.text[:200])
                return False
    except Exception as e:
        logger.error("webhook_dispatch_failed", alert_id=str(alert.id), error=str(e))
        return False
