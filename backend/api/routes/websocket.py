"""
WebSocket routes — drie real-time channels.

  /ws/alerts    — nieuwe FraudAlerts (risk_score >= threshold)
  /ws/events    — alle SecurityEvents (live feed)
  /ws/threatcon — THREATCON level changes (GREEN/YELLOW/RED/CRITICAL)

Authenticatie
─────────────
Browsers kunnen geen Authorization headers meesturen bij een WS handshake.
Daarom accepteren we een ?token=<base64(username:password)> query parameter,
identiek aan de Basic Auth credentials in de rest van de API.

Voorbeeld:
  ws://host/ws/alerts?token=YWRtaW46c2VjcmV0   (admin:secret in base64)

Verbindingsprotocol
───────────────────
Na connect ontvangt de client:
  {"type": "connected", "channel": "alerts", "ts": "..."}

Daarna ontvangt de client berichten bij elke relevante event:
  {"type": "alert",    "id": "...", "category": "...", ...}
  {"type": "event",    "id": "...", "event_type": "...", ...}
  {"type": "threatcon","level": "RED", "previous": "YELLOW", ...}

De server stuurt elke 30s een ping om de verbinding levend te houden:
  {"type": "ping", "ts": "..."}

De client hoeft niet te antwoorden op ping (nginx heeft keepalive).
"""
from __future__ import annotations

import asyncio
import base64
import logging
from datetime import datetime

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from api.ws_broadcaster import broadcaster
from config import get_settings

router = APIRouter(tags=["WebSocket"])
logger = logging.getLogger(__name__)

_PING_INTERVAL = 30  # seconds


# ── Auth ──────────────────────────────────────────────────────────────────────

def _verify_token(token: str | None) -> bool:
    """
    Decode and validate ?token=<base64(user:pass)> against dashboard credentials.
    Returns True on success, False on any failure.
    """
    if not token:
        return False
    try:
        decoded = base64.b64decode(token.encode()).decode()
        username, _, password = decoded.partition(":")
    except Exception:
        return False

    settings = get_settings()
    import secrets
    user_ok = secrets.compare_digest(username, settings.dashboard_username)
    pass_ok = secrets.compare_digest(password, settings.dashboard_password)
    return user_ok and pass_ok


async def _authenticate(ws: WebSocket, token: str | None) -> bool:
    """Accept the WS upgrade only after successful auth."""
    if _verify_token(token):
        return True
    # Reject before accepting — client gets HTTP 403 on the upgrade request
    await ws.close(code=status.WS_1008_POLICY_VIOLATION)
    logger.warning("ws_auth_rejected", client=ws.client)
    return False


# ── Ping loop ─────────────────────────────────────────────────────────────────

async def _ping_loop(ws: WebSocket) -> None:
    """Send periodic pings to keep the connection alive through proxies."""
    while True:
        await asyncio.sleep(_PING_INTERVAL)
        try:
            await ws.send_json({"type": "ping", "ts": datetime.utcnow().isoformat()})
        except Exception:
            break  # connection gone — let the main handler clean up


# ── Channel handlers ──────────────────────────────────────────────────────────

async def _run_channel(ws: WebSocket, channel: str) -> None:
    """
    Generic channel runner.
    Connects the client, starts the ping loop, and waits for disconnect.
    """
    await broadcaster.connect(ws, channel)
    await ws.send_json({
        "type": "connected",
        "channel": channel,
        "ts": datetime.utcnow().isoformat(),
        "threatcon": broadcaster._current_threatcon,
    })

    ping_task = asyncio.create_task(_ping_loop(ws))
    try:
        # Block until the client disconnects or sends a close frame
        while True:
            try:
                # We don't act on incoming messages, but we must drain them
                # to detect clean disconnects (WebSocketDisconnect)
                await asyncio.wait_for(ws.receive_text(), timeout=_PING_INTERVAL + 5)
            except asyncio.TimeoutError:
                # Normal — no messages received, connection still alive via ping
                continue
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("ws_connection_error", channel=channel, error=str(exc))
    finally:
        ping_task.cancel()
        await broadcaster.disconnect(ws, channel)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.websocket("/ws/alerts")
async def ws_alerts(
    ws: WebSocket,
    token: str | None = Query(default=None),
):
    """
    Real-time FraudAlert feed.

    Receives a message every time the analysis engine creates a new alert
    (risk_score >= threshold). Payload example:

        {
          "type": "alert",
          "id": "3f2a...",
          "category": "unauthorized_login",
          "status": "open",
          "risk_score": 78.5,
          "title": "[HIGH] Unauthorized Login on twitter",
          "platform": "twitter",
          "source_ip": "185.220.101.45",
          "source_country": "NL",
          "created_at": "2025-06-15T14:30:00"
        }
    """
    if not await _authenticate(ws, token):
        return
    await _run_channel(ws, "alerts")


@router.websocket("/ws/events")
async def ws_events(
    ws: WebSocket,
    token: str | None = Query(default=None),
):
    """
    Real-time SecurityEvent feed — all events, including low-risk ones.

    Payload example:

        {
          "type": "event",
          "id": "9c1b...",
          "event_type": "login",
          "severity": "medium",
          "risk_score": 42.0,
          "source_ip": "185.220.101.45",
          "source_country": "NL",
          "platform": "twitter",
          "occurred_at": "2025-06-15T14:30:00"
        }
    """
    if not await _authenticate(ws, token):
        return
    await _run_channel(ws, "events")


@router.websocket("/ws/threatcon")
async def ws_threatcon(
    ws: WebSocket,
    token: str | None = Query(default=None),
):
    """
    Real-time THREATCON level channel.

    Receives the current level immediately on connect (from_cache=True),
    then receives updates whenever the level changes.

    Payload example:

        {
          "type": "threatcon",
          "level": "RED",
          "previous": "YELLOW",
          "ts": "2025-06-15T14:30:00",
          "from_cache": false
        }

    Levels (in order of severity):
      GREEN    — no significant threats in the last 30 minutes
      YELLOW   — active threats, risk_score 30–59
      RED      — serious threats, risk_score 60–84
      CRITICAL — critical threats, risk_score >= 85
    """
    if not await _authenticate(ws, token):
        return
    await _run_channel(ws, "threatcon")


# ── Stats endpoint (REST, not WS) ─────────────────────────────────────────────

@router.get("/ws/stats")
async def ws_stats():
    """Current WebSocket connection counts and THREATCON level."""
    return broadcaster.stats()
