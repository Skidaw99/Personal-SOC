"""
WebSocket Broadcaster — singleton module.

Verantwoordelijkheden:
  1. ConnectionManager  — bijhoudt alle actieve WS verbindingen per channel.
  2. THREATCON engine   — berekent het huidige dreigingsniveau op basis van
                          een rolling window van risk scores (30 minuten).
  3. broadcast_*()      — publieke functies die door engine.py worden aangeroepen
                          na het verwerken van een event/alert.

Import-veiligheid
─────────────────
Dit module importeert NIETS uit de rest van de backend (geen models, geen DB).
Zo zijn er nooit circular imports wanneer engine.py dit module importeert.

THREATCON niveaus
─────────────────
  GREEN    — geen recente alerts, of max risk_score < 30
  YELLOW   — max risk_score in rolling window 30–59
  RED      — max risk_score 60–84
  CRITICAL — max risk_score >= 85

Het niveau wordt herberekend bij elke broadcast. Als het verandert, gaat
er automatisch een bericht naar alle /ws/threatcon clients.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from datetime import datetime, timedelta
from typing import NamedTuple

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# ── THREATCON ─────────────────────────────────────────────────────────────────

_THREATCON_WINDOW = timedelta(minutes=30)

LEVELS = ("GREEN", "YELLOW", "RED", "CRITICAL")


class _ScoreEntry(NamedTuple):
    ts: datetime
    risk_score: float


def _compute_threatcon(window: deque[_ScoreEntry]) -> str:
    cutoff = datetime.utcnow() - _THREATCON_WINDOW
    recent = [e.risk_score for e in window if e.ts >= cutoff]
    if not recent:
        return "GREEN"
    peak = max(recent)
    if peak >= 85:
        return "CRITICAL"
    if peak >= 60:
        return "RED"
    if peak >= 30:
        return "YELLOW"
    return "GREEN"


# ── ConnectionManager ─────────────────────────────────────────────────────────

class ConnectionManager:
    """
    Thread-safe (single asyncio event loop) WebSocket connection registry.

    Channels: "alerts" | "events" | "threatcon"
    """

    def __init__(self) -> None:
        # channel → set of active WebSocket connections
        self._connections: dict[str, set[WebSocket]] = {
            "alerts": set(),
            "events": set(),
            "threatcon": set(),
        }
        # Rolling window for THREATCON computation
        self._score_window: deque[_ScoreEntry] = deque(maxlen=500)
        self._current_threatcon: str = "GREEN"
        # Lock ensures only one coroutine mutates connection sets at a time
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, channel: str) -> None:
        await ws.accept()
        async with self._lock:
            self._connections[channel].add(ws)
        count = len(self._connections[channel])
        logger.info("ws_client_connected", channel=channel, total=count)

        # Send current THREATCON immediately on connect so the UI is in sync
        if channel == "threatcon":
            await self._send_safe(ws, {
                "type": "threatcon",
                "level": self._current_threatcon,
                "ts": datetime.utcnow().isoformat(),
                "from_cache": True,
            })

    async def disconnect(self, ws: WebSocket, channel: str) -> None:
        async with self._lock:
            self._connections[channel].discard(ws)
        logger.info(
            "ws_client_disconnected",
            channel=channel,
            remaining=len(self._connections[channel]),
        )

    async def broadcast(self, channel: str, payload: dict) -> None:
        """
        Send payload to all connected clients on the given channel.
        Dead connections are silently removed.
        """
        async with self._lock:
            targets = set(self._connections[channel])

        if not targets:
            return

        message = json.dumps(payload, default=str)
        dead: set[WebSocket] = set()

        results = await asyncio.gather(
            *[self._send_raw(ws, message) for ws in targets],
            return_exceptions=True,
        )
        for ws, result in zip(targets, results):
            if isinstance(result, Exception):
                dead.add(ws)

        if dead:
            async with self._lock:
                self._connections[channel] -= dead
            logger.debug("ws_dead_connections_removed", channel=channel, count=len(dead))

    async def broadcast_event(self, event_payload: dict) -> None:
        """Called after every SecurityEvent is persisted (regardless of score)."""
        payload = {"type": "event", **event_payload}
        await self.broadcast("events", payload)

    async def broadcast_alert(self, alert_payload: dict) -> None:
        """Called when a FraudAlert is created (risk_score >= threshold)."""
        payload = {"type": "alert", **alert_payload}
        await self.broadcast("alerts", payload)

        # Update THREATCON rolling window
        risk_score = alert_payload.get("risk_score", 0.0)
        self._score_window.append(_ScoreEntry(ts=datetime.utcnow(), risk_score=risk_score))
        await self._maybe_broadcast_threatcon()

    async def _maybe_broadcast_threatcon(self) -> None:
        """Recompute THREATCON; broadcast if the level changed."""
        new_level = _compute_threatcon(self._score_window)
        if new_level == self._current_threatcon:
            return

        old_level = self._current_threatcon
        self._current_threatcon = new_level
        logger.warning(
            "threatcon_level_change",
            old=old_level,
            new=new_level,
        )
        await self.broadcast("threatcon", {
            "type": "threatcon",
            "level": new_level,
            "previous": old_level,
            "ts": datetime.utcnow().isoformat(),
            "from_cache": False,
        })

    def stats(self) -> dict:
        return {
            "connections": {ch: len(sockets) for ch, sockets in self._connections.items()},
            "threatcon": self._current_threatcon,
            "score_window_size": len(self._score_window),
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    async def _send_raw(ws: WebSocket, message: str) -> None:
        await ws.send_text(message)

    @staticmethod
    async def _send_safe(ws: WebSocket, payload: dict) -> None:
        try:
            await ws.send_text(json.dumps(payload, default=str))
        except Exception:
            pass


# ── Module-level singleton ─────────────────────────────────────────────────────

broadcaster = ConnectionManager()
