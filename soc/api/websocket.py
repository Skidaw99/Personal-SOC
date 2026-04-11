"""
WebSocket Manager — realtime event broadcasting to the dashboard.

Channels:
  /ws/soc          — all SOC events (enriched, scored)
  /ws/alerts       — new FraudAlerts only (risk >= 50)
  /ws/threatcon    — threat level changes (CALM/ELEVATED/ACTIVE/CRITICAL)

Threat level is computed from the aggregate state of open alerts:
  CALM:      no open alerts
  ELEVATED:  1-2 open alerts, all risk < 70
  ACTIVE:    any alert with risk >= 70
  CRITICAL:  any alert with risk >= 90
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class ThreatLevel(str, Enum):
    CALM = "CALM"
    ELEVATED = "ELEVATED"
    ACTIVE = "ACTIVE"
    CRITICAL = "CRITICAL"


class ConnectionPool:
    """Manages WebSocket connections for a single channel."""

    def __init__(self, channel: str) -> None:
        self.channel = channel
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        logger.info("ws connect: channel=%s clients=%d", self.channel, len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)
        logger.info("ws disconnect: channel=%s clients=%d", self.channel, len(self._connections))

    async def broadcast(self, data: dict[str, Any]) -> None:
        if not self._connections:
            return
        message = json.dumps(data, default=str)
        stale: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(message)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)

    @property
    def client_count(self) -> int:
        return len(self._connections)


class SOCWebSocketManager:
    """
    Central WebSocket manager for all SOC channels.

    Usage:
        manager = SOCWebSocketManager()
        await manager.broadcast_event(event_payload)   # → /ws/soc
        await manager.broadcast_alert(alert_payload)   # → /ws/alerts
        await manager.update_threat_level(risk_score)   # → /ws/threatcon
    """

    def __init__(self) -> None:
        self.events = ConnectionPool("soc")
        self.alerts = ConnectionPool("alerts")
        self.threatcon = ConnectionPool("threatcon")
        self._current_level = ThreatLevel.CALM
        self._open_alerts: list[dict[str, Any]] = []
        self._max_alert_history = 100

    # ── Connection handlers ──────────────────────────────────────────────────

    async def connect_events(self, ws: WebSocket) -> None:
        await self.events.connect(ws)

    async def connect_alerts(self, ws: WebSocket) -> None:
        await self.alerts.connect(ws)
        # Send current threat level on connect
        await ws.send_text(json.dumps({
            "type": "threatcon",
            "level": self._current_level.value,
            "open_alerts": len(self._open_alerts),
        }))

    async def connect_threatcon(self, ws: WebSocket) -> None:
        await self.threatcon.connect(ws)
        await ws.send_text(json.dumps({
            "type": "threatcon",
            "level": self._current_level.value,
            "open_alerts": len(self._open_alerts),
            "timestamp": datetime.utcnow().isoformat(),
        }))

    # ── Broadcast methods ────────────────────────────────────────────────────

    async def broadcast_event(self, payload: dict[str, Any]) -> None:
        """Broadcast enriched event to /ws/soc."""
        payload["type"] = "event"
        payload["timestamp"] = payload.get("timestamp", datetime.utcnow().isoformat())
        await self.events.broadcast(payload)

    async def broadcast_alert(self, payload: dict[str, Any]) -> None:
        """Broadcast alert to /ws/alerts and update threat level."""
        payload["type"] = "alert"
        await self.alerts.broadcast(payload)

        # Track for threat level computation
        self._open_alerts.append(payload)
        if len(self._open_alerts) > self._max_alert_history:
            self._open_alerts = self._open_alerts[-self._max_alert_history:]

        # Update threat level
        risk = payload.get("risk_score", 0)
        await self.update_threat_level(risk)

    async def broadcast_actor(self, payload: dict[str, Any]) -> None:
        """Broadcast threat actor update to /ws/soc."""
        payload["type"] = "actor"
        await self.events.broadcast(payload)

    async def broadcast_copilot(self, payload: dict[str, Any]) -> None:
        """Broadcast AI copilot message to /ws/soc."""
        payload["type"] = "copilot"
        await self.events.broadcast(payload)

    # ── Threat Level Engine ──────────────────────────────────────────────────

    async def update_threat_level(self, latest_risk: float) -> None:
        """Recompute and broadcast threat level."""
        new_level = self._compute_level(latest_risk)

        if new_level != self._current_level:
            old_level = self._current_level
            self._current_level = new_level

            change_payload = {
                "type": "threatcon",
                "level": new_level.value,
                "previous": old_level.value,
                "open_alerts": len(self._open_alerts),
                "trigger_risk": latest_risk,
                "timestamp": datetime.utcnow().isoformat(),
            }

            await self.threatcon.broadcast(change_payload)
            # Also push to main event channel
            await self.events.broadcast(change_payload)

            logger.warning(
                "threat level change: %s → %s (trigger_risk=%.1f alerts=%d)",
                old_level.value, new_level.value,
                latest_risk, len(self._open_alerts),
            )

    def _compute_level(self, latest_risk: float) -> ThreatLevel:
        """Compute threat level from current alert state."""
        if latest_risk >= 90:
            return ThreatLevel.CRITICAL

        if latest_risk >= 70:
            return ThreatLevel.ACTIVE

        open_count = len(self._open_alerts)
        if open_count == 0:
            return ThreatLevel.CALM

        max_risk = max(
            (a.get("risk_score", 0) for a in self._open_alerts),
            default=0,
        )

        if max_risk >= 90:
            return ThreatLevel.CRITICAL
        if max_risk >= 70:
            return ThreatLevel.ACTIVE
        if open_count >= 1:
            return ThreatLevel.ELEVATED

        return ThreatLevel.CALM

    def clear_alerts(self) -> None:
        """Reset alert state (e.g., analyst acknowledged all)."""
        self._open_alerts.clear()
        self._current_level = ThreatLevel.CALM

    # ── Health ───────────────────────────────────────────────────────────────

    def health(self) -> dict:
        return {
            "threat_level": self._current_level.value,
            "open_alerts": len(self._open_alerts),
            "connections": {
                "events": self.events.client_count,
                "alerts": self.alerts.client_count,
                "threatcon": self.threatcon.client_count,
            },
        }


# ── Singleton ────────────────────────────────────────────────────────────────
ws_manager = SOCWebSocketManager()
