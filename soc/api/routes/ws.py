"""
WebSocket route handlers — registers /ws/soc, /ws/alerts, /ws/threatcon.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from soc.api.websocket import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter()


@router.websocket("/ws/soc")
async def ws_soc_events(ws: WebSocket) -> None:
    """All enriched SOC events — live feed for the dashboard."""
    await ws_manager.connect_events(ws)
    try:
        while True:
            # Keep connection alive; client can send pings
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.events.disconnect(ws)


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket) -> None:
    """High-risk alerts only — triggers dashboard notifications."""
    await ws_manager.connect_alerts(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.alerts.disconnect(ws)


@router.websocket("/ws/threatcon")
async def ws_threatcon(ws: WebSocket) -> None:
    """Threat level changes — CALM/ELEVATED/ACTIVE/CRITICAL."""
    await ws_manager.connect_threatcon(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.threatcon.disconnect(ws)
