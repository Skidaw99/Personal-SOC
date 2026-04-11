"""
SOC Service — FastAPI application.

Runs as a separate service alongside the SFD backend.
Provides: WebSocket channels, AI copilot API, intel lookups,
and the orchestration pipeline consumer.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from soc.config import get_soc_settings
from soc.database import init_db
from soc.api.routes.ws import router as ws_router
from soc.api.routes.ai import router as ai_router
from soc.api.routes.intel import router as intel_router
from soc.api.routes.actors import router as actors_router
from soc.api.websocket import ws_manager
from soc.intel.engine import IntelEngine
from soc.orchestrator.pipeline import OrchestrationPipeline
from soc.orchestrator.consumer import QueueConsumer

logger = logging.getLogger(__name__)

# ── Globals ──────────────────────────────────────────────────────────────────
_intel_engine: IntelEngine | None = None
_consumer: QueueConsumer | None = None
_consumer_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle for the SOC service."""
    global _intel_engine, _consumer, _consumer_task

    logger.info("SOC service starting...")

    # ── Database ──
    await init_db()
    logger.info("database initialized")

    # ── Intel Engine ──
    _intel_engine = IntelEngine.from_settings()
    await _intel_engine.startup()
    logger.info("intel engine started")

    # ── Pipeline + Consumer ──
    pipeline = OrchestrationPipeline(intel_engine=_intel_engine)

    # Wire pipeline output to WebSocket manager
    _original_process = pipeline.process

    async def _process_and_broadcast(session, payload):
        result = await _original_process(session, payload)
        if result:
            risk = result.get("risk_score", 0)
            await ws_manager.broadcast_event(result)
            if risk >= 50:
                await ws_manager.broadcast_alert(result)
            if result.get("correlation", {}).get("actor_display_name"):
                await ws_manager.broadcast_actor(result.get("correlation", {}))
        return result

    pipeline.process = _process_and_broadcast

    _consumer = QueueConsumer.from_settings(pipeline)
    _consumer_task = asyncio.create_task(_consumer.start())
    logger.info("queue consumer started")

    yield

    # ── Shutdown ──
    logger.info("SOC service shutting down...")
    if _consumer:
        await _consumer.stop()
    if _consumer_task:
        _consumer_task.cancel()
        try:
            await _consumer_task
        except asyncio.CancelledError:
            pass
    if _intel_engine:
        await _intel_engine.shutdown()

    logger.info("SOC service stopped")


# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PersonalSOC — Security Operations Center",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ───────────────────────────────────────────────────────────────────
app.include_router(ws_router)
app.include_router(ai_router)
app.include_router(intel_router)
app.include_router(actors_router)


@app.get("/health")
async def health():
    """SOC service health check."""
    intel_health = await _intel_engine.health() if _intel_engine else {}
    consumer_health = _consumer.health() if _consumer else {}
    ws_health = ws_manager.health()

    return {
        "status": "ok",
        "service": "soc",
        "intel": intel_health,
        "consumer": consumer_health,
        "websocket": ws_health,
    }


@app.get("/api/soc/threatcon")
async def get_threatcon():
    """Current threat level."""
    return {
        "level": ws_manager._current_level.value,
        "open_alerts": len(ws_manager._open_alerts),
    }
