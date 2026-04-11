"""
QueueConsumer — Redis BLPOP consumer for the SOC ingest queue.

Runs as an async loop, pulling events from soc:events:ingest
and feeding them into the OrchestrationPipeline.

Lifecycle:
  consumer = QueueConsumer.from_settings(pipeline)
  await consumer.start()   # blocks forever, processing events
  await consumer.stop()    # graceful shutdown

Error handling:
  - JSON parse errors → logged, event skipped
  - Pipeline errors → logged, event skipped (no retry for now)
  - Redis connection lost → reconnect with exponential backoff
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import redis.asyncio as aioredis

from soc.config import get_soc_settings
from soc.database import AsyncSessionLocal
from soc.orchestrator.pipeline import OrchestrationPipeline

logger = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
_RECONNECT_BASE_DELAY = 1.0
_RECONNECT_MAX_DELAY = 30.0
_BLPOP_TIMEOUT = 5            # seconds; 0 = block forever


class QueueConsumer:
    """
    Async Redis queue consumer for SOC event ingestion.

    Uses BLPOP for efficient blocking reads. One consumer per SOC instance.
    """

    def __init__(
        self,
        redis_url: str,
        queue_name: str,
        pipeline: OrchestrationPipeline,
    ) -> None:
        self._redis_url = redis_url
        self._queue_name = queue_name
        self._pipeline = pipeline
        self._client: Optional[aioredis.Redis] = None
        self._running = False
        self._processed = 0
        self._errors = 0

    @classmethod
    def from_settings(cls, pipeline: OrchestrationPipeline) -> "QueueConsumer":
        settings = get_soc_settings()
        return cls(
            redis_url=settings.redis_url,
            queue_name=settings.soc_ingest_queue,
            pipeline=pipeline,
        )

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """
        Start the consumer loop. Blocks until stop() is called.
        Reconnects automatically on Redis failures.
        """
        self._running = True
        delay = _RECONNECT_BASE_DELAY

        logger.info("queue consumer starting: queue=%s", self._queue_name)

        while self._running:
            try:
                await self._connect()
                delay = _RECONNECT_BASE_DELAY  # reset on success
                await self._consume_loop()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("queue consumer error: %s — reconnecting in %.1fs", exc, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, _RECONNECT_MAX_DELAY)

        await self._disconnect()
        logger.info(
            "queue consumer stopped: processed=%d errors=%d",
            self._processed, self._errors,
        )

    async def stop(self) -> None:
        """Signal the consumer to stop gracefully."""
        self._running = False

    # ── Internals ────────────────────────────────────────────────────────────

    async def _connect(self) -> None:
        self._client = aioredis.from_url(
            self._redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=10,
        )
        await self._client.ping()
        logger.info("queue consumer connected to Redis")

    async def _disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _consume_loop(self) -> None:
        """Inner loop: BLPOP → process → repeat."""
        while self._running:
            # BLPOP returns (key, value) or None on timeout
            result = await self._client.blpop(
                self._queue_name,
                timeout=_BLPOP_TIMEOUT,
            )

            if result is None:
                continue  # timeout, check if still running

            _, raw_message = result

            try:
                payload = json.loads(raw_message)
            except (json.JSONDecodeError, TypeError) as exc:
                logger.warning("queue consumer: invalid JSON skipped: %s", exc)
                self._errors += 1
                continue

            await self._process_payload(payload)

    async def _process_payload(self, payload: dict) -> None:
        """Process a single payload through the pipeline."""
        async with AsyncSessionLocal() as session:
            try:
                broadcast = await self._pipeline.process(session, payload)
                self._processed += 1

                if broadcast:
                    logger.debug(
                        "queue consumer: processed event=%s score=%.1f",
                        broadcast.get("soc_event_id"),
                        broadcast.get("risk_score", 0),
                    )

                    # TODO: broadcast to WebSocket clients
                    # await ws_manager.broadcast(broadcast)

            except Exception as exc:
                logger.error(
                    "queue consumer: pipeline error: %s — payload keys: %s",
                    exc, list(payload.keys()),
                )
                self._errors += 1
                # Rollback is handled by AsyncSessionLocal context manager

    # ── Health ───────────────────────────────────────────────────────────────

    def health(self) -> dict:
        return {
            "running": self._running,
            "processed": self._processed,
            "errors": self._errors,
            "queue": self._queue_name,
            "connected": self._client is not None,
        }
