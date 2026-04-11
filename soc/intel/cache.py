"""
IntelRedisCache — Redis L1 cache for IntelResult records.

Key:    soc:intel:{ip}
TTL:    configurable, default 3600s (1 hour)
Miss:   returns None, engine proceeds with live lookups
Error:  silently bypassed — cache is best-effort, never blocking
"""
from __future__ import annotations

import logging
from typing import Optional

import redis.asyncio as aioredis

from soc.intel.schemas import IntelResult

logger = logging.getLogger(__name__)

_KEY_PREFIX = "soc:intel:"


class IntelRedisCache:
    """Async Redis cache for IntelResult records."""

    def __init__(self, redis_url: str, default_ttl: int = 3600) -> None:
        self._redis_url = redis_url
        self._default_ttl = default_ttl
        self._client: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        try:
            self._client = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            await self._client.ping()
            logger.info("intel cache connected")
        except Exception as exc:
            logger.warning("intel cache unavailable: %s", exc)
            self._client = None

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get(self, ip: str) -> Optional[IntelResult]:
        if not self._client:
            return None
        try:
            raw = await self._client.get(_KEY_PREFIX + ip)
            if raw is None:
                return None
            intel = IntelResult.from_json(raw)
            intel.from_cache = True
            return intel
        except Exception as exc:
            logger.warning("intel cache get error ip=%s: %s", ip, exc)
            return None

    async def set(self, intel: IntelResult, ttl: Optional[int] = None) -> None:
        if not self._client:
            return
        effective_ttl = ttl if ttl is not None else self._default_ttl
        try:
            await self._client.set(_KEY_PREFIX + intel.ip, intel.to_json(), ex=effective_ttl)
        except Exception as exc:
            logger.warning("intel cache set error ip=%s: %s", intel.ip, exc)

    async def invalidate(self, ip: str) -> None:
        if not self._client:
            return
        try:
            await self._client.delete(_KEY_PREFIX + ip)
        except Exception as exc:
            logger.warning("intel cache invalidate error ip=%s: %s", ip, exc)

    async def ping(self) -> bool:
        if not self._client:
            return False
        try:
            return await self._client.ping()
        except Exception:
            return False
