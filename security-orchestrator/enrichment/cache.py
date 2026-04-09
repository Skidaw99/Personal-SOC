"""
IntelCache — Redis-backed cache voor ThreatIntelligence records.

Cache strategie
───────────────
- Key:  soc:ip_intel:{ip}
- TTL:  configureerbaar per provider, standaard 3600 s (1 uur)
- Bij cache hit: from_cache=True gezet op het ThreatIntelligence object
- Bij Redis uitval: cache wordt stilzwijgend omzeild (nooit blocking)

De cache slaat het volledige ThreatIntelligence object op als JSON.
"""
from __future__ import annotations

import logging
from typing import Optional

import redis.asyncio as aioredis

from .models import ThreatIntelligence

logger = logging.getLogger(__name__)

_KEY_PREFIX = "soc:ip_intel:"


class IntelCache:
    """Async Redis cache voor ThreatIntelligence records."""

    def __init__(self, redis_url: str, default_ttl: int = 3600) -> None:
        self._redis_url = redis_url
        self._default_ttl = default_ttl
        self._client: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        """Open Redis verbinding. Faalt gracefully — cache wordt dan omzeild."""
        try:
            self._client = aioredis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            # Ping to verify connection
            await self._client.ping()
            logger.info("intel_cache_connected", url=self._redis_url)
        except Exception as exc:
            logger.warning("intel_cache_unavailable", error=str(exc))
            self._client = None

    async def disconnect(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── Read ──────────────────────────────────────────────────────────────────

    async def get(self, ip: str) -> Optional[ThreatIntelligence]:
        """
        Return cached ThreatIntelligence or None on miss / error.
        Sets from_cache=True on the returned object.
        """
        if not self._client:
            return None

        key = _KEY_PREFIX + ip
        try:
            raw = await self._client.get(key)
            if raw is None:
                return None
            intel = ThreatIntelligence.from_json(raw)
            intel.from_cache = True
            logger.debug("intel_cache_hit", ip=ip)
            return intel
        except Exception as exc:
            logger.warning("intel_cache_get_error", ip=ip, error=str(exc))
            return None

    # ── Write ─────────────────────────────────────────────────────────────────

    async def set(self, intel: ThreatIntelligence, ttl: Optional[int] = None) -> None:
        """
        Cache the ThreatIntelligence record.
        Silently swallows errors — cache is best-effort.
        """
        if not self._client:
            return

        key = _KEY_PREFIX + intel.ip
        effective_ttl = ttl if ttl is not None else self._default_ttl

        try:
            await self._client.set(key, intel.to_json(), ex=effective_ttl)
            logger.debug("intel_cache_set", ip=intel.ip, ttl=effective_ttl)
        except Exception as exc:
            logger.warning("intel_cache_set_error", ip=intel.ip, error=str(exc))

    # ── Invalidation ──────────────────────────────────────────────────────────

    async def invalidate(self, ip: str) -> None:
        """Force-expire a cached record (e.g. after manual re-lookup)."""
        if not self._client:
            return
        try:
            await self._client.delete(_KEY_PREFIX + ip)
            logger.info("intel_cache_invalidated", ip=ip)
        except Exception as exc:
            logger.warning("intel_cache_invalidate_error", ip=ip, error=str(exc))

    async def ttl(self, ip: str) -> Optional[int]:
        """Return remaining TTL in seconds, or None if not cached."""
        if not self._client:
            return None
        try:
            val = await self._client.ttl(_KEY_PREFIX + ip)
            return val if val > 0 else None
        except Exception:
            return None

    # ── Health ────────────────────────────────────────────────────────────────

    async def ping(self) -> bool:
        """Health check for the /health endpoint."""
        if not self._client:
            return False
        try:
            return await self._client.ping()
        except Exception:
            return False
