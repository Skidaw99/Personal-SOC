"""
BaseEnricher — abstract contract every IP intelligence provider must implement.

Contract
--------
- `enrich(ip)` is the only required method.
- It must NEVER raise. Catch all exceptions internally and return
  {"error": "<message>"} so the engine can continue with other providers.
- Return value is a flat dict whose keys map to ThreatIntelligence fields
  OR to the special key "error" / "provider_name".
- All I/O must be async.

Lifecycle
---------
1. EnrichmentEngine instantiates each enricher once at startup.
2. `is_available()` is called once. If False, the enricher is skipped.
3. `enrich(ip)` is called per-IP inside asyncio.gather() with per-enricher
   timeout specified by `timeout_seconds`.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseEnricher(ABC):
    """Abstract base class for all IP intelligence enrichers."""

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """
        Unique slug for this provider.
        Used in cache keys, error dicts, and the providers_used list.
        Example: "abuseipdb", "virustotal", "maxmind", "shodan", "ipapi"
        """
        ...

    # ── Configuration ─────────────────────────────────────────────────────────

    @property
    def timeout_seconds(self) -> float:
        """
        Per-request HTTP timeout in seconds.
        Override in slow providers (e.g. Shodan can be 15 s).
        """
        return 10.0

    @property
    def requires_api_key(self) -> bool:
        """False for free providers like ip-api.com."""
        return True

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def is_available(self) -> bool:
        """
        Return False to skip this enricher entirely (e.g. missing API key).
        Called once at engine startup — result is cached.
        Default: True. Override for providers that need a key or local file.
        """
        return True

    # ── Core method ───────────────────────────────────────────────────────────

    @abstractmethod
    async def enrich(self, ip: str) -> dict[str, Any]:
        """
        Look up the given IP and return enrichment data.

        Returns a flat dict. Keys should match ThreatIntelligence field names
        where possible. Always include {"provider_name": self.provider_name}.

        On any failure, return::

            {
                "provider_name": self.provider_name,
                "error": "<human-readable message>",
            }

        Never raises.
        """
        ...

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _error(self, message: str) -> dict[str, str]:
        """Convenience: build the standard error response dict."""
        logger.warning("enricher_failed", provider=self.provider_name, error=message)
        return {"provider_name": self.provider_name, "error": message}

    def _ok(self, data: dict[str, Any]) -> dict[str, Any]:
        """Convenience: stamp provider_name onto a successful result."""
        data["provider_name"] = self.provider_name
        return data
