"""
BaseProvider — abstract contract for all IP intelligence providers.

Rules:
  - enrich() must NEVER raise — catch all exceptions and return _error()
  - Return flat dict with provider_name stamped in
  - All I/O must be async
  - Per-provider timeout via timeout_seconds property
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseProvider(ABC):

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique slug: 'abuseipdb', 'virustotal', 'shodan', 'maxmind', 'ipapi'."""
        ...

    @property
    def timeout_seconds(self) -> float:
        return 10.0

    @property
    def requires_api_key(self) -> bool:
        return True

    async def is_available(self) -> bool:
        return True

    @abstractmethod
    async def enrich(self, ip: str) -> dict[str, Any]:
        """
        Look up ip, return flat dict of enrichment data.
        On failure return self._error("reason").
        Never raises.
        """
        ...

    def _error(self, message: str) -> dict[str, str]:
        logger.warning("provider_failed provider=%s error=%s", self.provider_name, message)
        return {"provider_name": self.provider_name, "error": message}

    def _ok(self, data: dict[str, Any]) -> dict[str, Any]:
        data["provider_name"] = self.provider_name
        return data
