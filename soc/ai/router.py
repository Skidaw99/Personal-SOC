"""
AI Router — risk-based routing between Ollama and Claude.

  risk_score < 70  → Ollama (local, fast)
  risk_score >= 70 → Claude API (deep analysis)

Automatic fallback: if the primary backend is unavailable,
the other is tried. Both failing returns the primary anyway
(will error at generation time with a clear message).
"""
from __future__ import annotations

import logging
from typing import Protocol, Optional

from soc.config import get_soc_settings

logger = logging.getLogger(__name__)


class LLMBackend(Protocol):
    async def generate(self, prompt: str, system: str = "") -> str: ...
    async def is_available(self) -> bool: ...


class AIRouter:

    def __init__(
        self,
        ollama: LLMBackend,
        claude: Optional[LLMBackend],
        threshold: Optional[float] = None,
    ) -> None:
        self._ollama = ollama
        self._claude = claude
        settings = get_soc_settings()
        self._threshold = threshold or 70.0

    def select(self, risk_score: float) -> tuple[LLMBackend, str]:
        """Select backend based on risk score. Returns (backend, name)."""
        if risk_score >= self._threshold and self._claude is not None:
            return self._claude, "claude"
        return self._ollama, "ollama"

    async def select_with_fallback(self, risk_score: float) -> tuple[LLMBackend, str]:
        """Select backend with availability check and automatic fallback."""
        primary, name = self.select(risk_score)

        if await primary.is_available():
            return primary, name

        # Fallback
        if name == "claude":
            logger.warning("claude unavailable, falling back to ollama")
            if await self._ollama.is_available():
                return self._ollama, "ollama"
        elif self._claude is not None:
            logger.warning("ollama unavailable, falling back to claude")
            if await self._claude.is_available():
                return self._claude, "claude"

        logger.error("no AI backend available, using primary=%s anyway", name)
        return primary, name
