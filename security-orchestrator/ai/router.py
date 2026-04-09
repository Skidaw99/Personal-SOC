"""
AI Router — bepaalt welke backend (Ollama vs Claude) een request afhandelt.

Routing logica:
  risk_score < 70  → Ollama (lokaal Mistral 7B, snelle realtime analyse)
  risk_score >= 70 → Claude API (diepgaande threat reports, FBI rapporten)

Fallback: als Ollama niet beschikbaar is, fallback naar Claude (en vice versa
als Claude key ontbreekt — maar dat levert een waarschuwing op).
"""
from __future__ import annotations

import logging
from typing import Protocol

from .config import ai_settings

logger = logging.getLogger(__name__)


class LLMBackend(Protocol):
    """Protocol voor een LLM backend (Ollama of Claude)."""
    async def generate(self, prompt: str, system: str = "") -> str: ...
    async def is_available(self) -> bool: ...


class AIRouter:
    """
    Routeert requests naar Ollama of Claude op basis van risk_score.

    Bevat fallback logica: als de primaire backend niet beschikbaar is,
    wordt de andere geprobeerd.
    """

    def __init__(
        self,
        ollama: LLMBackend,
        claude: LLMBackend | None,
        threshold: float | None = None,
    ) -> None:
        self._ollama = ollama
        self._claude = claude
        self._threshold = threshold or ai_settings.ai_routing_threshold

    def select_backend(self, risk_score: float) -> tuple[LLMBackend, str]:
        """
        Selecteer de juiste backend op basis van risk_score.

        Returns:
            Tuple van (backend_instance, backend_name).

        Raises:
            RuntimeError: als geen enkele backend beschikbaar is.
        """
        if risk_score >= self._threshold:
            if self._claude is not None:
                logger.info(
                    "router_selected_claude",
                    risk_score=risk_score,
                    threshold=self._threshold,
                )
                return self._claude, "claude"
            else:
                logger.warning(
                    "router_claude_unavailable_fallback_ollama",
                    risk_score=risk_score,
                    reason="Claude client not configured (missing API key)",
                )
                return self._ollama, "ollama"
        else:
            logger.info(
                "router_selected_ollama",
                risk_score=risk_score,
                threshold=self._threshold,
            )
            return self._ollama, "ollama"

    async def select_backend_with_fallback(
        self, risk_score: float
    ) -> tuple[LLMBackend, str]:
        """
        Selecteer backend met availability check en automatische fallback.

        Probeert eerst de primaire backend. Als die niet beschikbaar is,
        valt terug op de andere.
        """
        primary, primary_name = self.select_backend(risk_score)

        if await primary.is_available():
            return primary, primary_name

        # Fallback
        if primary_name == "claude" and self._ollama is not None:
            logger.warning(
                "router_fallback",
                from_backend="claude",
                to_backend="ollama",
                reason="Claude API not reachable",
            )
            if await self._ollama.is_available():
                return self._ollama, "ollama"

        elif primary_name == "ollama" and self._claude is not None:
            logger.warning(
                "router_fallback",
                from_backend="ollama",
                to_backend="claude",
                reason="Ollama not reachable",
            )
            if await self._claude.is_available():
                return self._claude, "claude"

        # Geen fallback beschikbaar — probeer toch de primaire
        logger.error(
            "router_no_backend_available",
            risk_score=risk_score,
            primary=primary_name,
        )
        return primary, primary_name
