"""
Claude API client — async wrapper voor Anthropic Claude API.

Gebruikt de Anthropic Python SDK voor diepgaande threat analysis,
FBI rapport generatie en complexe threat actor profiling (risk_score >= 70).
"""
from __future__ import annotations

import logging
from typing import Optional

import anthropic

from .config import ai_settings

logger = logging.getLogger(__name__)


class ClaudeClient:
    """
    Async client voor de Anthropic Claude API.

    Gebruikt de officiële anthropic SDK met async support.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> None:
        self._api_key = api_key or ai_settings.anthropic_api_key
        self._model = model or ai_settings.claude_model
        self._max_tokens = max_tokens or ai_settings.claude_max_tokens

        if not self._api_key:
            raise ClaudeConfigError(
                "ANTHROPIC_API_KEY is not set. "
                "Claude API is required for high-risk analysis (risk_score >= 70)."
            )

        self._client = anthropic.AsyncAnthropic(api_key=self._api_key)

    async def generate(
        self,
        prompt: str,
        system: str = "",
    ) -> str:
        """
        Genereer een response via Claude API.

        Args:
            prompt:  User message (de eigenlijke vraag/data).
            system:  System prompt (rol en output instructies).

        Returns:
            LLM-gegenereerde tekst.

        Raises:
            ClaudeError: bij API-fouten.
        """
        try:
            kwargs: dict = {
                "model": self._model,
                "max_tokens": self._max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
            if system:
                kwargs["system"] = system

            response = await self._client.messages.create(**kwargs)

            content = response.content[0].text if response.content else ""
            if not content:
                raise ClaudeError("Claude returned empty response")

            logger.info(
                "claude_generate_ok",
                model=self._model,
                prompt_len=len(prompt),
                response_len=len(content),
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            )
            return content

        except anthropic.AuthenticationError as exc:
            raise ClaudeConfigError(
                f"Claude API authentication failed. Check ANTHROPIC_API_KEY. Error: {exc}"
            ) from exc
        except anthropic.RateLimitError as exc:
            raise ClaudeError(
                f"Claude API rate limit exceeded. Try again later. Error: {exc}"
            ) from exc
        except anthropic.APIStatusError as exc:
            raise ClaudeError(
                f"Claude API error {exc.status_code}: {exc.message}"
            ) from exc
        except Exception as exc:
            if isinstance(exc, (ClaudeError, ClaudeConfigError)):
                raise
            raise ClaudeError(f"Claude request failed: {exc}") from exc

    async def is_available(self) -> bool:
        """Check of de Claude API bereikbaar is met de huidige key."""
        if not self._api_key:
            return False
        try:
            # Minimale request om de key te valideren
            await self._client.messages.create(
                model=self._model,
                max_tokens=10,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True
        except Exception:
            return False


class ClaudeError(Exception):
    """Fout bij communicatie met Claude API."""


class ClaudeConfigError(ClaudeError):
    """Configuratiefout (bijv. ontbrekende API key)."""
