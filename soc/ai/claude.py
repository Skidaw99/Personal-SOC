"""
Claude API client — async wrapper for Anthropic Claude API.

Used for deep threat analysis, FBI report generation, and complex
threat actor profiling when risk_score >= 70.
"""
from __future__ import annotations

import logging
from typing import Optional

import anthropic

from soc.config import get_soc_settings

logger = logging.getLogger(__name__)


class ClaudeClient:

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
    ) -> None:
        settings = get_soc_settings()
        self._api_key = api_key or settings.anthropic_api_key
        self._model = model
        self._max_tokens = max_tokens

        if not self._api_key:
            raise ClaudeConfigError("ANTHROPIC_API_KEY not set")

        self._client = anthropic.AsyncAnthropic(api_key=self._api_key)

    async def generate(self, prompt: str, system: str = "") -> str:
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
                "claude ok: model=%s in=%d out=%d",
                self._model,
                response.usage.input_tokens,
                response.usage.output_tokens,
            )
            return content

        except anthropic.AuthenticationError as exc:
            raise ClaudeConfigError(f"Claude auth failed: {exc}") from exc
        except anthropic.RateLimitError as exc:
            raise ClaudeError(f"Claude rate limit: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise ClaudeError(f"Claude API {exc.status_code}: {exc.message}") from exc
        except (ClaudeError, ClaudeConfigError):
            raise
        except Exception as exc:
            raise ClaudeError(f"Claude request failed: {exc}") from exc

    async def is_available(self) -> bool:
        if not self._api_key:
            return False
        try:
            await self._client.messages.create(
                model=self._model, max_tokens=10,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True
        except Exception:
            return False


class ClaudeError(Exception):
    pass


class ClaudeConfigError(ClaudeError):
    pass
