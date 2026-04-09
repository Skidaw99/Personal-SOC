"""
Ollama client — async wrapper voor lokale Mistral 7B inference.

Gebruikt de Ollama REST API (/api/generate en /api/chat) voor snelle
realtime analyse van individuele security events (risk_score < 70).
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from .config import ai_settings

logger = logging.getLogger(__name__)


class OllamaClient:
    """
    Async client voor de lokale Ollama API.

    Gebruikt /api/chat voor conversatie-stijl prompts met system message.
    Fallback naar /api/generate als chat niet beschikbaar is.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self._base_url = (base_url or ai_settings.ollama_base_url).rstrip("/")
        self._model = model or ai_settings.ollama_model
        self._timeout = timeout or ai_settings.ollama_timeout

    async def generate(
        self,
        prompt: str,
        system: str = "",
    ) -> str:
        """
        Genereer een response via Ollama /api/chat.

        Args:
            prompt:  User message (de eigenlijke vraag/data).
            system:  System prompt (rol en output instructies).

        Returns:
            LLM-gegenereerde tekst.

        Raises:
            OllamaError: bij connectie- of API-fouten.
        """
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self._model,
            "messages": messages,
            "stream": False,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/api/chat",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()

            content = data.get("message", {}).get("content", "")
            if not content:
                raise OllamaError("Ollama returned empty response")

            logger.info(
                "ollama_generate_ok",
                model=self._model,
                prompt_len=len(prompt),
                response_len=len(content),
            )
            return content

        except httpx.ConnectError as exc:
            raise OllamaError(
                f"Cannot connect to Ollama at {self._base_url}. "
                f"Is Ollama running? Error: {exc}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise OllamaError(
                f"Ollama API error {exc.response.status_code}: {exc.response.text}"
            ) from exc
        except Exception as exc:
            if isinstance(exc, OllamaError):
                raise
            raise OllamaError(f"Ollama request failed: {exc}") from exc

    async def is_available(self) -> bool:
        """Check of Ollama draait en het model geladen is."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            # Match op model naam (met of zonder tag)
            base_name = self._model.split(":")[0]
            return any(base_name in m for m in models)
        except Exception:
            return False


class OllamaError(Exception):
    """Fout bij communicatie met Ollama."""
