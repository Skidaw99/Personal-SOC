"""
Ollama client — async wrapper for local Mistral inference.

Uses /api/chat for conversation-style prompts with system message.
Designed for fast, low-latency analysis of events with risk < 70.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from soc.config import get_soc_settings

logger = logging.getLogger(__name__)


class OllamaClient:

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 60.0,
    ) -> None:
        settings = get_soc_settings()
        self._base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self._model = model or settings.ollama_model
        self._timeout = timeout

    async def generate(self, prompt: str, system: str = "") -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {"model": self._model, "messages": messages, "stream": False}

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(f"{self._base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()

            content = data.get("message", {}).get("content", "")
            if not content:
                raise OllamaError("empty response from Ollama")

            logger.info("ollama ok: model=%s prompt=%d resp=%d", self._model, len(prompt), len(content))
            return content

        except httpx.ConnectError as exc:
            raise OllamaError(f"cannot connect to Ollama at {self._base_url}: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise OllamaError(f"Ollama HTTP {exc.response.status_code}: {exc.response.text}") from exc
        except OllamaError:
            raise
        except Exception as exc:
            raise OllamaError(f"Ollama request failed: {exc}") from exc

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                resp.raise_for_status()
                data = resp.json()
            models = [m.get("name", "") for m in data.get("models", [])]
            base_name = self._model.split(":")[0]
            return any(base_name in m for m in models)
        except Exception:
            return False


class OllamaError(Exception):
    pass
