"""
AI Copilot configuratie — Ollama + Claude API settings.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import Field


class AISettings(BaseSettings):
    """
    Configuratie voor de hybrid AI Copilot.

    Env vars:
      OLLAMA_BASE_URL        — Ollama API endpoint (default: http://localhost:11434)
      OLLAMA_MODEL           — Lokaal model (default: mistral:7b)
      OLLAMA_TIMEOUT         — Timeout in seconden voor Ollama requests
      ANTHROPIC_API_KEY      — Claude API key (vereist voor risk_score >= 70)
      CLAUDE_MODEL           — Claude model ID
      CLAUDE_MAX_TOKENS      — Max output tokens voor Claude responses
      AI_ROUTING_THRESHOLD   — Risk score grens: < threshold → Ollama, >= → Claude
    """

    # ── Ollama (lokaal) ──────────────────────────────────────────────────────
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama API base URL",
    )
    ollama_model: str = Field(
        default="mistral:7b",
        description="Lokaal Ollama model voor snelle analyse",
    )
    ollama_timeout: float = Field(
        default=60.0,
        description="Timeout in seconden voor Ollama requests",
    )

    # ── Claude API ───────────────────────────────────────────────────────────
    anthropic_api_key: str = Field(
        default="",
        description="Anthropic API key voor Claude",
    )
    claude_model: str = Field(
        default="claude-sonnet-4-20250514",
        description="Claude model ID voor diepgaande analyse",
    )
    claude_max_tokens: int = Field(
        default=4096,
        description="Max output tokens voor Claude responses",
    )

    # ── Routing ──────────────────────────────────────────────────────────────
    ai_routing_threshold: float = Field(
        default=70.0,
        description="Risk score grens: < threshold → Ollama, >= threshold → Claude",
    )

    model_config = {"env_prefix": "", "case_sensitive": False}


# Singleton — importeer dit overal
ai_settings = AISettings()
