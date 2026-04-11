"""
soc.ai — Hybrid AI Copilot service.

Ollama (local Mistral) for fast analysis when risk < 70.
Claude API (claude-sonnet-4-20250514) for deep analysis when risk >= 70.
Automatic fallback between backends.
"""
from soc.ai.copilot import SOCCopilot
from soc.ai.router import AIRouter

__all__ = ["SOCCopilot", "AIRouter"]
