"""
SOCCopilot — main AI orchestrator for the SOC.

Public API:
    copilot = SOCCopilot()
    result = await copilot.analyze_alert(event_data, risk_score)
    result = await copilot.summarize_actor(actor_data)
    result = await copilot.answer_question(question, context)
    result = await copilot.generate_fbi_brief(incident_data)
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Any, Optional

from soc.ai.claude import ClaudeClient, ClaudeConfigError
from soc.ai.ollama import OllamaClient
from soc.ai.router import AIRouter
from soc.ai import prompts
from soc.config import get_soc_settings

logger = logging.getLogger(__name__)


class CopilotResponse:
    """Standardized AI response."""

    def __init__(
        self,
        content: str,
        backend: str,
        model: str,
        capability: str,
        risk_score: float,
        duration_ms: float,
        error: Optional[str] = None,
    ) -> None:
        self.content = content
        self.backend_used = backend
        self.model_used = model
        self.capability = capability
        self.risk_score = risk_score
        self.processing_time_ms = duration_ms
        self.timestamp = datetime.utcnow()
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "backend_used": self.backend_used,
            "model_used": self.model_used,
            "capability": self.capability,
            "risk_score": self.risk_score,
            "processing_time_ms": self.processing_time_ms,
            "timestamp": self.timestamp.isoformat(),
            "error": self.error,
        }


class SOCCopilot:
    """
    Hybrid AI Copilot: Ollama (local) + Claude API.
    Routes by risk_score with automatic fallback.
    """

    def __init__(self) -> None:
        settings = get_soc_settings()

        self._ollama = OllamaClient()
        self._ollama_model = settings.ollama_model

        self._claude: Optional[ClaudeClient] = None
        self._claude_model = "claude-sonnet-4-20250514"
        try:
            self._claude = ClaudeClient()
        except ClaudeConfigError:
            logger.warning("claude not configured — high-risk requests fall back to ollama")

        self._router = AIRouter(
            ollama=self._ollama,
            claude=self._claude,
        )

    # ── Public API ───────────────────────────────────────────────────────────

    async def analyze_alert(
        self,
        event_data: dict[str, Any],
        risk_score: float = 0.0,
    ) -> CopilotResponse:
        """Analyze a security alert and return triage assessment."""
        prompt = self._build_alert_prompt(event_data)
        return await self._execute("alert_analysis", prompts.ALERT_ANALYSIS, prompt, risk_score)

    async def summarize_actor(
        self,
        actor_data: dict[str, Any],
        risk_score: float = 50.0,
    ) -> CopilotResponse:
        """Generate a threat actor profile summary."""
        prompt = self._build_actor_prompt(actor_data)
        return await self._execute("actor_profile", prompts.ACTOR_PROFILE, prompt, risk_score)

    async def answer_question(
        self,
        question: str,
        context: Optional[dict[str, Any]] = None,
        risk_score: float = 0.0,
    ) -> CopilotResponse:
        """Answer a free-form SOC analyst question."""
        prompt = question
        if context:
            prompt += f"\n\n### Context\n```json\n{json.dumps(context, indent=2, default=str)}\n```"
        return await self._execute("chat", prompts.CHAT, prompt, risk_score)

    async def generate_fbi_brief(
        self,
        incident_data: dict[str, Any],
        risk_score: float = 80.0,
    ) -> CopilotResponse:
        """Generate an FBI IC3-ready incident brief."""
        prompt = self._build_fbi_prompt(incident_data)
        return await self._execute("fbi_brief", prompts.FBI_BRIEF, prompt, risk_score)

    # ── Health ───────────────────────────────────────────────────────────────

    async def health(self) -> dict:
        ollama_ok = await self._ollama.is_available()
        claude_ok = await self._claude.is_available() if self._claude else False
        return {
            "ollama": {"available": ollama_ok, "model": self._ollama_model},
            "claude": {"available": claude_ok, "model": self._claude_model, "configured": self._claude is not None},
            "routing_threshold": 70.0,
        }

    # ── Internal ─────────────────────────────────────────────────────────────

    async def _execute(
        self,
        capability: str,
        system: str,
        prompt: str,
        risk_score: float,
    ) -> CopilotResponse:
        start = time.monotonic()

        backend, backend_name = self._router.select(risk_score)
        model = self._claude_model if backend_name == "claude" else self._ollama_model

        error_msg = None
        content = ""

        try:
            content = await backend.generate(prompt=prompt, system=system)
        except Exception as exc:
            logger.error("copilot %s failed on %s: %s", capability, backend_name, exc)
            error_msg = str(exc)

            # Try fallback
            fallback, fb_name = await self._router.select_with_fallback(risk_score)
            if fb_name != backend_name:
                try:
                    content = await fallback.generate(prompt=prompt, system=system)
                    backend_name = fb_name
                    model = self._claude_model if fb_name == "claude" else self._ollama_model
                    error_msg = f"fallback {backend_name}→{fb_name}: {error_msg}"
                except Exception as fb_exc:
                    error_msg = f"both backends failed — primary: {error_msg}, fallback: {fb_exc}"

        elapsed = (time.monotonic() - start) * 1000

        return CopilotResponse(
            content=content,
            backend=backend_name,
            model=model,
            capability=capability,
            risk_score=risk_score,
            duration_ms=round(elapsed, 1),
            error=error_msg,
        )

    # ── Prompt builders ──────────────────────────────────────────────────────

    @staticmethod
    def _build_alert_prompt(data: dict[str, Any]) -> str:
        lines = ["## Security Alert Data"]
        for key in ("event_type", "severity", "risk_score", "source_ip", "source_country", "description"):
            if key in data and data[key] is not None:
                lines.append(f"- **{key}**: {data[key]}")
        if data.get("intel"):
            lines.append(f"\n### IP Intelligence\n```json\n{json.dumps(data['intel'], indent=2, default=str)}\n```")
        if data.get("raw_payload"):
            lines.append(f"\n### Raw Payload\n```json\n{json.dumps(data['raw_payload'], indent=2, default=str)}\n```")
        return "\n".join(lines)

    @staticmethod
    def _build_actor_prompt(data: dict[str, Any]) -> str:
        lines = ["## Threat Actor Data"]
        for key in ("display_name", "threat_level", "total_events", "known_ips", "known_countries",
                     "platforms_targeted", "attack_categories", "is_tor", "is_vpn", "uses_automation",
                     "first_seen", "last_seen"):
            val = data.get(key)
            if val is not None:
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val[:20])
                lines.append(f"- **{key}**: {val}")
        if data.get("ip_intel"):
            lines.append(f"\n### IP Intelligence\n```json\n{json.dumps(data['ip_intel'], indent=2, default=str)}\n```")
        return "\n".join(lines)

    @staticmethod
    def _build_fbi_prompt(data: dict[str, Any]) -> str:
        lines = ["## Incident Data for FBI IC3 Brief"]
        for key in ("case_reference", "incident_type", "incident_date", "risk_score"):
            if key in data and data[key] is not None:
                lines.append(f"- **{key}**: {data[key]}")
        if data.get("actor_profile"):
            lines.append(f"\n### Threat Actor\n```json\n{json.dumps(data['actor_profile'], indent=2, default=str)}\n```")
        if data.get("involved_ips"):
            lines.append(f"\n### Involved IPs\n```json\n{json.dumps(data['involved_ips'], indent=2, default=str)}\n```")
        if data.get("timeline"):
            lines.append(f"\n### Timeline\n```json\n{json.dumps(data['timeline'], indent=2, default=str)}\n```")
        return "\n".join(lines)
