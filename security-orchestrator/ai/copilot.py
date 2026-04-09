"""
AI Copilot — hoofd-orchestrator voor de hybrid AI service.

Publieke API
────────────
    copilot = AICopilot()
    result = await copilot.analyze_alert(request)
    result = await copilot.threat_actor_profile(request)
    result = await copilot.fbi_report(request)
    result = await copilot.chat(request)

De copilot combineert:
  - Routing (risk_score → Ollama of Claude)
  - Prompt engineering (capability-specifieke system prompts)
  - Response formatting (gestandaardiseerd CopilotResponse model)
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Optional

from .claude import ClaudeClient, ClaudeConfigError
from .config import ai_settings
from .models import (
    AIBackend,
    AlertAnalysisRequest,
    ChatRequest,
    CopilotCapability,
    CopilotResponse,
    FBIReportRequest,
    ThreatProfileRequest,
)
from .ollama import OllamaClient
from .prompts import (
    ALERT_ANALYSIS_SYSTEM,
    CHAT_SYSTEM,
    FBI_REPORT_SYSTEM,
    THREAT_PROFILE_SYSTEM,
)
from .router import AIRouter

logger = logging.getLogger(__name__)


class AICopilot:
    """
    Hybrid AI Copilot voor de SOC Security Orchestrator.

    Initialiseert beide backends (Ollama lokaal + Claude API) en
    routeert requests op basis van risk_score.
    """

    def __init__(self) -> None:
        # Ollama — altijd beschikbaar (lokaal)
        self._ollama = OllamaClient()

        # Claude — optioneel (vereist API key)
        self._claude: Optional[ClaudeClient] = None
        try:
            self._claude = ClaudeClient()
        except ClaudeConfigError:
            logger.warning(
                "copilot_claude_not_configured",
                reason="ANTHROPIC_API_KEY not set — high-risk requests fall back to Ollama",
            )

        # Router
        self._router = AIRouter(
            ollama=self._ollama,
            claude=self._claude,
        )

    # ── Alert Analysis ───────────────────────────────────────────────────────

    async def analyze_alert(self, request: AlertAnalysisRequest) -> CopilotResponse:
        """Analyseer een security alert en geef een triage-beoordeling."""
        prompt = self._build_alert_prompt(request)
        return await self._execute(
            capability=CopilotCapability.ALERT_ANALYSIS,
            system=ALERT_ANALYSIS_SYSTEM,
            prompt=prompt,
            risk_score=request.risk_score,
        )

    # ── Threat Actor Profile ─────────────────────────────────────────────────

    async def threat_actor_profile(
        self, request: ThreatProfileRequest
    ) -> CopilotResponse:
        """Genereer een samenvatting van een threat actor profiel."""
        prompt = self._build_profile_prompt(request)
        return await self._execute(
            capability=CopilotCapability.THREAT_PROFILE,
            system=THREAT_PROFILE_SYSTEM,
            prompt=prompt,
            risk_score=request.risk_score,
        )

    # ── FBI Report ───────────────────────────────────────────────────────────

    async def fbi_report(self, request: FBIReportRequest) -> CopilotResponse:
        """Genereer een FBI IC3-format incident rapport."""
        prompt = self._build_fbi_prompt(request)
        return await self._execute(
            capability=CopilotCapability.FBI_REPORT,
            system=FBI_REPORT_SYSTEM,
            prompt=prompt,
            risk_score=request.risk_score,
        )

    # ── Chat ─────────────────────────────────────────────────────────────────

    async def chat(self, request: ChatRequest) -> CopilotResponse:
        """Beantwoord een vrije SOC-gerelateerde vraag."""
        prompt = request.message
        if request.context:
            prompt += f"\n\n### Context\n```json\n{json.dumps(request.context, indent=2, default=str)}\n```"
        return await self._execute(
            capability=CopilotCapability.CHAT,
            system=CHAT_SYSTEM,
            prompt=prompt,
            risk_score=request.risk_score,
        )

    # ── Health check ─────────────────────────────────────────────────────────

    async def health(self) -> dict:
        """Geeft de status van beide backends terug."""
        ollama_ok = await self._ollama.is_available()
        claude_ok = await self._claude.is_available() if self._claude else False
        return {
            "ollama": {
                "available": ollama_ok,
                "model": ai_settings.ollama_model,
                "url": ai_settings.ollama_base_url,
            },
            "claude": {
                "available": claude_ok,
                "model": ai_settings.claude_model,
                "configured": self._claude is not None,
            },
            "routing_threshold": ai_settings.ai_routing_threshold,
        }

    # ── Internal execution ───────────────────────────────────────────────────

    async def _execute(
        self,
        capability: CopilotCapability,
        system: str,
        prompt: str,
        risk_score: float,
    ) -> CopilotResponse:
        """
        Kern-executie: route naar de juiste backend, genereer response,
        verpak in CopilotResponse.
        """
        start = time.monotonic()

        backend, backend_name = self._router.select_backend(risk_score)
        model_used = (
            ai_settings.claude_model
            if backend_name == "claude"
            else ai_settings.ollama_model
        )

        error_msg = None
        content = ""

        try:
            content = await backend.generate(prompt=prompt, system=system)
        except Exception as exc:
            logger.error(
                "copilot_generation_failed",
                capability=capability.value,
                backend=backend_name,
                error=str(exc),
            )
            error_msg = str(exc)

            # Probeer fallback als primaire backend faalt
            fallback_backend, fallback_name = await self._try_fallback(
                backend_name, risk_score
            )
            if fallback_backend is not None and fallback_name != backend_name:
                try:
                    content = await fallback_backend.generate(
                        prompt=prompt, system=system
                    )
                    backend_name = fallback_name
                    model_used = (
                        ai_settings.claude_model
                        if fallback_name == "claude"
                        else ai_settings.ollama_model
                    )
                    error_msg = f"Fallback from {backend_name} to {fallback_name}: {error_msg}"
                except Exception as fallback_exc:
                    error_msg = (
                        f"Both backends failed. "
                        f"Primary ({backend_name}): {error_msg}. "
                        f"Fallback ({fallback_name}): {fallback_exc}"
                    )

        elapsed_ms = (time.monotonic() - start) * 1000

        return CopilotResponse(
            capability=capability,
            backend_used=AIBackend(backend_name),
            model_used=model_used,
            content=content,
            risk_score=risk_score,
            processing_time_ms=round(elapsed_ms, 1),
            timestamp=datetime.utcnow(),
            error=error_msg,
        )

    async def _try_fallback(
        self, failed_backend: str, risk_score: float
    ) -> tuple[object | None, str]:
        """Geef de fallback backend terug als die beschikbaar is."""
        if failed_backend == "ollama" and self._claude is not None:
            return self._claude, "claude"
        elif failed_backend == "claude":
            return self._ollama, "ollama"
        return None, failed_backend

    # ── Prompt builders ──────────────────────────────────────────────────────

    @staticmethod
    def _build_alert_prompt(req: AlertAnalysisRequest) -> str:
        sections = [
            f"## Security Alert Data",
            f"- **Event Type**: {req.event_type}",
            f"- **Severity**: {req.severity}",
            f"- **Risk Score**: {req.risk_score}/100",
        ]
        if req.alert_id:
            sections.append(f"- **Alert ID**: {req.alert_id}")
        if req.source_ip:
            sections.append(f"- **Source IP**: {req.source_ip}")
        if req.description:
            sections.append(f"\n### Description\n{req.description}")
        if req.threat_intel:
            sections.append(
                f"\n### Threat Intelligence Enrichment\n"
                f"```json\n{json.dumps(req.threat_intel, indent=2, default=str)}\n```"
            )
        if req.raw_payload:
            sections.append(
                f"\n### Raw Event Payload\n"
                f"```json\n{json.dumps(req.raw_payload, indent=2, default=str)}\n```"
            )
        return "\n".join(sections)

    @staticmethod
    def _build_profile_prompt(req: ThreatProfileRequest) -> str:
        sections = [
            f"## Threat Actor Data",
            f"- **Display Name**: {req.display_name or 'Unknown'}",
            f"- **Threat Level**: {req.threat_level}",
            f"- **Risk Score**: {req.risk_score}/100",
            f"- **Total Events**: {req.total_events}",
        ]
        if req.actor_id:
            sections.append(f"- **Actor ID**: {req.actor_id}")
        if req.known_ips:
            sections.append(f"- **Known IPs**: {', '.join(req.known_ips[:20])}")
        if req.known_countries:
            sections.append(f"- **Countries**: {', '.join(req.known_countries)}")
        if req.attack_categories:
            sections.append(f"- **Attack Categories**: {', '.join(req.attack_categories)}")
        if req.platforms_targeted:
            sections.append(f"- **Platforms Targeted**: {', '.join(req.platforms_targeted)}")

        flags = []
        if req.is_tor:
            flags.append("TOR")
        if req.is_vpn:
            flags.append("VPN")
        if req.uses_automation:
            flags.append("Automation/Bot")
        if flags:
            sections.append(f"- **Flags**: {', '.join(flags)}")

        if req.first_seen:
            sections.append(f"- **First Seen**: {req.first_seen.isoformat()}")
        if req.last_seen:
            sections.append(f"- **Last Seen**: {req.last_seen.isoformat()}")
        if req.analyst_notes:
            sections.append(f"\n### Analyst Notes\n{req.analyst_notes}")
        if req.ip_intel:
            sections.append(
                f"\n### IP Intelligence Data\n"
                f"```json\n{json.dumps(req.ip_intel, indent=2, default=str)}\n```"
            )
        return "\n".join(sections)

    @staticmethod
    def _build_fbi_prompt(req: FBIReportRequest) -> str:
        sections = [
            f"## Incident Data for FBI IC3 Report",
            f"- **Case Reference**: {req.case_reference}",
            f"- **Incident Type**: {req.incident_type}",
            f"- **Incident Date**: {req.incident_date.isoformat()}",
            f"- **Report Date**: {datetime.utcnow().isoformat()}",
            f"- **Risk Score**: {req.risk_score}/100",
        ]
        if req.actor_profile:
            sections.append(
                f"\n### Attributed Threat Actor\n"
                f"```json\n{json.dumps(req.actor_profile, indent=2, default=str)}\n```"
            )
        if req.involved_ips:
            sections.append(
                f"\n### Involved IP Addresses (with enrichment)\n"
                f"```json\n{json.dumps(req.involved_ips, indent=2, default=str)}\n```"
            )
        if req.event_timeline:
            sections.append(
                f"\n### Event Timeline\n"
                f"```json\n{json.dumps(req.event_timeline, indent=2, default=str)}\n```"
            )
        if req.affected_systems:
            sections.append(
                f"\n### Affected Systems\n"
                + "\n".join(f"- {s}" for s in req.affected_systems)
            )
        if req.estimated_impact:
            sections.append(f"\n### Estimated Impact\n{req.estimated_impact}")
        if req.evidence_references:
            sections.append(
                f"\n### Evidence References\n"
                + "\n".join(f"- {e}" for e in req.evidence_references)
            )
        if req.additional_context:
            sections.append(f"\n### Additional Context\n{req.additional_context}")
        return "\n".join(sections)
