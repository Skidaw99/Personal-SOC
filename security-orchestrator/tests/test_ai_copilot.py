"""
Tests voor de AI Copilot — routing logica, prompt building, en response handling.

Alle LLM calls worden gemockt (geen echte Ollama/Claude nodig).
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from security_orchestrator.ai.config import AISettings
from security_orchestrator.ai.models import (
    AIBackend,
    AlertAnalysisRequest,
    ChatRequest,
    CopilotCapability,
    CopilotResponse,
    FBIReportRequest,
    ThreatProfileRequest,
)
from security_orchestrator.ai.router import AIRouter
from security_orchestrator.ai.copilot import AICopilot


# ── Router tests ─────────────────────────────────────────────────────────────


class TestAIRouter:
    """Test routing logic: risk_score < 70 → Ollama, >= 70 → Claude."""

    def setup_method(self):
        self.ollama = AsyncMock()
        self.claude = AsyncMock()
        self.router = AIRouter(
            ollama=self.ollama,
            claude=self.claude,
            threshold=70.0,
        )

    def test_low_risk_routes_to_ollama(self):
        backend, name = self.router.select_backend(risk_score=30.0)
        assert name == "ollama"
        assert backend is self.ollama

    def test_medium_risk_routes_to_ollama(self):
        backend, name = self.router.select_backend(risk_score=69.9)
        assert name == "ollama"
        assert backend is self.ollama

    def test_high_risk_routes_to_claude(self):
        backend, name = self.router.select_backend(risk_score=70.0)
        assert name == "claude"
        assert backend is self.claude

    def test_critical_risk_routes_to_claude(self):
        backend, name = self.router.select_backend(risk_score=95.0)
        assert name == "claude"
        assert backend is self.claude

    def test_threshold_boundary_exact(self):
        """Exact op de grens → Claude."""
        backend, name = self.router.select_backend(risk_score=70.0)
        assert name == "claude"

    def test_no_claude_falls_back_to_ollama(self):
        """Als Claude niet geconfigureerd is, fallback naar Ollama."""
        router = AIRouter(ollama=self.ollama, claude=None, threshold=70.0)
        backend, name = router.select_backend(risk_score=90.0)
        assert name == "ollama"
        assert backend is self.ollama

    @pytest.mark.asyncio
    async def test_fallback_when_primary_unavailable(self):
        """Als Ollama niet beschikbaar is, fallback naar Claude."""
        self.ollama.is_available = AsyncMock(return_value=False)
        self.claude.is_available = AsyncMock(return_value=True)

        backend, name = await self.router.select_backend_with_fallback(
            risk_score=30.0
        )
        assert name == "claude"

    @pytest.mark.asyncio
    async def test_no_fallback_when_primary_available(self):
        """Als de primaire backend beschikbaar is, geen fallback."""
        self.ollama.is_available = AsyncMock(return_value=True)

        backend, name = await self.router.select_backend_with_fallback(
            risk_score=30.0
        )
        assert name == "ollama"


# ── Copilot tests ────────────────────────────────────────────────────────────


class TestAICopilot:
    """Test de copilot orchestrator met gemockte backends."""

    @pytest.fixture
    def copilot(self):
        """Maak een copilot met gemockte backends."""
        cop = AICopilot.__new__(AICopilot)
        cop._ollama = AsyncMock()
        cop._ollama.generate = AsyncMock(return_value="Ollama mock response")
        cop._ollama.is_available = AsyncMock(return_value=True)
        cop._claude = AsyncMock()
        cop._claude.generate = AsyncMock(return_value="Claude mock response")
        cop._claude.is_available = AsyncMock(return_value=True)
        cop._router = AIRouter(
            ollama=cop._ollama,
            claude=cop._claude,
            threshold=70.0,
        )
        return cop

    @pytest.mark.asyncio
    async def test_analyze_alert_low_risk_uses_ollama(self, copilot):
        request = AlertAnalysisRequest(
            event_type="port_scan",
            severity="low",
            risk_score=25.0,
            source_ip="192.168.1.100",
            description="Port scan detected from internal host",
        )
        result = await copilot.analyze_alert(request)

        assert result.capability == CopilotCapability.ALERT_ANALYSIS
        assert result.backend_used == AIBackend.OLLAMA
        assert result.content == "Ollama mock response"
        assert result.risk_score == 25.0
        assert result.error is None
        copilot._ollama.generate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_analyze_alert_high_risk_uses_claude(self, copilot):
        request = AlertAnalysisRequest(
            event_type="ransomware_callback",
            severity="critical",
            risk_score=92.0,
            source_ip="185.220.101.42",
            description="Suspected ransomware C2 callback detected",
        )
        result = await copilot.analyze_alert(request)

        assert result.capability == CopilotCapability.ALERT_ANALYSIS
        assert result.backend_used == AIBackend.CLAUDE
        assert result.content == "Claude mock response"
        assert result.risk_score == 92.0
        copilot._claude.generate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_threat_profile(self, copilot):
        request = ThreatProfileRequest(
            display_name="TOR-BF-A3F2",
            threat_level="high",
            risk_score=78.0,
            known_ips=["185.220.101.42", "185.220.101.43"],
            known_countries=["DE", "NL"],
            attack_categories=["brute_force"],
            total_events=42,
            is_tor=True,
        )
        result = await copilot.threat_actor_profile(request)

        assert result.capability == CopilotCapability.THREAT_PROFILE
        assert result.backend_used == AIBackend.CLAUDE  # risk_score 78 >= 70
        assert result.error is None

    @pytest.mark.asyncio
    async def test_fbi_report(self, copilot):
        request = FBIReportRequest(
            case_reference="SOC-2026-0042",
            incident_type="unauthorized_access",
            risk_score=85.0,
            affected_systems=["web-prod-01", "db-prod-02"],
            estimated_impact="Potential data exfiltration of customer PII",
        )
        result = await copilot.fbi_report(request)

        assert result.capability == CopilotCapability.FBI_REPORT
        assert result.backend_used == AIBackend.CLAUDE
        assert result.error is None

    @pytest.mark.asyncio
    async def test_chat_low_risk(self, copilot):
        request = ChatRequest(
            message="What is MITRE ATT&CK technique T1110?",
            risk_score=10.0,
        )
        result = await copilot.chat(request)

        assert result.capability == CopilotCapability.CHAT
        assert result.backend_used == AIBackend.OLLAMA
        assert result.content == "Ollama mock response"

    @pytest.mark.asyncio
    async def test_chat_with_context(self, copilot):
        request = ChatRequest(
            message="Is this IP malicious?",
            risk_score=75.0,
            context={"ip": "185.220.101.42", "abuse_score": 95},
        )
        result = await copilot.chat(request)

        assert result.backend_used == AIBackend.CLAUDE
        # Verify context was included in the prompt
        call_args = copilot._claude.generate.call_args
        assert "185.220.101.42" in call_args.kwargs.get("prompt", call_args[0][0] if call_args[0] else "")

    @pytest.mark.asyncio
    async def test_health_check(self, copilot):
        status = await copilot.health()

        assert status["ollama"]["available"] is True
        assert status["claude"]["available"] is True
        assert status["routing_threshold"] == 70.0

    @pytest.mark.asyncio
    async def test_backend_failure_triggers_fallback(self, copilot):
        """Als Ollama faalt, moet de copilot naar Claude fallbacken."""
        copilot._ollama.generate = AsyncMock(
            side_effect=Exception("Ollama connection refused")
        )

        request = AlertAnalysisRequest(
            event_type="port_scan",
            risk_score=25.0,
        )
        result = await copilot.analyze_alert(request)

        # Should have fallen back to Claude
        assert result.content == "Claude mock response"

    @pytest.mark.asyncio
    async def test_response_includes_timing(self, copilot):
        request = ChatRequest(message="test", risk_score=10.0)
        result = await copilot.chat(request)

        assert result.processing_time_ms > 0
        assert result.timestamp is not None


# ── Prompt builder tests ─────────────────────────────────────────────────────


class TestPromptBuilders:
    """Test dat prompt builders alle relevante data opnemen."""

    def test_alert_prompt_includes_all_fields(self):
        request = AlertAnalysisRequest(
            event_type="brute_force",
            severity="high",
            risk_score=65.0,
            source_ip="10.0.0.1",
            description="Multiple failed login attempts",
            threat_intel={"abuse_score": 85, "is_tor": True},
        )
        prompt = AICopilot._build_alert_prompt(request)

        assert "brute_force" in prompt
        assert "high" in prompt
        assert "65.0" in prompt
        assert "10.0.0.1" in prompt
        assert "Multiple failed login attempts" in prompt
        assert "abuse_score" in prompt

    def test_profile_prompt_includes_flags(self):
        request = ThreatProfileRequest(
            display_name="TOR-BF-A3F2",
            risk_score=80.0,
            is_tor=True,
            is_vpn=False,
            uses_automation=True,
        )
        prompt = AICopilot._build_profile_prompt(request)

        assert "TOR-BF-A3F2" in prompt
        assert "TOR" in prompt
        assert "Automation/Bot" in prompt

    def test_fbi_prompt_includes_evidence(self):
        request = FBIReportRequest(
            case_reference="SOC-2026-0042",
            incident_type="ransomware",
            risk_score=95.0,
            affected_systems=["web-01"],
            evidence_references=["pcap-001.pcap", "syslog-2026-04.gz"],
        )
        prompt = AICopilot._build_fbi_prompt(request)

        assert "SOC-2026-0042" in prompt
        assert "ransomware" in prompt
        assert "web-01" in prompt
        assert "pcap-001.pcap" in prompt
