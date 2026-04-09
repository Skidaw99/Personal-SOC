"""
Tests voor de Response Engine — rules, routing tiers, audit trail.

Alle externe calls (CrowdSec, SMTP, webhooks, platform API) worden gemockt.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from security_orchestrator.response.rules import RuleDecision, evaluate
from security_orchestrator.response.schemas import (
    ActionResult,
    ResponseEvent,
    ResponseResult,
)
from security_orchestrator.response.engine import ResponseEngine


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_event(**overrides) -> ResponseEvent:
    """Maak een ResponseEvent met sensible defaults."""
    defaults = {
        "soc_event_id": uuid.uuid4(),
        "event_type": "brute_force",
        "risk_score": 50.0,
        "severity": "medium",
        "source_ip": "185.220.101.42",
        "source_country": "DE",
        "platform": "twitter",
        "target_user_id": "user-12345",
    }
    defaults.update(overrides)
    return ResponseEvent(**defaults)


# ═══════════════════════════════════════════════════════════════════════════════
# RULES ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestRulesEngine:
    """Test de rules evaluatie logica."""

    # ── Tier routing ─────────────────────────────────────────────────────────

    def test_critical_tier_risk_90(self):
        event = _make_event(risk_score=90.0)
        decision = evaluate(event)

        assert decision.tier == "critical"
        assert "ip_block" in decision.actions
        assert "email_alert" in decision.actions

    def test_critical_tier_risk_95(self):
        event = _make_event(risk_score=95.0)
        decision = evaluate(event)

        assert decision.tier == "critical"
        assert "ip_block" in decision.actions

    def test_high_tier_risk_70(self):
        event = _make_event(risk_score=70.0)
        decision = evaluate(event)

        assert decision.tier == "high"
        assert "email_alert" in decision.actions
        assert "webhook_alert" in decision.actions
        assert "account_flag" in decision.actions
        assert "ip_block" not in decision.actions

    def test_high_tier_risk_89(self):
        event = _make_event(risk_score=89.9)
        decision = evaluate(event)

        assert decision.tier == "high"

    def test_medium_tier_risk_50(self):
        event = _make_event(risk_score=50.0)
        decision = evaluate(event)

        assert decision.tier == "medium"
        assert "webhook_alert" in decision.actions
        assert "log_only" in decision.actions
        assert "email_alert" not in decision.actions
        assert "ip_block" not in decision.actions

    def test_low_tier_risk_below_50(self):
        event = _make_event(risk_score=25.0)
        decision = evaluate(event)

        assert decision.tier == "low"
        assert decision.actions == ["log_only"]

    def test_low_tier_risk_zero(self):
        event = _make_event(risk_score=0.0)
        decision = evaluate(event)

        assert decision.tier == "low"
        assert decision.actions == ["log_only"]

    # ── Boundary tests ───────────────────────────────────────────────────────

    def test_boundary_49_is_low(self):
        event = _make_event(risk_score=49.9)
        decision = evaluate(event)
        assert decision.tier == "low"

    def test_boundary_50_is_medium(self):
        event = _make_event(risk_score=50.0)
        decision = evaluate(event)
        assert decision.tier == "medium"

    def test_boundary_69_is_medium(self):
        event = _make_event(risk_score=69.9)
        decision = evaluate(event)
        assert decision.tier == "medium"

    def test_boundary_70_is_high(self):
        event = _make_event(risk_score=70.0)
        decision = evaluate(event)
        assert decision.tier == "high"

    def test_boundary_89_is_high(self):
        event = _make_event(risk_score=89.9)
        decision = evaluate(event)
        assert decision.tier == "high"

    def test_boundary_90_is_critical(self):
        event = _make_event(risk_score=90.0)
        decision = evaluate(event)
        assert decision.tier == "critical"

    # ── Override regels ──────────────────────────────────────────────────────

    def test_account_takeover_override(self):
        event = _make_event(event_type="account_takeover", risk_score=30.0)
        decision = evaluate(event)

        assert decision.tier == "override"
        assert "account_lock" in decision.actions
        assert "email_alert" in decision.actions
        assert "webhook_alert" in decision.actions

    def test_account_takeover_merges_with_tier_actions(self):
        """Account takeover met hoge risk score moet alle acties combineren."""
        event = _make_event(event_type="account_takeover", risk_score=95.0)
        decision = evaluate(event)

        assert decision.tier == "override"
        # Override acties
        assert "account_lock" in decision.actions
        # Tier acties (critical)
        assert "ip_block" in decision.actions
        assert "email_alert" in decision.actions

    def test_account_takeover_low_risk_still_locks(self):
        """Zelfs met lage risk score moet account_takeover het account locken."""
        event = _make_event(event_type="account_takeover", risk_score=10.0)
        decision = evaluate(event)

        assert "account_lock" in decision.actions

    # ── Rule matches metadata ────────────────────────────────────────────────

    def test_rules_matched_contains_reasons(self):
        event = _make_event(risk_score=75.0)
        decision = evaluate(event)

        assert len(decision.matches) >= 1
        for match in decision.matches:
            assert match.rule
            assert match.reason
            assert match.tier

    def test_actions_are_deduplicated(self):
        """Bij overlap tussen override en tier moeten acties uniek zijn."""
        event = _make_event(event_type="account_takeover", risk_score=80.0)
        decision = evaluate(event)

        # email_alert zit in zowel override als high tier — mag maar 1x voorkomen
        assert decision.actions.count("email_alert") == 1

    def test_actions_ordered_by_priority(self):
        """Acties moeten op volgorde van prioriteit staan."""
        event = _make_event(event_type="account_takeover", risk_score=95.0)
        decision = evaluate(event)

        # account_lock moet voor ip_block, ip_block voor email, etc.
        indices = {a: i for i, a in enumerate(decision.actions)}
        if "account_lock" in indices and "ip_block" in indices:
            assert indices["account_lock"] < indices["ip_block"]
        if "ip_block" in indices and "email_alert" in indices:
            assert indices["ip_block"] < indices["email_alert"]


# ═══════════════════════════════════════════════════════════════════════════════
# RESPONSE ENGINE TESTS (met gemockte DB en executors)
# ═══════════════════════════════════════════════════════════════════════════════

class TestResponseEngine:
    """Test de engine orchestratie met gemockte session en executors."""

    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        return session

    @pytest.fixture
    def engine(self, mock_session):
        return ResponseEngine(mock_session)

    @pytest.mark.asyncio
    async def test_low_risk_only_logs(self, engine, mock_session):
        event = _make_event(risk_score=25.0)

        with patch.dict(
            "security_orchestrator.response.engine._EXECUTOR_MAP", {}, clear=True
        ):
            result = await engine.process(event)

        assert result.tier == "low"
        assert len(result.actions_executed) == 1
        assert result.actions_executed[0].action_type == "log_only"
        assert result.actions_executed[0].status == "success"

    @pytest.mark.asyncio
    async def test_critical_risk_executes_block_and_email(self, engine, mock_session):
        event = _make_event(risk_score=92.0)

        mock_crowdsec = AsyncMock()
        mock_crowdsec.return_value.execute = AsyncMock(
            return_value=ActionResult(
                action_type="ip_block", status="success",
                target="185.220.101.42",
            )
        )
        mock_email = AsyncMock()
        mock_email.return_value.execute = AsyncMock(
            return_value=ActionResult(
                action_type="email_alert", status="success",
                target="soc@example.com",
            )
        )

        with patch.dict(
            "security_orchestrator.response.engine._EXECUTOR_MAP",
            {"ip_block": mock_crowdsec, "email_alert": mock_email},
            clear=True,
        ):
            result = await engine.process(event)

        assert result.tier == "critical"
        assert len(result.actions_executed) == 2
        action_types = {a.action_type for a in result.actions_executed}
        assert "ip_block" in action_types
        assert "email_alert" in action_types

    @pytest.mark.asyncio
    async def test_dry_run_skips_execution(self, mock_session):
        engine = ResponseEngine(mock_session)
        engine._dry_run = True

        event = _make_event(risk_score=95.0)

        result = await engine.process(event)

        assert result.is_dry_run is True
        assert all(a.status == "skipped" for a in result.actions_executed)

    @pytest.mark.asyncio
    async def test_audit_records_written(self, engine, mock_session):
        event = _make_event(risk_score=25.0)

        with patch.dict(
            "security_orchestrator.response.engine._EXECUTOR_MAP", {}, clear=True
        ):
            result = await engine.process(event)

        # session.add wordt aangeroepen voor decision + action records
        assert mock_session.add.call_count >= 2  # 1 decision + 1 action
        # session.flush wordt aangeroepen na elke write
        assert mock_session.flush.await_count >= 2

    @pytest.mark.asyncio
    async def test_account_takeover_triggers_lock(self, engine, mock_session):
        event = _make_event(event_type="account_takeover", risk_score=85.0)

        mock_lock = AsyncMock()
        mock_lock.return_value.execute = AsyncMock(
            return_value=ActionResult(
                action_type="account_lock", status="success",
                target="user-12345",
            )
        )
        mock_email = AsyncMock()
        mock_email.return_value.execute = AsyncMock(
            return_value=ActionResult(
                action_type="email_alert", status="success",
            )
        )
        mock_webhook = AsyncMock()
        mock_webhook.return_value.execute = AsyncMock(
            return_value=ActionResult(
                action_type="webhook_alert", status="success",
            )
        )
        mock_flag = AsyncMock()
        mock_flag.return_value.execute = AsyncMock(
            return_value=ActionResult(
                action_type="account_flag", status="success",
            )
        )

        with patch.dict(
            "security_orchestrator.response.engine._EXECUTOR_MAP",
            {
                "account_lock": mock_lock,
                "email_alert": mock_email,
                "webhook_alert": mock_webhook,
                "account_flag": mock_flag,
            },
            clear=True,
        ):
            result = await engine.process(event)

        assert result.tier == "override"
        action_types = {a.action_type for a in result.actions_executed}
        assert "account_lock" in action_types

    @pytest.mark.asyncio
    async def test_executor_failure_doesnt_stop_others(self, engine, mock_session):
        """Als één executor faalt, moeten de anderen gewoon doorgaan."""
        event = _make_event(risk_score=92.0)

        mock_crowdsec = AsyncMock()
        mock_crowdsec.return_value.execute = AsyncMock(
            return_value=ActionResult(
                action_type="ip_block", status="failed",
                error="CrowdSec connection refused",
            )
        )
        mock_email = AsyncMock()
        mock_email.return_value.execute = AsyncMock(
            return_value=ActionResult(
                action_type="email_alert", status="success",
            )
        )

        with patch.dict(
            "security_orchestrator.response.engine._EXECUTOR_MAP",
            {"ip_block": mock_crowdsec, "email_alert": mock_email},
            clear=True,
        ):
            result = await engine.process(event)

        assert result.has_failures is True
        assert not result.all_succeeded
        # Email moet gewoon geslaagd zijn ondanks CrowdSec fout
        email_result = next(
            a for a in result.actions_executed if a.action_type == "email_alert"
        )
        assert email_result.status == "success"


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestResponseSchemas:
    """Test input/output schema's."""

    def test_event_to_snapshot(self):
        event = _make_event()
        snapshot = event.to_snapshot()

        assert snapshot["event_type"] == "brute_force"
        assert snapshot["source_ip"] == "185.220.101.42"
        assert "soc_event_id" in snapshot
        assert "occurred_at" in snapshot

    def test_result_summary(self):
        result = ResponseResult(
            decision_id=uuid.uuid4(),
            tier="critical",
            risk_score=92.0,
            rules_matched=[{"rule": "risk_tier_critical", "tier": "critical", "actions": [], "reason": "test"}],
            actions_executed=[
                ActionResult(action_type="ip_block", status="success"),
                ActionResult(action_type="email_alert", status="failed", error="timeout"),
            ],
        )
        summary = result.summary()

        assert "critical" in summary
        assert "ok=1" in summary
        assert "fail=1" in summary

    def test_result_all_succeeded(self):
        result = ResponseResult(
            decision_id=uuid.uuid4(),
            tier="low",
            risk_score=20.0,
            rules_matched=[],
            actions_executed=[
                ActionResult(action_type="log_only", status="success"),
            ],
        )
        assert result.all_succeeded is True
        assert result.has_failures is False

    def test_result_dry_run_summary(self):
        result = ResponseResult(
            decision_id=uuid.uuid4(),
            tier="critical",
            risk_score=95.0,
            rules_matched=[],
            actions_executed=[],
            is_dry_run=True,
        )
        assert "DRY-RUN" in result.summary()
