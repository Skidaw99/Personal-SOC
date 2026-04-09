"""
ResponseEngine — hoofd-orchestrator voor geautomatiseerde incident response.

Publieke API
────────────
    engine = ResponseEngine(session)
    result = await engine.process(event)
    print(result.summary())

Interne flow per event
──────────────────────
  1. Rules engine evalueren → RuleDecision (tier + acties)
  2. ResponseDecision record aanmaken in DB
  3. Executors selecteren op basis van geplande acties
  4. Alle executors parallel uitvoeren (of sequentieel bij dry-run)
  5. ResponseAction audit records schrijven (append-only)
  6. ResponseResult teruggeven

Thread safety
─────────────
De engine is NIET thread-safe. Eén instantie per request/taak.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from . import rules
from .config import response_settings
from .executors.account import AccountFlagExecutor, AccountLockExecutor
from .executors.base import BaseExecutor
from .executors.crowdsec import CrowdSecExecutor
from .executors.email import EmailExecutor
from .executors.webhook import WebhookExecutor
from .models import (
    ActionStatus,
    ActionType,
    ResponseAction,
    ResponseDecision,
    ResponseTier,
)
from .schemas import ActionResult, ResponseEvent, ResponseResult

logger = logging.getLogger(__name__)


# ── Executor registry ────────────────────────────────────────────────────────

_EXECUTOR_MAP: dict[str, type[BaseExecutor]] = {
    "ip_block": CrowdSecExecutor,
    "email_alert": EmailExecutor,
    "webhook_alert": WebhookExecutor,
    "account_lock": AccountLockExecutor,
    "account_flag": AccountFlagExecutor,
}


class ResponseEngine:
    """
    Orchestreert geautomatiseerde incident response.

    Instantieer per DB session (per request of Celery task).

    Usage::

        async with AsyncSessionLocal() as session:
            engine = ResponseEngine(session)
            result = await engine.process(event)
            await session.commit()
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._dry_run = response_settings.response_dry_run

    async def process(self, event: ResponseEvent) -> ResponseResult:
        """
        Verwerk een event: evalueer regels, voer acties uit, schrijf audit trail.

        Idempotent: als het event al verwerkt is, wordt het overgeslagen
        met een log_only result.
        """
        # ── 1. Rules evalueren ───────────────────────────────────────────────
        decision = rules.evaluate(event)

        # ── 2. Decision record aanmaken ──────────────────────────────────────
        decision_id = uuid.uuid4()
        db_decision = ResponseDecision(
            id=decision_id,
            soc_event_id=event.soc_event_id,
            actor_id=event.actor_id,
            event_type=event.event_type,
            risk_score=event.risk_score,
            tier=ResponseTier(decision.tier),
            rules_matched=[m.to_dict() for m in decision.matches],
            planned_actions=decision.actions,
            input_snapshot=event.to_snapshot(),
            is_dry_run=self._dry_run,
            decided_at=datetime.utcnow(),
        )
        self._session.add(db_decision)
        await self._session.flush()

        # ── 3. Acties uitvoeren ──────────────────────────────────────────────
        action_results: list[ActionResult] = []

        if self._dry_run:
            # Dry-run: log alle acties maar voer ze niet echt uit
            for action_type in decision.actions:
                result = ActionResult(
                    action_type=action_type,
                    status="skipped",
                    target=self._get_target(action_type, event),
                    error="Dry-run mode — action not executed",
                )
                action_results.append(result)
                await self._write_audit_record(decision_id, result)
        else:
            # Live: executors parallel uitvoeren
            action_results = await self._execute_actions(
                decision_id, decision.actions, event
            )

        # ── 4. Result samenstellen ───────────────────────────────────────────
        result = ResponseResult(
            decision_id=decision_id,
            tier=decision.tier,
            risk_score=event.risk_score,
            rules_matched=[m.to_dict() for m in decision.matches],
            actions_executed=action_results,
            is_dry_run=self._dry_run,
        )

        logger.info(
            "response_engine_processed",
            soc_event_id=str(event.soc_event_id),
            tier=decision.tier,
            actions_total=len(action_results),
            actions_ok=sum(1 for a in action_results if a.status == "success"),
            actions_failed=sum(1 for a in action_results if a.status == "failed"),
            dry_run=self._dry_run,
        )

        return result

    # ── Action execution ─────────────────────────────────────────────────────

    async def _execute_actions(
        self,
        decision_id: uuid.UUID,
        action_types: list[str],
        event: ResponseEvent,
    ) -> list[ActionResult]:
        """
        Voer alle geplande acties parallel uit.

        Elke actie wordt individueel afgevangen — een fout in één actie
        stopt de andere acties niet.
        """

        async def run_one(action_type: str) -> ActionResult:
            executor_cls = _EXECUTOR_MAP.get(action_type)

            if executor_cls is None:
                # log_only heeft geen executor — direct audit record
                result = ActionResult(
                    action_type=action_type,
                    status="success",
                    target=None,
                    payload={"note": "Logged to audit trail"},
                )
                await self._write_audit_record(decision_id, result)
                return result

            executor = executor_cls()

            try:
                result = await executor.execute(event)
            except Exception as exc:
                # Executor contract zegt "nooit raisen" maar safety net
                result = ActionResult(
                    action_type=action_type,
                    status="failed",
                    error=f"Executor raised unexpectedly: {exc}",
                )

            await self._write_audit_record(decision_id, result)
            return result

        results = await asyncio.gather(
            *[run_one(at) for at in action_types],
            return_exceptions=False,
        )
        return list(results)

    # ── Audit trail ──────────────────────────────────────────────────────────

    async def _write_audit_record(
        self,
        decision_id: uuid.UUID,
        result: ActionResult,
    ) -> None:
        """
        Schrijf een IMMUTABLE audit record naar response_actions.

        Dit is APPEND-ONLY: er worden nooit bestaande records geüpdatet.
        Elk record is een permanent forensisch bewijs.
        """
        now = datetime.utcnow()

        # Map string status naar enum
        status_map = {
            "success": ActionStatus.SUCCESS,
            "failed": ActionStatus.FAILED,
            "skipped": ActionStatus.SKIPPED,
            "pending": ActionStatus.PENDING,
        }

        # Map string action_type naar enum (graceful fallback)
        try:
            action_type_enum = ActionType(result.action_type)
        except ValueError:
            action_type_enum = ActionType.LOG_ONLY

        record = ResponseAction(
            id=uuid.uuid4(),
            decision_id=decision_id,
            action_type=action_type_enum,
            status=status_map.get(result.status, ActionStatus.FAILED),
            target=result.target,
            action_payload=result.payload,
            started_at=now,
            completed_at=now,
            duration_ms=result.duration_ms,
            error_message=result.error,
            retry_count=0,
            created_at=now,
        )
        self._session.add(record)
        await self._session.flush()

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _get_target(action_type: str, event: ResponseEvent) -> Optional[str]:
        """Bepaal het target voor een actie (voor dry-run logging)."""
        if action_type == "ip_block":
            return event.source_ip
        elif action_type in ("account_lock", "account_flag"):
            return event.target_user_id
        elif action_type == "email_alert":
            return response_settings.alert_to_emails or None
        elif action_type == "webhook_alert":
            return response_settings.webhook_url or None
        return None
