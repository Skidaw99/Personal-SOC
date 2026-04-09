"""
Response Rules Engine — bepaalt welke acties moeten worden uitgevoerd.

Regels worden in volgorde van specificiteit geëvalueerd:

  1. Override regels  (event_type specifiek, bijv. account_takeover)
  2. Tier regels      (risk score gebaseerd)

Elke regel retourneert een lijst van actie-typen die moeten worden
uitgevoerd, plus metadata over waarom de regel heeft gefired.

Tier tabel
──────────
  risk >= 90  → CRITICAL  → ip_block + email_alert
  risk >= 70  → HIGH      → email_alert + webhook_alert + account_flag
  risk >= 50  → MEDIUM    → webhook_alert + log_only
  risk <  50  → LOW       → log_only

Override regels
───────────────
  account_takeover → account_lock + email_alert + webhook_alert  (altijd OVERRIDE tier)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .schemas import ResponseEvent

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """Resultaat van een gematchte regel."""
    rule: str          # Machine-readable naam
    tier: str          # critical / high / medium / low / override
    actions: list[str] # Lijst van action_type slugs
    reason: str        # Human-readable uitleg

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "tier": self.tier,
            "actions": self.actions,
            "reason": self.reason,
        }


@dataclass
class RuleDecision:
    """Gecombineerd resultaat van alle gematchte regels."""
    tier: str
    matches: list[RuleMatch]
    actions: list[str]   # Gededupliceerde lijst van alle vereiste acties

    def to_dict(self) -> dict:
        return {
            "tier": self.tier,
            "matches": [m.to_dict() for m in self.matches],
            "actions": self.actions,
        }


# ── Override regels ──────────────────────────────────────────────────────────

_OVERRIDE_RULES: dict[str, RuleMatch] = {
    "account_takeover": RuleMatch(
        rule="account_takeover_detected",
        tier="override",
        actions=["account_lock", "email_alert", "webhook_alert"],
        reason=(
            "Account takeover detected — immediate account lock, "
            "critical email and webhook alert triggered"
        ),
    ),
}


# ── Tier regels ──────────────────────────────────────────────────────────────

def _tier_from_score(risk_score: float) -> tuple[str, list[str], str]:
    """
    Bepaal response tier, acties en reden op basis van risk score.

    Returns:
        (tier, actions, reason)
    """
    if risk_score >= 90:
        return (
            "critical",
            ["ip_block", "email_alert"],
            f"Risk score {risk_score:.0f} >= 90 — critical tier: "
            f"IP blocked via CrowdSec + email alert sent",
        )
    elif risk_score >= 70:
        return (
            "high",
            ["email_alert", "webhook_alert", "account_flag"],
            f"Risk score {risk_score:.0f} >= 70 — high tier: "
            f"email + webhook alert + account flagged for review",
        )
    elif risk_score >= 50:
        return (
            "medium",
            ["webhook_alert", "log_only"],
            f"Risk score {risk_score:.0f} >= 50 — medium tier: "
            f"webhook alert + logged for monitoring",
        )
    else:
        return (
            "low",
            ["log_only"],
            f"Risk score {risk_score:.0f} < 50 — low tier: "
            f"logged only, no automated action",
        )


def evaluate(event: ResponseEvent) -> RuleDecision:
    """
    Evalueer alle regels voor een event en retourneer de gecombineerde beslissing.

    Override regels worden eerst gecontroleerd. Als een override matcht,
    worden de acties samengevoegd met de tier-gebaseerde acties (de tier
    wordt overschreven naar "override").
    """
    matches: list[RuleMatch] = []
    all_actions: set[str] = set()
    highest_tier = "low"

    # 1. Check override regels (event_type specifiek)
    override = _OVERRIDE_RULES.get(event.event_type)
    if override is not None:
        matches.append(override)
        all_actions.update(override.actions)
        highest_tier = "override"
        logger.warning(
            "response_override_rule_fired",
            rule=override.rule,
            event_type=event.event_type,
            soc_event_id=str(event.soc_event_id),
        )

    # 2. Tier regels (altijd evalueren — acties worden samengevoegd)
    tier, tier_actions, tier_reason = _tier_from_score(event.risk_score)

    tier_match = RuleMatch(
        rule=f"risk_tier_{tier}",
        tier=tier,
        actions=tier_actions,
        reason=tier_reason,
    )
    matches.append(tier_match)
    all_actions.update(tier_actions)

    # Bepaal de hoogste tier (override > critical > high > medium > low)
    if highest_tier != "override":
        highest_tier = tier

    # Dedupliceer en sorteer acties op prioriteit
    action_priority = [
        "account_lock",
        "ip_block",
        "email_alert",
        "webhook_alert",
        "account_flag",
        "log_only",
    ]
    sorted_actions = [a for a in action_priority if a in all_actions]

    logger.info(
        "response_rules_evaluated",
        tier=highest_tier,
        rules=[m.rule for m in matches],
        actions=sorted_actions,
        risk_score=event.risk_score,
        event_type=event.event_type,
    )

    return RuleDecision(
        tier=highest_tier,
        matches=matches,
        actions=sorted_actions,
    )
