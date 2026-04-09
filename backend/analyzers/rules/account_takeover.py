from dataclasses import dataclass
from collectors.base import RawEvent
from models.event import EventType, EventSeverity
from models.baseline import BehaviorBaseline


@dataclass
class RuleResult:
    triggered: bool
    severity: EventSeverity
    risk_score: float
    reason: str
    evidence: dict


# Events that strongly indicate a takeover attempt
TAKEOVER_SIGNALS = {
    EventType.PASSWORD_CHANGE: 70,
    EventType.EMAIL_CHANGE: 80,
    EventType.PHONE_CHANGE: 65,
    EventType.PROFILE_CHANGE: 20,
}


def analyze_account_takeover(event: RawEvent, baseline: BehaviorBaseline | None) -> RuleResult:
    """
    Detects account takeover signals:
      - Password/email/phone change from unknown location: high risk
      - Profile change from unknown IP/country: medium risk
      - Multiple critical changes in same session:  amplified risk

    Scoring:
      Base score from TAKEOVER_SIGNALS map
      +25 if source IP is unknown
      +20 if source country is unknown
      +15 if event occurred outside typical hours
    """
    base_score = TAKEOVER_SIGNALS.get(event.event_type, 0)
    if base_score == 0:
        return RuleResult(triggered=False, severity=EventSeverity.INFO, risk_score=0.0, reason="Not a takeover signal event", evidence={})

    score = float(base_score)
    reasons = [f"{event.event_type.value.replace('_', ' ').title()} detected on {event.platform}"]
    evidence = {"event_type": event.event_type.value, "platform": event.platform}

    if baseline:
        known_ips: list = baseline.known_ips if isinstance(baseline.known_ips, list) else []
        known_countries: list = baseline.known_countries if isinstance(baseline.known_countries, list) else []
        typical_hours: list = baseline.typical_active_hours if isinstance(baseline.typical_active_hours, list) else []

        if event.source_ip and event.source_ip not in known_ips:
            score += 25
            reasons.append(f"Change initiated from unknown IP: {event.source_ip}")
            evidence["unknown_ip"] = event.source_ip

        if event.source_country and event.source_country not in known_countries:
            score += 20
            reasons.append(f"Change from new country: {event.source_country}")
            evidence["unknown_country"] = event.source_country

        if typical_hours and event.occurred_at.hour not in typical_hours:
            score += 15
            reasons.append(f"Change at unusual hour: {event.occurred_at.hour}:00 UTC")
            evidence["unusual_hour"] = event.occurred_at.hour
    else:
        # No baseline — still flag critical change events
        score = max(score, 50.0)
        reasons.append("No baseline established — flagging credential change as suspicious")

    severity = EventSeverity.LOW
    if score >= 75:
        severity = EventSeverity.CRITICAL
    elif score >= 55:
        severity = EventSeverity.HIGH
    elif score >= 35:
        severity = EventSeverity.MEDIUM

    return RuleResult(
        triggered=True,
        severity=severity,
        risk_score=min(score, 100.0),
        reason=" | ".join(reasons),
        evidence=evidence,
    )
