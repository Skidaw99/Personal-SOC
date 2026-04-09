from dataclasses import dataclass
from collectors.base import RawEvent
from models.event import EventType, EventSeverity
from models.baseline import BehaviorBaseline


@dataclass
class RuleResult:
    triggered: bool
    severity: EventSeverity
    risk_score: float          # 0.0 – 100.0
    reason: str
    evidence: dict


def analyze_login_anomaly(event: RawEvent, baseline: BehaviorBaseline | None) -> RuleResult:
    """
    Detects unauthorized logins by comparing the incoming login event
    against the account's established behavioral baseline.

    Risk scoring:
      - New IP not in baseline:          +25
      - New country not in baseline:     +40
      - New device not in baseline:      +20
      - No baseline established yet:     +10 (cautious — just flag as LOW)
      - Outside typical active hours:    +15
    """
    if event.event_type not in (EventType.LOGIN, EventType.TOKEN_REFRESH):
        return RuleResult(triggered=False, severity=EventSeverity.INFO, risk_score=0.0, reason="Not a login event", evidence={})

    score = 0.0
    reasons = []
    evidence = {}

    if baseline is None or not baseline.baseline_established:
        return RuleResult(
            triggered=True,
            severity=EventSeverity.LOW,
            risk_score=10.0,
            reason="Login detected — no baseline established yet for this account",
            evidence={"ip": event.source_ip, "country": event.source_country, "device": event.source_device},
        )

    # IP check
    known_ips: list = baseline.known_ips if isinstance(baseline.known_ips, list) else []
    if event.source_ip and event.source_ip not in known_ips:
        score += 25
        reasons.append(f"Unknown IP: {event.source_ip}")
        evidence["unknown_ip"] = event.source_ip

    # Country check
    known_countries: list = baseline.known_countries if isinstance(baseline.known_countries, list) else []
    if event.source_country and event.source_country not in known_countries:
        score += 40
        reasons.append(f"Login from new country: {event.source_country}")
        evidence["unknown_country"] = event.source_country

    # Device check
    known_devices: list = baseline.known_devices if isinstance(baseline.known_devices, list) else []
    if event.source_device and event.source_device not in known_devices:
        score += 20
        reasons.append(f"Unknown device: {event.source_device}")
        evidence["unknown_device"] = event.source_device

    # Hour-of-day check
    typical_hours: list = baseline.typical_active_hours if isinstance(baseline.typical_active_hours, list) else []
    if typical_hours and event.occurred_at.hour not in typical_hours:
        score += 15
        reasons.append(f"Login at unusual hour: {event.occurred_at.hour}:00 UTC")
        evidence["unusual_hour"] = event.occurred_at.hour

    if score == 0:
        return RuleResult(triggered=False, severity=EventSeverity.INFO, risk_score=0.0, reason="Login matches baseline", evidence={})

    severity = EventSeverity.LOW
    if score >= 60:
        severity = EventSeverity.CRITICAL
    elif score >= 40:
        severity = EventSeverity.HIGH
    elif score >= 25:
        severity = EventSeverity.MEDIUM

    return RuleResult(
        triggered=True,
        severity=severity,
        risk_score=min(score, 100.0),
        reason=" | ".join(reasons),
        evidence=evidence,
    )
