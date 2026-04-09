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


def analyze_token_misuse(event: RawEvent, baseline: BehaviorBaseline | None) -> RuleResult:
    """
    Detects API token misuse by checking:
      - New OAuth app authorized that wasn't previously known:  +50
      - Token refreshed from an unknown IP:                     +30
      - Token used by an unknown client application:            +35
      - Token rejected (401) = likely revoked/stolen:           +90
    """
    if event.event_type not in (EventType.NEW_OAUTH_APP, EventType.TOKEN_REFRESH, EventType.APP_REVOKED):
        return RuleResult(triggered=False, severity=EventSeverity.INFO, risk_score=0.0, reason="Not a token event", evidence={})

    score = 0.0
    reasons = []
    evidence = {}

    # Token explicitly rejected = critical signal
    payload = event.raw_payload or {}
    if payload.get("http_status") == 401 or payload.get("error") == "unauthorized":
        return RuleResult(
            triggered=True,
            severity=EventSeverity.CRITICAL,
            risk_score=90.0,
            reason=f"Access token rejected by {event.platform} — token may have been revoked or stolen",
            evidence={"platform": event.platform, "http_status": 401},
        )

    # New OAuth app
    if event.event_type == EventType.NEW_OAUTH_APP:
        known_apps: list = (baseline.known_apps if baseline and isinstance(baseline.known_apps, list) else [])
        if event.client_app and event.client_app not in known_apps:
            score += 50
            reasons.append(f"New OAuth app authorized: {event.client_app}")
            evidence["new_oauth_app"] = event.client_app

    # Unknown client app posting on behalf of account
    if event.event_type == EventType.TOKEN_REFRESH and event.client_app:
        known_apps: list = (baseline.known_apps if baseline and isinstance(baseline.known_apps, list) else [])
        if event.client_app not in known_apps:
            score += 35
            reasons.append(f"Token used by unknown client: {event.client_app}")
            evidence["unknown_client"] = event.client_app

    # Unknown IP refreshing token
    if event.source_ip and baseline:
        known_ips: list = baseline.known_ips if isinstance(baseline.known_ips, list) else []
        if event.source_ip not in known_ips:
            score += 30
            reasons.append(f"Token operation from unknown IP: {event.source_ip}")
            evidence["unknown_ip"] = event.source_ip

    if score == 0:
        return RuleResult(triggered=False, severity=EventSeverity.INFO, risk_score=0.0, reason="Token activity matches baseline", evidence={})

    severity = EventSeverity.LOW
    if score >= 70:
        severity = EventSeverity.CRITICAL
    elif score >= 50:
        severity = EventSeverity.HIGH
    elif score >= 30:
        severity = EventSeverity.MEDIUM

    return RuleResult(
        triggered=True,
        severity=severity,
        risk_score=min(score, 100.0),
        reason=" | ".join(reasons),
        evidence=evidence,
    )
