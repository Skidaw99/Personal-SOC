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


# Multiplier thresholds for volume anomaly detection
POST_SPIKE_MULTIPLIER = 3.0    # 3x daily average = suspicious
API_SPIKE_MULTIPLIER = 5.0     # 5x daily average = suspicious
MESSAGE_SPIKE_MULTIPLIER = 4.0


def analyze_suspicious_activity(event: RawEvent, baseline: BehaviorBaseline | None) -> RuleResult:
    """
    Detects suspicious posting/messaging/API activity:
      - Post volume spike (3x+ daily average):     MEDIUM/HIGH
      - Message volume spike:                       HIGH
      - Post from unknown client app:               MEDIUM
      - API call volume spike:                      HIGH
    """
    if event.event_type not in (EventType.POST_CREATED, EventType.MESSAGE_SENT,
                                 EventType.API_CALL_SPIKE, EventType.FOLLOWER_SPIKE):
        return RuleResult(triggered=False, severity=EventSeverity.INFO, risk_score=0.0, reason="Not a suspicious activity event", evidence={})

    score = 0.0
    reasons = []
    evidence = {"event_type": event.event_type.value, "platform": event.platform}

    payload = event.raw_payload or {}

    # --- Post from unknown client app ---
    if event.event_type == EventType.POST_CREATED and event.client_app:
        known_apps: list = (baseline.known_apps if baseline and isinstance(baseline.known_apps, list) else [])
        if event.client_app not in known_apps:
            score += 35
            reasons.append(f"Post published via unknown client: {event.client_app}")
            evidence["unknown_client_app"] = event.client_app

    # --- Post volume spike ---
    if event.event_type == EventType.POST_CREATED and baseline and baseline.avg_daily_posts > 0:
        current_count = payload.get("count", 1)
        if current_count >= baseline.avg_daily_posts * POST_SPIKE_MULTIPLIER:
            spike_ratio = round(current_count / baseline.avg_daily_posts, 1)
            score += 40
            reasons.append(f"Post volume spike: {current_count} posts ({spike_ratio}x daily average)")
            evidence["post_spike"] = {"current": current_count, "avg": baseline.avg_daily_posts, "ratio": spike_ratio}

    # --- Message spike ---
    if event.event_type == EventType.MESSAGE_SENT and baseline and baseline.avg_daily_messages > 0:
        current_count = payload.get("count", 1)
        if current_count >= baseline.avg_daily_messages * MESSAGE_SPIKE_MULTIPLIER:
            spike_ratio = round(current_count / baseline.avg_daily_messages, 1)
            score += 50
            reasons.append(f"Message volume spike: {current_count} messages ({spike_ratio}x daily average)")
            evidence["message_spike"] = {"current": current_count, "avg": baseline.avg_daily_messages, "ratio": spike_ratio}

    # --- API call spike ---
    if event.event_type == EventType.API_CALL_SPIKE and baseline and baseline.avg_daily_api_calls > 0:
        current_calls = payload.get("count", 1)
        if current_calls >= baseline.avg_daily_api_calls * API_SPIKE_MULTIPLIER:
            spike_ratio = round(current_calls / baseline.avg_daily_api_calls, 1)
            score += 45
            reasons.append(f"API call spike: {current_calls} calls ({spike_ratio}x daily average)")
            evidence["api_spike"] = {"current": current_calls, "avg": baseline.avg_daily_api_calls, "ratio": spike_ratio}

    # --- Follower spike (bot activity signal) ---
    if event.event_type == EventType.FOLLOWER_SPIKE:
        follower_gain = payload.get("gain", 0)
        if follower_gain > 500:
            score += 30
            reasons.append(f"Unusual follower spike: +{follower_gain} followers")
            evidence["follower_spike"] = follower_gain

    if score == 0:
        return RuleResult(triggered=False, severity=EventSeverity.INFO, risk_score=0.0, reason="Activity within normal range", evidence={})

    severity = EventSeverity.LOW
    if score >= 70:
        severity = EventSeverity.HIGH
    elif score >= 40:
        severity = EventSeverity.MEDIUM

    return RuleResult(
        triggered=True,
        severity=severity,
        risk_score=min(score, 100.0),
        reason=" | ".join(reasons),
        evidence=evidence,
    )
