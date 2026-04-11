"""
soc.orchestrator — Security Event Orchestration Pipeline.

Ingests events from the Social Fraud Detector (via Redis queue),
enriches them with IP intelligence, normalizes into SocSecurityEvent,
correlates to threat actors, computes final risk scores, and persists.

Pipeline
────────
  Redis BLPOP (consumer.py)
    → normalizer.py    (raw JSON → SocSecurityEvent)
    → IntelEngine      (IP enrichment → threat_score)
    → correlator.py    (IP clustering + attack patterns → ThreatActor)
    → pipeline.py      (orchestrates full flow, persists, broadcasts)
"""
from soc.orchestrator.pipeline import OrchestrationPipeline
from soc.orchestrator.normalizer import EventNormalizer
from soc.orchestrator.correlator import EventCorrelator
from soc.orchestrator.consumer import QueueConsumer

__all__ = [
    "OrchestrationPipeline",
    "EventNormalizer",
    "EventCorrelator",
    "QueueConsumer",
]
