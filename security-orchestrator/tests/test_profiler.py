"""
Threat Actor Profiler — unit tests.

Getest zonder echte database: alle repository calls worden gemockt.
Dit maakt de tests snel, deterministisch en CI-vriendelijk.

Run:
    pytest tests/test_profiler.py -v
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from correlation.fingerprint import DeviceFingerprint, extract, similarity
from correlation.models import ActorStatus, ThreatLevel
from correlation.schemas import CorrelationEvent, ProfilerResult
from correlation.signals import (
    ATTRIBUTION_THRESHOLD,
    MatchSignal,
    extract_signals,
    total_confidence,
)
from correlation.matcher import ActorMatcher, MatchDecision


# ── Fixtures ──────────────────────────────────────────────────────────────────

TOR_IP = "185.220.101.45"
OFFICE_IP = "203.0.113.10"
SUBNET_IP = "185.220.101.99"  # same /24 as TOR_IP


def make_event(**kwargs) -> CorrelationEvent:
    defaults = dict(
        soc_event_id=uuid.uuid4(),
        occurred_at=datetime(2025, 6, 15, 14, 30, 0),  # 14h UTC
        event_type="brute_force",
        source="social_fraud_detector",
        source_ip=TOR_IP,
        source_country="NL",
        source_asn=4224,
        source_isp="Tor Project",
        platform="twitter",
        user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        accept_language="nl",
        severity="high",
        risk_score=75.0,
        is_tor=True,
    )
    defaults.update(kwargs)
    return CorrelationEvent(**defaults)


def make_actor(**kwargs) -> MagicMock:
    """Create a mock ThreatActor with sensible defaults."""
    actor = MagicMock()
    actor.id = uuid.uuid4()
    actor.display_name = "TOR-BF-A3F2"
    actor.threat_level = ThreatLevel.HIGH
    actor.confidence_score = 75.0
    actor.status = ActorStatus.ACTIVE
    actor.known_ips = [TOR_IP]
    actor.known_countries = ["NL"]
    actor.primary_country = "NL"
    actor.primary_asn = 4224
    actor.platforms_targeted = ["twitter"]
    actor.attack_categories = ["brute_force"]
    actor.typical_hours = [13, 14, 15]
    actor.is_tor = True
    actor.is_vpn = False
    actor.is_cross_platform = False
    actor.uses_automation = False
    actor.max_ip_threat_score = 90.0
    actor.ips = []
    actor.fingerprints = []
    actor.total_events = 5
    actor.first_seen_at = datetime(2025, 6, 1)
    actor.last_seen_at = datetime(2025, 6, 14)
    for key, val in kwargs.items():
        setattr(actor, key, val)
    return actor


# ── Fingerprint tests ──────────────────────────────────────────────────────────

class TestDeviceFingerprint:
    def test_extract_firefox_linux(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        fp = extract(ua, accept_language="nl-NL,nl;q=0.9")
        assert fp.browser_family == "Firefox"
        assert fp.os_family == "Linux"
        assert fp.device_type in ("desktop", None)
        assert fp.fingerprint_hash != ""

    def test_extract_curl_bot(self):
        fp = extract("curl/7.88.1")
        assert fp.device_type == "bot"
        assert fp.browser_family in ("curl", "Other")

    def test_extract_python_requests_bot(self):
        fp = extract("python-requests/2.31.0")
        assert fp.device_type == "bot"

    def test_extract_none_ua(self):
        fp = extract(None)
        assert fp.fingerprint_hash != ""   # still produces a stable hash
        assert fp.browser_family is None

    def test_hash_is_deterministic(self):
        ua = "Mozilla/5.0 Firefox/115.0"
        fp1 = extract(ua, "nl")
        fp2 = extract(ua, "nl")
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_different_ua_different_hash(self):
        fp1 = extract("Mozilla/5.0 Firefox/115.0", "nl")
        fp2 = extract("curl/7.88.1", "nl")
        assert fp1.fingerprint_hash != fp2.fingerprint_hash

    def test_lang_normalization(self):
        fp1 = extract("Mozilla/5.0", "nl-NL,nl;q=0.9")
        fp2 = extract("Mozilla/5.0", "nl")
        # Normalized language should be identical → same hash
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_similarity_identical(self):
        fp = extract("Mozilla/5.0 Firefox/115.0", "nl")
        assert similarity(fp, fp) == 1.0

    def test_similarity_same_browser_os(self):
        fp1 = DeviceFingerprint(
            browser_family="Firefox", os_family="Linux",
            device_type="desktop", accept_language="nl",
        )
        fp1.compute_hash()
        fp2 = DeviceFingerprint(
            browser_family="Firefox", os_family="Linux",
            device_type="desktop", accept_language="nl",
        )
        fp2.compute_hash()
        assert similarity(fp1, fp2) == 1.0

    def test_similarity_different_browser(self):
        fp1 = DeviceFingerprint(browser_family="Firefox", os_family="Linux", device_type="desktop")
        fp1.compute_hash()
        fp2 = DeviceFingerprint(browser_family="Chrome", os_family="Linux", device_type="desktop")
        fp2.compute_hash()
        sim = similarity(fp1, fp2)
        assert 0.40 <= sim < 1.0   # OS matches but browser differs

    def test_similarity_completely_different(self):
        fp1 = DeviceFingerprint(browser_family="Firefox", os_family="Linux", device_type="desktop")
        fp1.compute_hash()
        fp2 = DeviceFingerprint(browser_family="curl", os_family="Other", device_type="bot")
        fp2.compute_hash()
        sim = similarity(fp1, fp2)
        assert sim < 0.40


# ── Signal tests ───────────────────────────────────────────────────────────────

class TestMatchSignals:
    def test_exact_ip_match(self):
        event = make_event(source_ip=TOR_IP)
        actor = make_actor(known_ips=[TOR_IP])
        signals = extract_signals(event, actor, None)
        names = [s.name for s in signals]
        assert "exact_ip_match" in names
        # Exact IP should contribute 90 points
        ip_signal = next(s for s in signals if s.name == "exact_ip_match")
        assert ip_signal.score == 90.0

    def test_subnet_24_match(self):
        event = make_event(source_ip=SUBNET_IP)  # .99 vs .45 — same /24
        actor = make_actor(known_ips=[TOR_IP], attack_categories=[])
        signals = extract_signals(event, actor, None)
        names = [s.name for s in signals]
        assert "subnet_24_match" in names or "subnet_24_plus_attack" in names

    def test_subnet_24_plus_attack(self):
        event = make_event(source_ip=SUBNET_IP, event_type="brute_force")
        actor = make_actor(known_ips=[TOR_IP], attack_categories=["brute_force"])
        signals = extract_signals(event, actor, None)
        names = [s.name for s in signals]
        assert "subnet_24_plus_attack" in names
        sig = next(s for s in signals if s.name == "subnet_24_plus_attack")
        assert sig.score == 40.0

    def test_cross_platform_ip(self):
        # Same /24 IP, but on a NEW platform
        event = make_event(source_ip=SUBNET_IP, platform="instagram")
        actor = make_actor(known_ips=[TOR_IP], platforms_targeted=["twitter"])
        signals = extract_signals(event, actor, None)
        names = [s.name for s in signals]
        assert "cross_platform_ip" in names
        sig = next(s for s in signals if s.name == "cross_platform_ip")
        assert sig.score == 30.0

    def test_same_attack_category(self):
        event = make_event(event_type="brute_force")
        actor = make_actor(known_ips=["1.2.3.4"], attack_categories=["brute_force"])
        signals = extract_signals(event, actor, None)
        names = [s.name for s in signals]
        assert "same_attack_category" in names

    def test_same_platform(self):
        event = make_event(platform="twitter")
        actor = make_actor(known_ips=["1.2.3.4"], platforms_targeted=["twitter"])
        signals = extract_signals(event, actor, None)
        names = [s.name for s in signals]
        assert "same_platform" in names

    def test_temporal_proximity(self):
        # Event at hour 14, actor typically active 13-15
        event = make_event(occurred_at=datetime(2025, 6, 15, 14, 30))
        actor = make_actor(known_ips=["1.2.3.4"], typical_hours=[13, 14, 15])
        signals = extract_signals(event, actor, None)
        names = [s.name for s in signals]
        assert "temporal_proximity" in names

    def test_no_temporal_signal_outside_window(self):
        # Event at hour 3, actor typically active 14-16
        event = make_event(occurred_at=datetime(2025, 6, 15, 3, 0))
        actor = make_actor(known_ips=["1.2.3.4"], typical_hours=[14, 15, 16])
        signals = extract_signals(event, actor, None)
        names = [s.name for s in signals]
        assert "temporal_proximity" not in names

    def test_same_country(self):
        event = make_event(source_country="NL")
        actor = make_actor(known_ips=["1.2.3.4"], primary_country="NL")
        signals = extract_signals(event, actor, None)
        names = [s.name for s in signals]
        assert "same_country" in names
        sig = next(s for s in signals if s.name == "same_country")
        assert sig.score == 5.0   # very weak signal

    def test_total_confidence_capped_at_100(self):
        signals = [
            MatchSignal("a", 90.0, ""),
            MatchSignal("b", 85.0, ""),
            MatchSignal("c", 30.0, ""),
        ]
        assert total_confidence(signals) == 100.0

    def test_attribution_threshold(self):
        # Exact IP alone (90) is above threshold
        event = make_event(source_ip=TOR_IP)
        actor = make_actor(known_ips=[TOR_IP])
        signals = extract_signals(event, actor, None)
        assert total_confidence(signals) >= ATTRIBUTION_THRESHOLD

    def test_weak_signals_below_threshold(self):
        # Only same_country (5) + temporal (15) = 20 — below threshold
        event = make_event(
            source_ip="8.8.8.8",      # different IP and /24
            source_country="NL",
            occurred_at=datetime(2025, 6, 15, 14, 0),
        )
        actor = make_actor(
            known_ips=["1.2.3.4"],
            primary_country="NL",
            typical_hours=[14],
            platforms_targeted=["linkedin"],  # different platform
        )
        signals = extract_signals(event, actor, None)
        assert total_confidence(signals) < ATTRIBUTION_THRESHOLD


# ── Matcher tests ──────────────────────────────────────────────────────────────

class TestActorMatcher:
    @pytest.mark.asyncio
    async def test_no_candidates_returns_new_actor(self):
        repo = AsyncMock()
        repo.find_actors_by_ip.return_value = []
        repo.find_actors_by_ip_prefix_24.return_value = []
        repo.find_actors_by_fingerprint.return_value = []

        matcher = ActorMatcher(repo)
        event = make_event(source_ip="10.0.0.1")
        decision = await matcher.match(event, None)

        assert decision.is_new_actor is True
        assert decision.best_match is None

    @pytest.mark.asyncio
    async def test_exact_ip_hit_attributes_to_actor(self):
        actor = make_actor(known_ips=[TOR_IP])
        repo = AsyncMock()
        repo.find_actors_by_ip.return_value = [actor]
        repo.find_actors_by_ip_prefix_24.return_value = []
        repo.find_actors_by_fingerprint.return_value = []

        matcher = ActorMatcher(repo)
        event = make_event(source_ip=TOR_IP)
        decision = await matcher.match(event, None)

        assert decision.is_new_actor is False
        assert decision.best_match is not None
        assert decision.best_match.confidence >= ATTRIBUTION_THRESHOLD
        assert "exact_ip_match" in [s.name for s in decision.best_match.signals]

    @pytest.mark.asyncio
    async def test_subnet_hit_above_threshold_with_attack_match(self):
        actor = make_actor(
            known_ips=[TOR_IP],
            attack_categories=["brute_force"],
            platforms_targeted=["twitter"],
            typical_hours=[14],
            primary_country="NL",
        )
        repo = AsyncMock()
        repo.find_actors_by_ip.return_value = []  # no exact match
        repo.find_actors_by_ip_prefix_24.return_value = [actor]
        repo.find_actors_by_fingerprint.return_value = []

        matcher = ActorMatcher(repo)
        # Same /24, same attack, same platform, same hour → should exceed threshold
        event = make_event(
            source_ip=SUBNET_IP,
            event_type="brute_force",
            platform="twitter",
            source_country="NL",
            occurred_at=datetime(2025, 6, 15, 14, 30),
        )
        decision = await matcher.match(event, None)

        # subnet_24_plus_attack (40) + same_attack (25) + same_platform (20) + temporal (15) + country (5) = 105 → 100
        assert decision.is_new_actor is False
        assert decision.best_match.confidence >= ATTRIBUTION_THRESHOLD

    @pytest.mark.asyncio
    async def test_deduplication_of_candidates(self):
        """Same actor returned by both IP and /24 queries must appear once."""
        actor = make_actor(known_ips=[TOR_IP])
        repo = AsyncMock()
        repo.find_actors_by_ip.return_value = [actor]
        # /24 also returns the same actor (different path through DB)
        repo.find_actors_by_ip_prefix_24.return_value = [actor]
        repo.find_actors_by_fingerprint.return_value = []

        matcher = ActorMatcher(repo)
        event = make_event(source_ip=TOR_IP)
        decision = await matcher.match(event, None)

        # Should only score the actor once
        assert len(decision.all_candidates) == 1


# ── Profiler integration tests (mocked DB) ────────────────────────────────────

class TestThreatActorProfiler:
    @pytest.mark.asyncio
    async def test_creates_new_actor_on_first_event(self):
        from correlation.profiler import ThreatActorProfiler

        event = make_event()
        new_actor = make_actor(
            display_name="TOR-BF-A3F2",
            threat_level=ThreatLevel.HIGH,
            confidence_score=50.0,
            total_events=0,
            platforms_targeted=[],
        )

        mock_session = AsyncMock()
        with patch(
            "correlation.profiler.ActorRepository"
        ) as MockRepo, patch(
            "correlation.profiler.ActorMatcher"
        ) as MockMatcher:
            repo_instance = MockRepo.return_value
            repo_instance.event_already_attributed = AsyncMock(return_value=False)
            repo_instance.create_actor = AsyncMock(return_value=new_actor)
            repo_instance.upsert_actor_ip = AsyncMock()
            repo_instance.upsert_actor_fingerprint = AsyncMock()
            repo_instance.record_attribution = AsyncMock()

            matcher_instance = MockMatcher.return_value
            matcher_instance.match = AsyncMock(
                return_value=MatchDecision(is_new_actor=True)
            )

            profiler = ThreatActorProfiler(mock_session)
            result = await profiler.process(event)

        assert result.was_new_actor is True
        assert result.match_confidence == 100.0
        assert result.actor_display_name == "TOR-BF-A3F2"

    @pytest.mark.asyncio
    async def test_attributes_to_existing_actor(self):
        from correlation.profiler import ThreatActorProfiler
        from correlation.matcher import MatchResult

        event = make_event(source_ip=TOR_IP)
        existing_actor = make_actor(known_ips=[TOR_IP])

        ip_signal = MatchSignal("exact_ip_match", 90.0, "IP match")
        match_result = MatchResult(
            actor_id=existing_actor.id,
            actor=existing_actor,
            confidence=90.0,
            signals=[ip_signal],
        )

        mock_session = AsyncMock()
        with patch("correlation.profiler.ActorRepository") as MockRepo, \
             patch("correlation.profiler.ActorMatcher") as MockMatcher:

            repo_instance = MockRepo.return_value
            repo_instance.event_already_attributed = AsyncMock(return_value=False)
            repo_instance.update_actor_on_event = AsyncMock()
            repo_instance.upsert_actor_ip = AsyncMock()
            repo_instance.upsert_actor_fingerprint = AsyncMock()
            repo_instance.record_attribution = AsyncMock()

            matcher_instance = MockMatcher.return_value
            matcher_instance.match = AsyncMock(
                return_value=MatchDecision(
                    is_new_actor=False,
                    best_match=match_result,
                    all_candidates=[match_result],
                )
            )

            profiler = ThreatActorProfiler(mock_session)
            result = await profiler.process(event)

        assert result.was_new_actor is False
        assert result.match_confidence == 90.0
        assert "exact_ip_match" in [s["name"] for s in result.signals_fired]

    @pytest.mark.asyncio
    async def test_cross_platform_detection(self):
        from correlation.profiler import ThreatActorProfiler
        from correlation.matcher import MatchResult

        # Actor previously seen only on twitter; new event on instagram
        event = make_event(source_ip=TOR_IP, platform="instagram")
        existing_actor = make_actor(
            known_ips=[TOR_IP],
            platforms_targeted=["twitter"],  # twitter only
        )

        ip_signal = MatchSignal("exact_ip_match", 90.0, "IP match")
        match_result = MatchResult(
            actor_id=existing_actor.id,
            actor=existing_actor,
            confidence=90.0,
            signals=[ip_signal],
        )

        mock_session = AsyncMock()
        with patch("correlation.profiler.ActorRepository") as MockRepo, \
             patch("correlation.profiler.ActorMatcher") as MockMatcher:

            repo_instance = MockRepo.return_value
            repo_instance.event_already_attributed = AsyncMock(return_value=False)
            repo_instance.update_actor_on_event = AsyncMock()
            repo_instance.upsert_actor_ip = AsyncMock()
            repo_instance.upsert_actor_fingerprint = AsyncMock()
            repo_instance.record_attribution = AsyncMock()

            matcher_instance = MockMatcher.return_value
            matcher_instance.match = AsyncMock(
                return_value=MatchDecision(
                    is_new_actor=False,
                    best_match=match_result,
                    all_candidates=[match_result],
                )
            )

            profiler = ThreatActorProfiler(mock_session)
            result = await profiler.process(event)

        assert result.new_platform_detected is True

    @pytest.mark.asyncio
    async def test_idempotency_skips_duplicate(self):
        from correlation.profiler import ThreatActorProfiler

        event = make_event()
        existing_actor_event = MagicMock()
        existing_actor_event.actor_id = uuid.uuid4()
        existing_actor_event.match_confidence = 90.0
        existing_actor_event.was_new_actor = False
        existing_actor_event.match_signals = []

        existing_actor = make_actor()
        mock_session = AsyncMock()

        with patch("correlation.profiler.ActorRepository") as MockRepo, \
             patch("correlation.profiler.ActorMatcher"):

            repo_instance = MockRepo.return_value
            repo_instance.event_already_attributed = AsyncMock(return_value=True)
            repo_instance.get_actor = AsyncMock(return_value=existing_actor)

            # Simulate the DB query for the existing ActorEvent
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = existing_actor_event
            mock_session.execute = AsyncMock(return_value=mock_result)

            profiler = ThreatActorProfiler(mock_session)
            result = await profiler.process(event)

        # Must return a result without calling create_actor or record_attribution
        assert result is not None
        repo_instance.create_actor.assert_not_called() if hasattr(repo_instance.create_actor, 'assert_not_called') else None
