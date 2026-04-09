"""
Match Signals — de bouwstenen van actor-attributie.

Elk signaal is een observatie die suggereert dat een nieuw event
toehoort aan een bepaalde ThreatActor. Signalen zijn additief:
de matcher telt ze op tot een totale confidence score (0–100).

Signal design principles
────────────────────────
- Een enkel signaal bewijst nooit attributie op zichzelf.
- Twee zwakke signalen samen (bijv. /24 subnet + zelfde aanvalspatroon)
  zijn sterker dan één sterk signaal in isolatie.
- Bij tegenstrijdige signalen wint de hogere score.
- Confidence >= ATTRIBUTION_THRESHOLD → attribueer aan actor.
- Confidence < ATTRIBUTION_THRESHOLD → maak nieuwe actor.

Signal scores (max optelling = 100 voor threshold bepaling)
────────────────────────────────────────────────────────────
  Exact IP match               90   (nagenoeg zeker)
  Exact fingerprint hash       85   (nagenoeg zeker)
  Partial fingerprint          45   (waarschijnlijk)
  /24 subnet + attack type     40   (sterk)
  Cross-platform IP            30   (sterk — zelfde IP op ander platform)
  Same attack category         25   (matig)
  /24 subnet alleen            20   (matig)
  Same platform                20   (matig)
  Temporal proximity           15   (zwak — aanvalspatroon timing)
  /16 subnet                   15   (zwak)
  Same ASN/ISP                 10   (zwak)
  Same country                  5   (zeer zwak)

Attribution threshold:  60
New actor threshold:    < 60
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .models import ThreatActor
    from .schemas import CorrelationEvent
    from .fingerprint import DeviceFingerprint

# ── Threshold ─────────────────────────────────────────────────────────────────
ATTRIBUTION_THRESHOLD = 60.0


# ── MatchSignal dataclass ──────────────────────────────────────────────────────

@dataclass
class MatchSignal:
    """A single evidence signal that contributes to match confidence."""
    name: str          # Machine-readable slug, e.g. "exact_ip_match"
    score: float       # Points contributed to match confidence
    reason: str        # Human-readable explanation for the analyst

    def to_dict(self) -> dict:
        return {"name": self.name, "score": self.score, "reason": self.reason}


# ── Signal extractors ──────────────────────────────────────────────────────────

def extract_signals(
    event: "CorrelationEvent",
    actor: "ThreatActor",
    event_fp: Optional["DeviceFingerprint"],
) -> list[MatchSignal]:
    """
    Compare a CorrelationEvent against a ThreatActor and return all
    matching signals. An empty list means no correlation evidence.

    Called for every candidate actor during matching.
    """
    signals: list[MatchSignal] = []

    # ── IP signals ────────────────────────────────────────────────────────────
    _ip_signals(event, actor, signals)

    # ── Fingerprint signals ───────────────────────────────────────────────────
    if event_fp:
        _fingerprint_signals(event_fp, actor, signals)

    # ── Attack pattern signals ────────────────────────────────────────────────
    _attack_signals(event, actor, signals)

    # ── Platform signals ──────────────────────────────────────────────────────
    _platform_signals(event, actor, signals)

    # ── Temporal signals ──────────────────────────────────────────────────────
    _temporal_signals(event, actor, signals)

    # ── Geographic signals ────────────────────────────────────────────────────
    _geo_signals(event, actor, signals)

    return signals


def total_confidence(signals: list[MatchSignal]) -> float:
    """Sum all signal scores, capped at 100."""
    return min(100.0, sum(s.score for s in signals))


# ── Individual signal extractors ───────────────────────────────────────────────

def _ip_signals(
    event: "CorrelationEvent",
    actor: "ThreatActor",
    out: list[MatchSignal],
) -> None:
    if not event.source_ip:
        return

    known_ips: list[str] = list(actor.known_ips or [])
    actor_ip_objects = actor.ips  # list[ActorIp]

    event_ip_str = event.source_ip

    # 1. Exact IP match
    if event_ip_str in known_ips:
        out.append(MatchSignal(
            name="exact_ip_match",
            score=90.0,
            reason=f"Source IP {event_ip_str} is in actor's known IP list",
        ))
        return  # Exact match dominates; skip subnet checks

    # Parse for subnet checks
    try:
        event_ip = ipaddress.ip_address(event_ip_str)
    except ValueError:
        return

    if not isinstance(event_ip, ipaddress.IPv4Address):
        # TODO: IPv6 subnet matching — for now only exact match
        return

    event_24 = _prefix_24(event_ip_str)
    event_16 = _prefix_16(event_ip_str)

    # Collect actor prefixes
    actor_24s = {_prefix_24(ip) for ip in known_ips if _prefix_24(ip)}
    actor_16s = {_prefix_16(ip) for ip in known_ips if _prefix_16(ip)}

    in_24 = event_24 and event_24 in actor_24s
    in_16 = event_16 and event_16 in actor_16s

    if in_24:
        # Check if the /24 overlap is combined with an attack pattern match
        attack_overlap = bool(
            event.event_type and event.event_type in (actor.attack_categories or [])
        )
        if attack_overlap:
            out.append(MatchSignal(
                name="subnet_24_plus_attack",
                score=40.0,
                reason=(
                    f"Source IP {event_ip_str} is in the same /24 ({event_24}.x) "
                    f"as actor and attack type '{event.event_type}' matches"
                ),
            ))
        else:
            out.append(MatchSignal(
                name="subnet_24_match",
                score=20.0,
                reason=(
                    f"Source IP {event_ip_str} is in the same /24 ({event_24}.x) "
                    f"as actor's known IPs"
                ),
            ))
    elif in_16:
        out.append(MatchSignal(
            name="subnet_16_match",
            score=15.0,
            reason=(
                f"Source IP {event_ip_str} shares /16 ({event_16}.x.x) "
                f"with actor's known IPs"
            ),
        ))

    # Cross-platform IP — same IP seen attacking a different platform
    if in_24 and event.platform and event.platform not in (actor.platforms_targeted or []):
        out.append(MatchSignal(
            name="cross_platform_ip",
            score=30.0,
            reason=(
                f"IP {event_ip_str} linked to actor on platform(s) "
                f"{actor.platforms_targeted}, now seen on '{event.platform}'"
            ),
        ))

    # ASN match
    if event.source_asn and actor.primary_asn and event.source_asn == actor.primary_asn:
        out.append(MatchSignal(
            name="same_asn",
            score=10.0,
            reason=f"Source ASN {event.source_asn} matches actor's primary ASN",
        ))


def _fingerprint_signals(
    event_fp: "DeviceFingerprint",
    actor: "ThreatActor",
    out: list[MatchSignal],
) -> None:
    from . import fingerprint as fp_module

    actor_fps = actor.fingerprints  # list[ActorFingerprint]
    if not actor_fps:
        return

    best_score = 0.0
    best_reason = ""

    for afp in actor_fps:
        # 1. Exact hash match
        if event_fp.fingerprint_hash and afp.fingerprint_hash == event_fp.fingerprint_hash:
            out.append(MatchSignal(
                name="exact_fingerprint_match",
                score=85.0,
                reason=(
                    f"Device fingerprint hash {event_fp.fingerprint_hash[:8]}... "
                    f"matches actor fingerprint (browser={afp.browser_family}, "
                    f"os={afp.os_family})"
                ),
            ))
            return  # Exact match — skip partial checks

        # 2. Partial similarity
        actor_fp = fp_module.DeviceFingerprint(
            browser_family=afp.browser_family,
            browser_version_major=afp.browser_version_major,
            os_family=afp.os_family,
            os_version_major=afp.os_version_major,
            device_type=afp.device_type,
            accept_language=afp.accept_language,
            fingerprint_hash=afp.fingerprint_hash,
        )
        sim = fp_module.similarity(event_fp, actor_fp)
        if sim >= 0.70 and sim > best_score:
            best_score = sim
            best_reason = (
                f"Device fingerprint similarity {sim:.0%} "
                f"(browser={event_fp.browser_family}/{actor_fp.browser_family}, "
                f"os={event_fp.os_family}/{actor_fp.os_family})"
            )

    if best_score >= 0.70:
        out.append(MatchSignal(
            name="partial_fingerprint_match",
            score=45.0,
            reason=best_reason,
        ))


def _attack_signals(
    event: "CorrelationEvent",
    actor: "ThreatActor",
    out: list[MatchSignal],
) -> None:
    categories: list[str] = list(actor.attack_categories or [])
    if not event.event_type or not categories:
        return

    if event.event_type in categories:
        out.append(MatchSignal(
            name="same_attack_category",
            score=25.0,
            reason=(
                f"Attack type '{event.event_type}' matches actor's known "
                f"categories {categories}"
            ),
        ))


def _platform_signals(
    event: "CorrelationEvent",
    actor: "ThreatActor",
    out: list[MatchSignal],
) -> None:
    platforms: list[str] = list(actor.platforms_targeted or [])
    if not event.platform or not platforms:
        return

    if event.platform in platforms:
        out.append(MatchSignal(
            name="same_platform",
            score=20.0,
            reason=(
                f"Platform '{event.platform}' matches actor's known "
                f"targets {platforms}"
            ),
        ))


def _temporal_signals(
    event: "CorrelationEvent",
    actor: "ThreatActor",
    out: list[MatchSignal],
) -> None:
    typical_hours: list[int] = list(actor.typical_hours or [])
    if not typical_hours:
        return

    event_hour = event.occurred_at.hour
    # Check ±1 hour window to account for slight scheduling drift
    for h in (event_hour - 1, event_hour, event_hour + 1):
        if h % 24 in typical_hours:
            out.append(MatchSignal(
                name="temporal_proximity",
                score=15.0,
                reason=(
                    f"Event occurred at hour {event_hour} UTC, within actor's "
                    f"typical active hours {sorted(typical_hours)}"
                ),
            ))
            return


def _geo_signals(
    event: "CorrelationEvent",
    actor: "ThreatActor",
    out: list[MatchSignal],
) -> None:
    if not event.source_country or not actor.primary_country:
        return

    if event.source_country.upper() == actor.primary_country.upper():
        out.append(MatchSignal(
            name="same_country",
            score=5.0,
            reason=(
                f"Source country '{event.source_country}' matches "
                f"actor's primary country"
            ),
        ))


# ── IP prefix helpers ──────────────────────────────────────────────────────────

def _prefix_24(ip: str) -> Optional[str]:
    """Extract /24 prefix string: '185.220.101.45' → '185.220.101'."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return None


def _prefix_16(ip: str) -> Optional[str]:
    """Extract /16 prefix string: '185.220.101.45' → '185.220'."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}"
    return None
