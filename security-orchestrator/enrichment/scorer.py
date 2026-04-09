"""
ThreatScorer — berekent de gewogen composite threat score (0-100).

Scoring model
─────────────
Basis (gewogen gemiddelde van drie bronnen, totaal 100%):

  AbuseIPDB confidence score          40 %
  VirusTotal malicious engine ratio   35 %
  Shodan open-port / vuln signal      25 %

Bonus (additief, capped op 100 totaal):
  +20  TOR exit node bevestigd (een of meer bronnen)
  +10  VPN of open proxy bevestigd
  +10  Datacenter/hosting IP (niet-residentieel)
  + 5  Per actieve CVE in Shodan (max +15)
  + 5  ip-api.com proxy flag (additionele bevestiging)

Reputation buckets:
   0 – 19  → clean
  20 – 49  → suspicious
  50 – 74  → malicious
  75 – 100 → critical

De scorer muteert het ThreatIntelligence object in-place en retourneert het.
"""
from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import ThreatIntelligence

# ── Weights ────────────────────────────────────────────────────────────────────
_W_ABUSE = 0.40
_W_VT = 0.35
_W_SHODAN = 0.25

# ── Bonus caps ─────────────────────────────────────────────────────────────────
_BONUS_TOR = 20.0
_BONUS_VPN_OR_PROXY = 10.0
_BONUS_DATACENTER = 10.0
_BONUS_PER_CVE = 5.0
_BONUS_CVE_MAX = 15.0
_BONUS_IPAPI_PROXY = 5.0


def _abuse_component(intel: "ThreatIntelligence") -> float:
    """AbuseIPDB confidence score is already 0-100."""
    score = intel.abuse_confidence_score
    if score is None:
        return 0.0
    return float(max(0, min(100, score)))


def _virustotal_component(intel: "ThreatIntelligence") -> float:
    """
    Normalise VT votes to 0-100.

    ratio = malicious / (malicious + suspicious + harmless + undetected)
    We weight suspicious at 50 % of a full malicious vote.
    """
    total = intel.vt_total_engines
    if not total:
        return 0.0

    malicious = intel.vt_malicious or 0
    suspicious = intel.vt_suspicious or 0
    weighted_bad = malicious + suspicious * 0.5

    ratio = weighted_bad / total
    return float(min(100.0, ratio * 100.0))


def _shodan_component(intel: "ThreatIntelligence") -> float:
    """
    Shodan signal: combination of dangerous open ports and CVE count.

    Port scoring:
      - Any port in _HIGH_RISK_PORTS    → +20 pts  (capped at 40)
      - Any port in _MEDIUM_RISK_PORTS  → +10 pts  (capped at 20)
      - Total ports open (>10)          → +10 pts

    CVE scoring: +10 per CVE, capped at 40 pts.

    Total capped at 100.
    """
    _HIGH_RISK_PORTS = {
        22,    # SSH brute force target
        23,    # Telnet
        445,   # SMB (ransomware)
        3389,  # RDP
        4444,  # Metasploit default
        6666,  # IRC / botnet C2
        6667,
        9001,  # Tor relay
        9030,  # Tor control
        31337, # "Elite" backdoor
    }
    _MEDIUM_RISK_PORTS = {
        21,   # FTP
        25,   # SMTP relay (spam)
        53,   # DNS (open resolver)
        3306, # MySQL exposed
        5432, # PostgreSQL exposed
        6379, # Redis exposed
        8080, # Proxy / alt-HTTP
        27017,# MongoDB exposed
    }

    score = 0.0
    ports = set(intel.shodan_ports or [])
    vulns = intel.shodan_vulns or []

    # High-risk ports
    high_hits = len(ports & _HIGH_RISK_PORTS)
    score += min(40.0, high_hits * 20.0)

    # Medium-risk ports
    med_hits = len(ports & _MEDIUM_RISK_PORTS)
    score += min(20.0, med_hits * 10.0)

    # Large attack surface
    if len(ports) > 10:
        score += 10.0

    # CVEs
    score += min(40.0, len(vulns) * 10.0)

    return min(100.0, score)


def compute(intel: "ThreatIntelligence") -> "ThreatIntelligence":
    """
    Compute composite threat_score and reputation for the given intel record.
    Mutates intel in-place and returns it.
    """
    base = (
        _abuse_component(intel) * _W_ABUSE
        + _virustotal_component(intel) * _W_VT
        + _shodan_component(intel) * _W_SHODAN
    )

    bonus = 0.0

    # TOR confirmation — any single reliable source is enough
    is_tor = bool(
        intel.is_tor
        or any("tor" in (t.lower()) for t in (intel.shodan_tags or []))
        or any("tor" in (t.lower()) for t in (intel.vt_tags or []))
    )
    if is_tor:
        bonus += _BONUS_TOR
        intel.is_tor = True

    # VPN / proxy
    if intel.is_vpn or intel.is_proxy or intel.ipapi_is_proxy:
        bonus += _BONUS_VPN_OR_PROXY

    # Datacenter / hosting
    if intel.is_datacenter or intel.ipapi_is_hosting:
        bonus += _BONUS_DATACENTER

    # CVE bonus (capped)
    cve_count = len(intel.shodan_vulns or [])
    bonus += min(_BONUS_CVE_MAX, cve_count * _BONUS_PER_CVE)

    # ip-api proxy signal (only if not already counted above)
    if intel.ipapi_is_proxy and not intel.is_proxy:
        bonus += _BONUS_IPAPI_PROXY

    raw = base + bonus
    intel.threat_score = round(min(100.0, max(0.0, raw)), 2)
    intel.reputation = _reputation(intel.threat_score)

    return intel


def _reputation(score: float) -> str:
    if score < 20.0:
        return "clean"
    elif score < 50.0:
        return "suspicious"
    elif score < 75.0:
        return "malicious"
    else:
        return "critical"
