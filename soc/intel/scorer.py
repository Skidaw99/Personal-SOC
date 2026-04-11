"""
IntelScorer — weighted composite threat score (0-100).

Scoring model
─────────────
Base (weighted average, total 100%):
  AbuseIPDB confidence score          40%
  VirusTotal malicious engine ratio   35%
  Shodan open-port / vuln signal      25%

Bonus (additive, capped at 100 total):
  +20  TOR exit node confirmed
  +10  VPN or open proxy confirmed
  +10  Datacenter/hosting IP
  + 5  Per active CVE (max +15)
  + 5  ip-api proxy flag (supplementary)

Reputation buckets:
   0 – 19  → clean
  20 – 49  → suspicious
  50 – 74  → malicious
  75 – 100 → critical
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc.intel.schemas import IntelResult

# ── Weights ──────────────────────────────────────────────────────────────────
_W_ABUSE = 0.40
_W_VT = 0.35
_W_SHODAN = 0.25

# ── Bonuses ──────────────────────────────────────────────────────────────────
_BONUS_TOR = 20.0
_BONUS_VPN_PROXY = 10.0
_BONUS_DATACENTER = 10.0
_BONUS_PER_CVE = 5.0
_BONUS_CVE_MAX = 15.0
_BONUS_IPAPI_PROXY = 5.0

# ── High/medium risk ports for Shodan scoring ────────────────────────────────
_HIGH_RISK_PORTS = {
    22, 23, 445, 3389, 4444, 6666, 6667, 9001, 9030, 31337,
}
_MEDIUM_RISK_PORTS = {
    21, 25, 53, 3306, 5432, 6379, 8080, 27017,
}


class IntelScorer:
    """Computes composite threat_score and reputation on an IntelResult."""

    def compute(self, intel: "IntelResult") -> "IntelResult":
        base = (
            self._abuse_component(intel) * _W_ABUSE
            + self._vt_component(intel) * _W_VT
            + self._shodan_component(intel) * _W_SHODAN
        )

        bonus = 0.0

        # TOR
        is_tor = bool(
            intel.is_tor
            or any("tor" in t.lower() for t in (intel.shodan_tags or []))
            or any("tor" in t.lower() for t in (intel.vt_tags or []))
        )
        if is_tor:
            bonus += _BONUS_TOR
            intel.is_tor = True

        # VPN / proxy
        if intel.is_vpn or intel.is_proxy or intel.ipapi_is_proxy:
            bonus += _BONUS_VPN_PROXY

        # Datacenter
        if intel.is_datacenter or intel.ipapi_is_hosting:
            bonus += _BONUS_DATACENTER

        # CVEs
        cve_count = len(intel.shodan_vulns or [])
        bonus += min(_BONUS_CVE_MAX, cve_count * _BONUS_PER_CVE)

        # ip-api supplementary proxy
        if intel.ipapi_is_proxy and not intel.is_proxy:
            bonus += _BONUS_IPAPI_PROXY

        intel.threat_score = round(min(100.0, max(0.0, base + bonus)), 2)
        intel.reputation = self._reputation(intel.threat_score)
        return intel

    def _abuse_component(self, intel: "IntelResult") -> float:
        score = intel.abuse_confidence_score
        if score is None:
            return 0.0
        return float(max(0, min(100, score)))

    def _vt_component(self, intel: "IntelResult") -> float:
        total = intel.vt_total_engines
        if not total:
            return 0.0
        malicious = intel.vt_malicious or 0
        suspicious = intel.vt_suspicious or 0
        weighted_bad = malicious + suspicious * 0.5
        return min(100.0, (weighted_bad / total) * 100.0)

    def _shodan_component(self, intel: "IntelResult") -> float:
        score = 0.0
        ports = set(intel.shodan_ports or [])
        vulns = intel.shodan_vulns or []

        high_hits = len(ports & _HIGH_RISK_PORTS)
        score += min(40.0, high_hits * 20.0)

        med_hits = len(ports & _MEDIUM_RISK_PORTS)
        score += min(20.0, med_hits * 10.0)

        if len(ports) > 10:
            score += 10.0

        score += min(40.0, len(vulns) * 10.0)
        return min(100.0, score)

    def _reputation(self, score: float) -> str:
        if score < 20.0:
            return "clean"
        elif score < 50.0:
            return "suspicious"
        elif score < 75.0:
            return "malicious"
        return "critical"
