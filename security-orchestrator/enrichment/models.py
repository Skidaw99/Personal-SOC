"""
ThreatIntelligence — canonical output dataclass for the IP Intelligence Engine.

Every enricher writes into a flat dict; EnrichmentEngine.merge() assembles
this dataclass from those dicts. Nothing in this file does any I/O.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional


# ── Sub-models ────────────────────────────────────────────────────────────────

@dataclass
class GeoLocation:
    country_code: Optional[str] = None      # ISO 3166-1 alpha-2  e.g. "NL"
    country_name: Optional[str] = None      # e.g. "Netherlands"
    region: Optional[str] = None            # State / province
    city: Optional[str] = None
    postal_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None          # e.g. "Europe/Amsterdam"
    asn: Optional[int] = None               # Autonomous System Number
    asn_name: Optional[str] = None          # e.g. "AS-CHOOPA"
    isp: Optional[str] = None
    org: Optional[str] = None


# ── Main dataclass ────────────────────────────────────────────────────────────

@dataclass
class ThreatIntelligence:
    """
    Fully enriched IP intelligence record.

    Fields are populated by individual enrichers; missing data stays None.
    threat_score (0-100) and reputation are computed by scorer.py after
    all enrichers have run.
    """

    ip: str

    # ── Geographic / network ─────────────────────────────────────────────────
    geo: GeoLocation = field(default_factory=GeoLocation)

    # ── Anonymization flags ───────────────────────────────────────────────────
    # Set to True only when at least one provider positively confirms the flag.
    # None = unknown (no provider returned data for this field).
    is_tor: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_datacenter: Optional[bool] = None
    is_mobile: Optional[bool] = None

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    abuse_confidence_score: Optional[int] = None    # 0-100
    abuse_total_reports: Optional[int] = None       # lifetime report count
    abuse_num_distinct_users: Optional[int] = None  # unique reporters
    abuse_last_reported_at: Optional[datetime] = None
    abuse_usage_type: Optional[str] = None          # e.g. "Data Center/Web Hosting/Transit"
    abuse_domain: Optional[str] = None
    abuse_is_whitelisted: Optional[bool] = None

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_harmless: Optional[int] = None
    vt_undetected: Optional[int] = None
    vt_total_engines: Optional[int] = None
    vt_last_analysis_date: Optional[datetime] = None
    vt_tags: list[str] = field(default_factory=list)
    vt_community_score: Optional[int] = None        # positive = good, negative = bad

    # ── Shodan ────────────────────────────────────────────────────────────────
    shodan_ports: list[int] = field(default_factory=list)
    shodan_vulns: list[str] = field(default_factory=list)       # CVE IDs
    shodan_hostnames: list[str] = field(default_factory=list)
    shodan_domains: list[str] = field(default_factory=list)
    shodan_tags: list[str] = field(default_factory=list)        # e.g. ["tor", "vpn"]
    shodan_os: Optional[str] = None
    shodan_last_update: Optional[datetime] = None

    # ── ip-api.com ────────────────────────────────────────────────────────────
    # Free, no key — used as fallback geo source and proxy/hosting flag
    ipapi_is_hosting: Optional[bool] = None
    ipapi_is_proxy: Optional[bool] = None

    # ── Composite scoring (set by scorer.py) ──────────────────────────────────
    threat_score: float = 0.0
    # "clean" | "suspicious" | "malicious" | "critical"
    reputation: str = "unknown"

    # ── Metadata ──────────────────────────────────────────────────────────────
    providers_used: list[str] = field(default_factory=list)
    # provider_name → error message for any provider that failed
    providers_failed: dict[str, str] = field(default_factory=dict)
    enriched_at: datetime = field(default_factory=datetime.utcnow)
    from_cache: bool = False

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dict (for Redis cache and API responses)."""
        d = asdict(self)
        # Convert datetime objects to ISO strings
        for key, val in d.items():
            if isinstance(val, datetime):
                d[key] = val.isoformat()
        # Geo sub-dict is already handled by asdict
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatIntelligence":
        """Deserialize from a cached dict. Restores datetime fields."""
        data = dict(data)

        # Restore GeoLocation
        geo_data = data.pop("geo", {}) or {}
        geo = GeoLocation(**{k: v for k, v in geo_data.items() if k in GeoLocation.__dataclass_fields__})

        # Restore datetime fields
        dt_fields = {
            "abuse_last_reported_at", "vt_last_analysis_date",
            "shodan_last_update", "enriched_at",
        }
        for f_name in dt_fields:
            val = data.get(f_name)
            if isinstance(val, str):
                try:
                    data[f_name] = datetime.fromisoformat(val)
                except ValueError:
                    data[f_name] = None

        # Drop unknown keys (forward-compat)
        known = set(cls.__dataclass_fields__.keys())
        data = {k: v for k, v in data.items() if k in known}

        return cls(geo=geo, **data)

    @classmethod
    def from_json(cls, raw: str) -> "ThreatIntelligence":
        return cls.from_dict(json.loads(raw))

    # ── Convenience helpers ────────────────────────────────────────────────────

    @property
    def is_anonymous(self) -> bool:
        """True if the IP is confirmed as TOR, VPN, or proxy by any provider."""
        return bool(self.is_tor or self.is_vpn or self.is_proxy)

    @property
    def has_known_vulns(self) -> bool:
        return len(self.shodan_vulns) > 0

    def summary_line(self) -> str:
        """Single-line human-readable summary for logs."""
        anon = []
        if self.is_tor:
            anon.append("TOR")
        if self.is_vpn:
            anon.append("VPN")
        if self.is_proxy:
            anon.append("PROXY")
        anon_str = "/".join(anon) if anon else "none"
        return (
            f"[{self.ip}] score={self.threat_score:.1f} rep={self.reputation} "
            f"country={self.geo.country_code} anon={anon_str} "
            f"abuse={self.abuse_confidence_score} "
            f"vt_malicious={self.vt_malicious} "
            f"ports={len(self.shodan_ports)} vulns={len(self.shodan_vulns)}"
        )
