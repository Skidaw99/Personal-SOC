"""
Intel schemas — canonical dataclasses for IP intelligence results.

IntelResult is the single output type for the entire intel engine.
All providers write into flat dicts; the engine merges them into this.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class GeoData:
    """Geographic + network ownership data for an IP."""
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    asn: Optional[int] = None
    asn_name: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None


@dataclass
class IntelResult:
    """
    Fully enriched IP intelligence record.

    Populated by the IntelEngine after all providers have run.
    threat_score and reputation are set by IntelScorer.
    """
    ip: str

    # ── Geo ──────────────────────────────────────────────────────────────────
    geo: GeoData = field(default_factory=GeoData)

    # ── Anonymization flags ──────────────────────────────────────────────────
    is_tor: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_datacenter: Optional[bool] = None
    is_mobile: Optional[bool] = None

    # ── AbuseIPDB ────────────────────────────────────────────────────────────
    abuse_confidence_score: Optional[int] = None
    abuse_total_reports: Optional[int] = None
    abuse_num_distinct_users: Optional[int] = None
    abuse_last_reported_at: Optional[datetime] = None
    abuse_usage_type: Optional[str] = None
    abuse_domain: Optional[str] = None
    abuse_is_whitelisted: Optional[bool] = None
    abuse_raw: Optional[dict] = None

    # ── VirusTotal ───────────────────────────────────────────────────────────
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_harmless: Optional[int] = None
    vt_undetected: Optional[int] = None
    vt_total_engines: Optional[int] = None
    vt_last_analysis_date: Optional[datetime] = None
    vt_tags: list[str] = field(default_factory=list)
    vt_community_score: Optional[int] = None
    vt_raw: Optional[dict] = None

    # ── Shodan ───────────────────────────────────────────────────────────────
    shodan_ports: list[int] = field(default_factory=list)
    shodan_vulns: list[str] = field(default_factory=list)
    shodan_hostnames: list[str] = field(default_factory=list)
    shodan_tags: list[str] = field(default_factory=list)
    shodan_os: Optional[str] = None
    shodan_last_update: Optional[datetime] = None
    shodan_raw: Optional[dict] = None

    # ── ip-api.com flags ─────────────────────────────────────────────────────
    ipapi_is_hosting: Optional[bool] = None
    ipapi_is_proxy: Optional[bool] = None

    # ── Composite scoring (set by IntelScorer) ───────────────────────────────
    threat_score: float = 0.0
    reputation: str = "unknown"

    # ── Metadata ─────────────────────────────────────────────────────────────
    providers_used: list[str] = field(default_factory=list)
    providers_failed: dict[str, str] = field(default_factory=dict)
    enriched_at: datetime = field(default_factory=datetime.utcnow)
    from_cache: bool = False
    lookup_duration_ms: Optional[float] = None

    # ── Serialization ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        d = asdict(self)
        for key, val in d.items():
            if isinstance(val, datetime):
                d[key] = val.isoformat()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: dict) -> "IntelResult":
        data = dict(data)
        geo_data = data.pop("geo", {}) or {}
        geo = GeoData(**{k: v for k, v in geo_data.items() if k in GeoData.__dataclass_fields__})

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

        known = set(cls.__dataclass_fields__.keys())
        data = {k: v for k, v in data.items() if k in known}
        return cls(geo=geo, **data)

    @classmethod
    def from_json(cls, raw: str) -> "IntelResult":
        return cls.from_dict(json.loads(raw))

    # ── Helpers ──────────────────────────────────────────────────────────────

    @property
    def is_anonymous(self) -> bool:
        return bool(self.is_tor or self.is_vpn or self.is_proxy)

    @property
    def has_known_vulns(self) -> bool:
        return len(self.shodan_vulns) > 0

    def summary_line(self) -> str:
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
            f"vt_mal={self.vt_malicious} "
            f"ports={len(self.shodan_ports)} vulns={len(self.shodan_vulns)}"
        )

    def to_api_response(self) -> dict:
        """Lightweight dict for API / WebSocket — no raw blobs."""
        return {
            "ip": self.ip,
            "threat_score": self.threat_score,
            "reputation": self.reputation,
            "geo": {
                "country_code": self.geo.country_code,
                "country_name": self.geo.country_name,
                "city": self.geo.city,
                "latitude": self.geo.latitude,
                "longitude": self.geo.longitude,
                "asn": self.geo.asn,
                "isp": self.geo.isp,
            },
            "flags": {
                "is_tor": self.is_tor,
                "is_vpn": self.is_vpn,
                "is_proxy": self.is_proxy,
                "is_datacenter": self.is_datacenter,
            },
            "abuse": {
                "confidence_score": self.abuse_confidence_score,
                "total_reports": self.abuse_total_reports,
            },
            "virustotal": {
                "malicious": self.vt_malicious,
                "suspicious": self.vt_suspicious,
                "community_score": self.vt_community_score,
            },
            "shodan": {
                "open_ports": self.shodan_ports,
                "vulnerabilities": self.shodan_vulns,
                "hostnames": self.shodan_hostnames,
            },
            "providers_used": self.providers_used,
            "providers_failed": self.providers_failed,
            "from_cache": self.from_cache,
            "enriched_at": self.enriched_at.isoformat() if self.enriched_at else None,
            "lookup_duration_ms": self.lookup_duration_ms,
        }
