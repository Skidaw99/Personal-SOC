"""
Evidence Builder — data schemas voor het evidence package.

EvidencePackage is de centrale datastructuur die alle informatie bevat
die nodig is om een compleet FBI-ready PDF rapport te genereren.
De collector vult dit package; de PDF generator leest het.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID


@dataclass
class IpEvidence:
    """Volledige IP intelligence data voor een betrokken IP-adres."""
    ip_address: str
    threat_score: float = 0.0
    reputation: str = "unknown"
    # Geo
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    # Anonymization
    is_tor: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_datacenter: bool = False
    # AbuseIPDB
    abuse_confidence: Optional[int] = None
    abuse_total_reports: Optional[int] = None
    abuse_last_reported: Optional[str] = None
    # VirusTotal
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_total_engines: Optional[int] = None
    # Shodan
    shodan_ports: list[int] = field(default_factory=list)
    shodan_vulns: list[str] = field(default_factory=list)
    shodan_hostnames: list[str] = field(default_factory=list)
    # Timestamps
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


@dataclass
class TimelineEntry:
    """Eén event in de incident tijdlijn."""
    timestamp: datetime
    event_type: str
    source_ip: Optional[str] = None
    severity: str = "medium"
    description: Optional[str] = None
    source: Optional[str] = None      # bijv. "social_fraud_detector"
    soc_event_id: Optional[str] = None


@dataclass
class ActorEvidence:
    """Threat actor profiel data voor het rapport."""
    actor_id: Optional[str] = None
    display_name: str = "Unknown"
    alias: Optional[str] = None
    threat_level: str = "medium"
    confidence_score: float = 0.0
    status: str = "active"
    total_events: int = 0
    # Observables
    known_ips: list[str] = field(default_factory=list)
    known_countries: list[str] = field(default_factory=list)
    attack_categories: list[str] = field(default_factory=list)
    platforms_targeted: list[str] = field(default_factory=list)
    typical_hours: list[int] = field(default_factory=list)
    # Flags
    is_tor: bool = False
    is_vpn: bool = False
    uses_automation: bool = False
    is_cross_platform: bool = False
    # Timestamps
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    # Analyst
    analyst_notes: Optional[str] = None
    tags: list[str] = field(default_factory=list)


@dataclass
class PlatformEvidence:
    """Platform bewijsmateriaal — API logs, screenshots, etc."""
    platform: str                          # bijv. "twitter", "instagram"
    evidence_type: str                     # "api_log", "screenshot", "export"
    description: str
    collected_at: datetime = field(default_factory=datetime.utcnow)
    reference_path: Optional[str] = None   # bestandspad of URL
    data: Optional[dict] = None            # gestructureerde API response data


@dataclass
class ResponseActionEvidence:
    """Audit record van een uitgevoerde response actie."""
    action_type: str
    status: str
    target: Optional[str] = None
    executed_at: Optional[str] = None
    duration_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class LegalReference:
    """Verwijzing naar een relevant wetsartikel."""
    jurisdiction: str          # "US" of "EU"
    statute: str               # bijv. "18 U.S.C. § 1030"
    name: str                  # bijv. "Computer Fraud and Abuse Act"
    section: Optional[str] = None
    relevance: str = ""        # waarom dit artikel van toepassing is


@dataclass
class EvidencePackage:
    """
    Compleet evidence package — input voor de PDF generator.

    Bevat alle data die nodig is om een FBI IC3-ready rapport te genereren.
    """

    # ── Case metadata ────────────────────────────────────────────────────────
    case_id: str
    case_title: str
    classification: str = "TLP:AMBER"
    report_date: datetime = field(default_factory=datetime.utcnow)
    analyst_name: str = "SOC Automated System"
    organization: str = "SOC Security Operations Center"

    # ── Incident samenvatting ────────────────────────────────────────────────
    incident_type: str = "unknown"
    incident_date: Optional[datetime] = None
    executive_summary: str = ""
    risk_score: float = 0.0
    severity: str = "medium"

    # ── Evidence secties ─────────────────────────────────────────────────────
    timeline: list[TimelineEntry] = field(default_factory=list)
    ip_evidence: list[IpEvidence] = field(default_factory=list)
    actor: Optional[ActorEvidence] = None
    platform_evidence: list[PlatformEvidence] = field(default_factory=list)
    response_actions: list[ResponseActionEvidence] = field(default_factory=list)
    legal_references: list[LegalReference] = field(default_factory=list)

    # ── IOCs ─────────────────────────────────────────────────────────────────
    ioc_ips: list[str] = field(default_factory=list)
    ioc_domains: list[str] = field(default_factory=list)
    ioc_hashes: list[str] = field(default_factory=list)
    ioc_urls: list[str] = field(default_factory=list)

    # ── Chain of custody ─────────────────────────────────────────────────────
    chain_of_custody: list[dict] = field(default_factory=list)
