"""
EnrichmentEngine — orkestreert alle IP intelligence enrichers.

Flow per IP lookup
──────────────────
1. Cache check  →  hit: return immediately
2. Availability check per enricher (eenmalig bij startup)
3. asyncio.gather() → alle beschikbare enrichers parallel
4. merge() → flat dicts samenvoegen tot ThreatIntelligence
5. scorer.compute() → threat_score + reputation
6. Cache write (best-effort)
7. Return ThreatIntelligence

Elke enricher heeft een individuele timeout. Uitval van één enricher
blokkeert de anderen niet — resultaat bevat dan een entry in providers_failed.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime
from typing import Any, Optional

from .abuseipdb import AbuseIPDBEnricher
from .base import BaseEnricher
from .cache import IntelCache
from .ipapi import IpApiEnricher
from .maxmind import MaxMindEnricher
from .models import GeoLocation, ThreatIntelligence
from .shodan import ShodanEnricher
from . import scorer
from .virustotal import VirusTotalEnricher

logger = logging.getLogger(__name__)

# Per-enricher timeout in seconds (overrides BaseEnricher.timeout_seconds when lower)
_GATHER_TIMEOUT = 20.0


class EnrichmentEngine:
    """
    Single entry point for IP intelligence enrichment.

    Usage::

        engine = EnrichmentEngine.from_env()
        await engine.startup()

        intel = await engine.enrich("185.220.101.45")
        print(intel.summary_line())

        await engine.shutdown()
    """

    def __init__(
        self,
        enrichers: list[BaseEnricher],
        cache: IntelCache,
    ) -> None:
        self._all_enrichers = enrichers
        self._active_enrichers: list[BaseEnricher] = []
        self._cache = cache

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "EnrichmentEngine":
        """
        Build an EnrichmentEngine from environment variables.
        Can be called before the async event loop starts.
        """
        enrichers: list[BaseEnricher] = [
            MaxMindEnricher(
                db_path=os.getenv("MAXMIND_DB_PATH", "/data/geoip/GeoLite2-City.mmdb")
            ),
            IpApiEnricher(),
            AbuseIPDBEnricher(
                api_key=os.getenv("ABUSEIPDB_API_KEY", "")
            ),
            VirusTotalEnricher(
                api_key=os.getenv("VIRUSTOTAL_API_KEY", "")
            ),
            ShodanEnricher(
                api_key=os.getenv("SHODAN_API_KEY", "")
            ),
        ]

        cache = IntelCache(
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
            default_ttl=int(os.getenv("INTEL_CACHE_TTL", "3600")),
        )

        return cls(enrichers=enrichers, cache=cache)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def startup(self) -> None:
        """
        Connect to Redis, probe each enricher's availability.
        Call this once at application startup.
        """
        await self._cache.connect()

        self._active_enrichers = []
        for enricher in self._all_enrichers:
            try:
                available = await enricher.is_available()
            except Exception as exc:
                logger.warning(
                    "enricher_availability_check_failed",
                    provider=enricher.provider_name,
                    error=str(exc),
                )
                available = False

            if available:
                self._active_enrichers.append(enricher)
                logger.info("enricher_active", provider=enricher.provider_name)
            else:
                logger.warning("enricher_skipped", provider=enricher.provider_name)

        if not self._active_enrichers:
            logger.error("no_enrichers_available — all lookups will return empty intel")

    async def shutdown(self) -> None:
        """Release resources. Call at application shutdown."""
        await self._cache.disconnect()
        for enricher in self._all_enrichers:
            if hasattr(enricher, "close"):
                enricher.close()

    # ── Main public API ────────────────────────────────────────────────────────

    async def enrich(self, ip: str, force_refresh: bool = False) -> ThreatIntelligence:
        """
        Return fully enriched ThreatIntelligence for the given IP.

        Args:
            ip:            IPv4 or IPv6 address string.
            force_refresh: Skip cache and re-query all providers.
        """
        # 1. Cache check
        if not force_refresh:
            cached = await self._cache.get(ip)
            if cached is not None:
                return cached

        # 2. Run all active enrichers concurrently
        raw_results = await self._run_enrichers(ip)

        # 3. Merge flat dicts into ThreatIntelligence
        intel = self._merge(ip, raw_results)

        # 4. Compute composite score
        scorer.compute(intel)

        # 5. Cache
        await self._cache.set(intel)

        return intel

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _run_enrichers(self, ip: str) -> list[dict[str, Any]]:
        """Run all active enrichers in parallel with individual timeout protection."""

        async def safe_enrich(enricher: BaseEnricher) -> dict[str, Any]:
            try:
                return await asyncio.wait_for(
                    enricher.enrich(ip),
                    timeout=enricher.timeout_seconds,
                )
            except asyncio.TimeoutError:
                return enricher._error(f"timeout_after_{enricher.timeout_seconds}s")
            except Exception as exc:
                return enricher._error(str(exc))

        results = await asyncio.gather(
            *[safe_enrich(e) for e in self._active_enrichers],
            return_exceptions=False,
        )
        return list(results)

    def _merge(self, ip: str, results: list[dict[str, Any]]) -> ThreatIntelligence:
        """
        Merge raw provider dicts into a ThreatIntelligence instance.

        Priority: MaxMind > ip-api.com for geo fields.
        Anonymization flags: True wins (OR across providers).
        """
        intel = ThreatIntelligence(ip=ip, enriched_at=datetime.utcnow())

        # Track which providers succeeded / failed
        geo_source: Optional[str] = None
        maxmind_data: dict[str, Any] = {}
        ipapi_data: dict[str, Any] = {}

        for result in results:
            provider = result.get("provider_name", "unknown")

            if "error" in result:
                intel.providers_failed[provider] = result["error"]
                continue

            intel.providers_used.append(provider)

            if provider == "maxmind":
                maxmind_data = result
            elif provider == "ipapi":
                ipapi_data = result
            elif provider == "abuseipdb":
                self._apply_abuseipdb(intel, result)
            elif provider == "virustotal":
                self._apply_virustotal(intel, result)
            elif provider == "shodan":
                self._apply_shodan(intel, result)

        # Geo priority: MaxMind → ip-api.com
        if maxmind_data and maxmind_data.get("geo_country_code") is not None:
            self._apply_geo(intel, maxmind_data)
            geo_source = "maxmind"
        elif ipapi_data and ipapi_data.get("geo_country_code") is not None:
            self._apply_geo(intel, ipapi_data)
            geo_source = "ipapi"

        # Anonymization flags from ip-api
        if ipapi_data:
            self._apply_ipapi_flags(intel, ipapi_data)

        # Surface TOR hints from VT and Shodan tags
        self._resolve_tor_flag(intel, results)

        return intel

    # ── Field applicators ──────────────────────────────────────────────────────

    def _apply_geo(self, intel: ThreatIntelligence, d: dict[str, Any]) -> None:
        intel.geo = GeoLocation(
            country_code=d.get("geo_country_code"),
            country_name=d.get("geo_country_name"),
            region=d.get("geo_region"),
            city=d.get("geo_city"),
            postal_code=d.get("geo_postal_code"),
            latitude=d.get("geo_latitude"),
            longitude=d.get("geo_longitude"),
            timezone=d.get("geo_timezone"),
            asn=d.get("geo_asn"),
            asn_name=d.get("geo_asn_name"),
            isp=d.get("geo_isp"),
            org=d.get("geo_org"),
        )

    def _apply_ipapi_flags(self, intel: ThreatIntelligence, d: dict[str, Any]) -> None:
        intel.ipapi_is_hosting = d.get("ipapi_is_hosting")
        intel.ipapi_is_proxy = d.get("ipapi_is_proxy")
        intel.is_mobile = d.get("ipapi_is_mobile")

        # ip-api proxy flag covers TOR, VPN, and open proxies
        if d.get("ipapi_is_proxy"):
            intel.is_proxy = True
        if d.get("ipapi_is_hosting"):
            intel.is_datacenter = True

    def _apply_abuseipdb(self, intel: ThreatIntelligence, d: dict[str, Any]) -> None:
        intel.abuse_confidence_score = d.get("abuse_confidence_score")
        intel.abuse_total_reports = d.get("abuse_total_reports")
        intel.abuse_num_distinct_users = d.get("abuse_num_distinct_users")
        intel.abuse_last_reported_at = d.get("abuse_last_reported_at")
        intel.abuse_usage_type = d.get("abuse_usage_type")
        intel.abuse_domain = d.get("abuse_domain")
        intel.abuse_is_whitelisted = d.get("abuse_is_whitelisted")

        # Supplement geo if not yet set
        if not intel.geo.country_code and d.get("abuse_country_code"):
            intel.geo.country_code = d["abuse_country_code"]
        if not intel.geo.isp and d.get("abuse_isp"):
            intel.geo.isp = d["abuse_isp"]

    def _apply_virustotal(self, intel: ThreatIntelligence, d: dict[str, Any]) -> None:
        intel.vt_malicious = d.get("vt_malicious")
        intel.vt_suspicious = d.get("vt_suspicious")
        intel.vt_harmless = d.get("vt_harmless")
        intel.vt_undetected = d.get("vt_undetected")
        intel.vt_total_engines = d.get("vt_total_engines")
        intel.vt_last_analysis_date = d.get("vt_last_analysis_date")
        intel.vt_tags = d.get("vt_tags") or []
        intel.vt_community_score = d.get("vt_community_score")

    def _apply_shodan(self, intel: ThreatIntelligence, d: dict[str, Any]) -> None:
        intel.shodan_ports = d.get("shodan_ports") or []
        intel.shodan_vulns = d.get("shodan_vulns") or []
        intel.shodan_hostnames = d.get("shodan_hostnames") or []
        intel.shodan_domains = d.get("shodan_domains") or []
        intel.shodan_tags = d.get("shodan_tags") or []
        intel.shodan_os = d.get("shodan_os")
        intel.shodan_last_update = d.get("shodan_last_update")

        # Supplement geo from Shodan if still missing
        if not intel.geo.country_code and d.get("shodan_country_code"):
            intel.geo.country_code = d["shodan_country_code"]
        if not intel.geo.asn and d.get("shodan_asn"):
            # Shodan returns "AS12345" string — strip prefix
            asn_raw = str(d["shodan_asn"])
            try:
                intel.geo.asn = int(asn_raw.lstrip("AS"))
            except ValueError:
                pass
        if not intel.geo.isp and d.get("shodan_isp"):
            intel.geo.isp = d["shodan_isp"]

    def _resolve_tor_flag(
        self, intel: ThreatIntelligence, results: list[dict[str, Any]]
    ) -> None:
        """
        Set intel.is_tor = True if any provider explicitly confirms it.
        We look at provider hint fields and tag lists.
        """
        for result in results:
            if result.get("vt_is_tor_hint") or result.get("shodan_is_tor_hint"):
                intel.is_tor = True
                return

        # Also check tags from already-merged data
        tor_keywords = {"tor", "tor-exit", "tor-exit-node"}
        if tor_keywords & set(t.lower() for t in (intel.shodan_tags or [])):
            intel.is_tor = True
        if tor_keywords & set(t.lower() for t in (intel.vt_tags or [])):
            intel.is_tor = True

    # ── Health ────────────────────────────────────────────────────────────────

    async def health(self) -> dict:
        return {
            "active_enrichers": [e.provider_name for e in self._active_enrichers],
            "skipped_enrichers": [
                e.provider_name
                for e in self._all_enrichers
                if e not in self._active_enrichers
            ],
            "cache_available": await self._cache.ping(),
        }
