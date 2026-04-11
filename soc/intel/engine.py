"""
IntelEngine — single entry point for IP intelligence lookups.

Flow per IP
───────────
1. Redis L1 cache check → hit: return immediately
2. Postgres L2 cache check → hit + not expired: return + warm L1
3. Run all active providers concurrently (asyncio.gather)
4. Merge flat dicts into IntelResult
5. IntelScorer.compute() → threat_score + reputation
6. L1 cache write (Redis, best-effort)
7. L2 persist (Postgres upsert)
8. Return IntelResult

Provider failures are isolated — one failing provider never blocks others.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from soc.config import get_soc_settings
from soc.intel.cache import IntelRedisCache
from soc.intel.persist import IntelPersist
from soc.intel.providers.base import BaseProvider
from soc.intel.providers.abuseipdb import AbuseIPDBProvider
from soc.intel.providers.virustotal import VirusTotalProvider
from soc.intel.providers.shodan import ShodanProvider
from soc.intel.providers.maxmind import MaxMindProvider
from soc.intel.providers.ipapi import IpApiProvider
from soc.intel.schemas import IntelResult, GeoData
from soc.intel.scorer import IntelScorer

logger = logging.getLogger(__name__)


class IntelEngine:
    """
    Orchestrates multi-provider IP enrichment with two-tier caching.

    Usage::

        engine = IntelEngine.from_settings()
        await engine.startup()

        result = await engine.lookup("185.220.101.45", session=db)
        print(result.summary_line())

        await engine.shutdown()
    """

    def __init__(
        self,
        providers: list[BaseProvider],
        cache: IntelRedisCache,
        persist: IntelPersist,
        scorer: IntelScorer,
    ) -> None:
        self._all_providers = providers
        self._active_providers: list[BaseProvider] = []
        self._cache = cache
        self._persist = persist
        self._scorer = scorer

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def from_settings(cls) -> "IntelEngine":
        settings = get_soc_settings()

        providers: list[BaseProvider] = [
            MaxMindProvider(db_path=settings.maxmind_db_path),
            IpApiProvider(),
            AbuseIPDBProvider(api_key=settings.abuseipdb_api_key),
            VirusTotalProvider(api_key=settings.virustotal_api_key),
            ShodanProvider(api_key=settings.shodan_api_key),
        ]

        cache = IntelRedisCache(
            redis_url=settings.redis_url,
            default_ttl=settings.cache_ttl_abuseipdb,
        )

        return cls(
            providers=providers,
            cache=cache,
            persist=IntelPersist(),
            scorer=IntelScorer(),
        )

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def startup(self) -> None:
        await self._cache.connect()

        self._active_providers = []
        for provider in self._all_providers:
            try:
                available = await provider.is_available()
            except Exception as exc:
                logger.warning(
                    "provider availability check failed: %s — %s",
                    provider.provider_name, exc,
                )
                available = False

            if available:
                self._active_providers.append(provider)
                logger.info("provider active: %s", provider.provider_name)
            else:
                logger.warning("provider skipped: %s", provider.provider_name)

        if not self._active_providers:
            logger.error("no intel providers available — all lookups will return empty results")

    async def shutdown(self) -> None:
        await self._cache.disconnect()
        for provider in self._all_providers:
            if hasattr(provider, "close"):
                provider.close()

    # ── Main API ─────────────────────────────────────────────────────────────

    async def lookup(
        self,
        ip: str,
        session: Optional[AsyncSession] = None,
        force_refresh: bool = False,
    ) -> IntelResult:
        """
        Fully enriched IP intelligence lookup with two-tier caching.

        Args:
            ip:            IPv4 or IPv6 address.
            session:       Optional DB session for L2 persist. If None, skip persist.
            force_refresh: Skip all caches and re-query providers.
        """
        start = time.monotonic()

        # ── L1: Redis cache ──
        if not force_refresh:
            cached = await self._cache.get(ip)
            if cached is not None:
                cached.lookup_duration_ms = round((time.monotonic() - start) * 1000, 2)
                return cached

        # ── L2: Postgres cache ──
        if not force_refresh and session is not None:
            db_record = await self._persist.get_by_ip(session, ip)
            if db_record is not None and not db_record.is_expired:
                intel = self._record_to_result(db_record)
                intel.from_cache = True
                intel.lookup_duration_ms = round((time.monotonic() - start) * 1000, 2)
                # Warm L1
                await self._cache.set(intel)
                return intel

        # ── Live lookup ──
        raw_results = await self._run_providers(ip)
        intel = self._merge(ip, raw_results)
        self._scorer.compute(intel)
        intel.lookup_duration_ms = round((time.monotonic() - start) * 1000, 2)

        # ── Write caches ──
        await self._cache.set(intel)
        if session is not None:
            await self._persist.upsert(session, intel)
            await session.commit()

        logger.info(
            "intel lookup complete: %s score=%.1f rep=%s providers=%s duration=%.0fms",
            ip, intel.threat_score, intel.reputation,
            intel.providers_used, intel.lookup_duration_ms,
        )

        return intel

    async def bulk_lookup(
        self,
        ips: list[str],
        session: Optional[AsyncSession] = None,
        max_concurrent: int = 5,
    ) -> list[IntelResult]:
        """
        Look up multiple IPs with concurrency control.
        Respects provider rate limits via semaphore.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def bounded_lookup(ip: str) -> IntelResult:
            async with semaphore:
                return await self.lookup(ip, session=session)

        return await asyncio.gather(*[bounded_lookup(ip) for ip in ips])

    # ── Internals ────────────────────────────────────────────────────────────

    async def _run_providers(self, ip: str) -> list[dict[str, Any]]:
        async def safe_enrich(provider: BaseProvider) -> dict[str, Any]:
            try:
                return await asyncio.wait_for(
                    provider.enrich(ip),
                    timeout=provider.timeout_seconds,
                )
            except asyncio.TimeoutError:
                return provider._error(f"timeout_after_{provider.timeout_seconds}s")
            except Exception as exc:
                return provider._error(str(exc))

        results = await asyncio.gather(
            *[safe_enrich(p) for p in self._active_providers],
            return_exceptions=False,
        )
        return list(results)

    def _merge(self, ip: str, results: list[dict[str, Any]]) -> IntelResult:
        intel = IntelResult(ip=ip, enriched_at=datetime.utcnow())

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

        # Geo priority: MaxMind > ip-api
        if maxmind_data and maxmind_data.get("geo_country_code") is not None:
            self._apply_geo(intel, maxmind_data)
        elif ipapi_data and ipapi_data.get("geo_country_code") is not None:
            self._apply_geo(intel, ipapi_data)

        # ip-api flags
        if ipapi_data:
            self._apply_ipapi_flags(intel, ipapi_data)

        # TOR resolution from multiple sources
        self._resolve_tor_flag(intel, results)

        return intel

    def _apply_geo(self, intel: IntelResult, d: dict[str, Any]) -> None:
        intel.geo = GeoData(
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

    def _apply_ipapi_flags(self, intel: IntelResult, d: dict[str, Any]) -> None:
        intel.ipapi_is_hosting = d.get("ipapi_is_hosting")
        intel.ipapi_is_proxy = d.get("ipapi_is_proxy")
        intel.is_mobile = d.get("ipapi_is_mobile")
        if d.get("ipapi_is_proxy"):
            intel.is_proxy = True
        if d.get("ipapi_is_hosting"):
            intel.is_datacenter = True

    def _apply_abuseipdb(self, intel: IntelResult, d: dict[str, Any]) -> None:
        intel.abuse_confidence_score = d.get("abuse_confidence_score")
        intel.abuse_total_reports = d.get("abuse_total_reports")
        intel.abuse_num_distinct_users = d.get("abuse_num_distinct_users")
        intel.abuse_last_reported_at = d.get("abuse_last_reported_at")
        intel.abuse_usage_type = d.get("abuse_usage_type")
        intel.abuse_domain = d.get("abuse_domain")
        intel.abuse_is_whitelisted = d.get("abuse_is_whitelisted")
        intel.abuse_raw = d.get("abuse_raw")

        # Supplement geo
        if not intel.geo.country_code and d.get("abuse_country_code"):
            intel.geo.country_code = d["abuse_country_code"]
        if not intel.geo.isp and d.get("abuse_isp"):
            intel.geo.isp = d["abuse_isp"]

    def _apply_virustotal(self, intel: IntelResult, d: dict[str, Any]) -> None:
        intel.vt_malicious = d.get("vt_malicious")
        intel.vt_suspicious = d.get("vt_suspicious")
        intel.vt_harmless = d.get("vt_harmless")
        intel.vt_undetected = d.get("vt_undetected")
        intel.vt_total_engines = d.get("vt_total_engines")
        intel.vt_last_analysis_date = d.get("vt_last_analysis_date")
        intel.vt_tags = d.get("vt_tags") or []
        intel.vt_community_score = d.get("vt_community_score")
        intel.vt_raw = d.get("vt_raw")

    def _apply_shodan(self, intel: IntelResult, d: dict[str, Any]) -> None:
        intel.shodan_ports = d.get("shodan_ports") or []
        intel.shodan_vulns = d.get("shodan_vulns") or []
        intel.shodan_hostnames = d.get("shodan_hostnames") or []
        intel.shodan_tags = d.get("shodan_tags") or []
        intel.shodan_os = d.get("shodan_os")
        intel.shodan_last_update = d.get("shodan_last_update")
        intel.shodan_raw = d.get("shodan_raw")

        # Supplement geo
        if not intel.geo.country_code and d.get("shodan_country_code"):
            intel.geo.country_code = d["shodan_country_code"]
        if not intel.geo.asn and d.get("shodan_asn"):
            asn_raw = str(d["shodan_asn"])
            try:
                intel.geo.asn = int(asn_raw.lstrip("AS"))
            except ValueError:
                pass
        if not intel.geo.isp and d.get("shodan_isp"):
            intel.geo.isp = d["shodan_isp"]

    def _resolve_tor_flag(self, intel: IntelResult, results: list[dict[str, Any]]) -> None:
        for result in results:
            if result.get("vt_is_tor_hint") or result.get("shodan_is_tor_hint"):
                intel.is_tor = True
                return

        tor_keywords = {"tor", "tor-exit", "tor-exit-node"}
        if tor_keywords & {t.lower() for t in (intel.shodan_tags or [])}:
            intel.is_tor = True
        if tor_keywords & {t.lower() for t in (intel.vt_tags or [])}:
            intel.is_tor = True

    def _record_to_result(self, record) -> IntelResult:
        """Convert IpIntelCache ORM record to IntelResult."""
        return IntelResult(
            ip=record.ip_address,
            geo=GeoData(
                country_code=record.country_code,
                country_name=record.country_name,
                city=record.city,
                latitude=record.latitude,
                longitude=record.longitude,
                asn=record.asn,
                isp=record.isp,
                org=record.org,
            ),
            is_tor=record.is_tor,
            is_vpn=record.is_vpn,
            is_proxy=record.is_proxy,
            is_datacenter=record.is_datacenter,
            abuse_confidence_score=record.abuse_confidence_score,
            abuse_total_reports=record.abuse_total_reports,
            abuse_last_reported_at=record.abuse_last_reported_at,
            abuse_usage_type=record.abuse_usage_type,
            abuse_raw=record.abuse_raw,
            vt_malicious=record.vt_malicious_votes,
            vt_suspicious=record.vt_suspicious_votes,
            vt_harmless=record.vt_harmless_votes,
            vt_undetected=record.vt_undetected_votes,
            vt_last_analysis_date=record.vt_last_analysis_at,
            vt_tags=record.vt_tags or [],
            vt_raw=record.vt_raw,
            shodan_ports=record.shodan_open_ports or [],
            shodan_vulns=record.shodan_vulnerabilities or [],
            shodan_hostnames=record.shodan_hostnames or [],
            shodan_tags=record.shodan_tags or [],
            shodan_last_update=record.shodan_last_seen,
            shodan_raw=record.shodan_raw,
            threat_score=record.threat_score,
            reputation=record.reputation,
            providers_used=record.providers_queried or [],
            enriched_at=record.last_lookup_at,
        )

    # ── Health ───────────────────────────────────────────────────────────────

    async def health(self) -> dict:
        return {
            "active_providers": [p.provider_name for p in self._active_providers],
            "skipped_providers": [
                p.provider_name for p in self._all_providers
                if p not in self._active_providers
            ],
            "cache_available": await self._cache.ping(),
        }
