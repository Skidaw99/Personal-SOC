"""
ShodanEnricher — Shodan InternetDB + Host API lookup.

Strategy
--------
1. InternetDB (https://internetdb.shodan.io/{ip}) — gratis, geen key,
   geeft ports, hostnames, vulns, tags, CPEs. Snel en ruim genoeg voor
   de meeste use cases.

2. Shodan Host API (/shodan/host/{ip}) — vereist API key, geeft uitgebreide
   banner data, OS, services, locatie. Wordt alleen gebruikt als
   SHODAN_API_KEY aanwezig is.

Als er geen API key is draait de enricher op InternetDB alleen.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from .base import BaseEnricher

logger = logging.getLogger(__name__)

_INTERNETDB_URL = "https://internetdb.shodan.io"
_HOST_API_URL = "https://api.shodan.io/shodan/host"


class ShodanEnricher(BaseEnricher):
    """
    Combines Shodan InternetDB (free, no key) with the full Host API
    (paid/free-tier key) when available.
    """

    provider_name = "shodan"
    timeout_seconds = 15.0

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key
        self._has_key = bool(api_key)

    async def is_available(self) -> bool:
        # Always available via InternetDB; Host API requires a key but we
        # degrade gracefully, so we never return False here.
        return True

    async def enrich(self, ip: str) -> dict[str, Any]:
        # Always query InternetDB — it's free and fast
        internetdb_data = await self._query_internetdb(ip)

        # Optionally enrich with Host API
        host_data: dict[str, Any] = {}
        if self._has_key:
            host_data = await self._query_host_api(ip)

        # Merge: Host API wins on overlap, InternetDB fills gaps
        merged = {**internetdb_data, **host_data}

        # Surface Tor indicator from Shodan tags
        tags = merged.get("shodan_tags") or []
        is_tor = any(t.lower() in ("tor", "tor-exit") for t in tags)

        merged["shodan_is_tor_hint"] = is_tor
        return self._ok(merged)

    # ── InternetDB ────────────────────────────────────────────────────────────

    async def _query_internetdb(self, ip: str) -> dict[str, Any]:
        url = f"{_INTERNETDB_URL}/{ip}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url)
        except httpx.TimeoutException:
            logger.warning("shodan_internetdb_timeout", ip=ip)
            return {}
        except Exception as exc:
            logger.warning("shodan_internetdb_error", ip=ip, error=str(exc))
            return {}

        if resp.status_code == 404:
            # IP not indexed by Shodan — common for residential IPs
            return {
                "shodan_ports": [],
                "shodan_vulns": [],
                "shodan_hostnames": [],
                "shodan_tags": [],
                "shodan_cpes": [],
            }

        if not resp.is_success:
            logger.warning("shodan_internetdb_http_error", ip=ip, status=resp.status_code)
            return {}

        try:
            d = resp.json()
        except Exception as exc:
            logger.warning("shodan_internetdb_parse_error", ip=ip, error=str(exc))
            return {}

        return {
            "shodan_ports": sorted(d.get("ports") or []),
            "shodan_vulns": list(d.get("vulns") or []),      # CVE-YYYY-NNNNN
            "shodan_hostnames": list(d.get("hostnames") or []),
            "shodan_tags": list(d.get("tags") or []),
            "shodan_cpes": list(d.get("cpes") or []),
        }

    # ── Host API ──────────────────────────────────────────────────────────────

    async def _query_host_api(self, ip: str) -> dict[str, Any]:
        url = f"{_HOST_API_URL}/{ip}"
        params = {"key": self._api_key, "minify": "true"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url, params=params)
        except httpx.TimeoutException:
            logger.warning("shodan_host_api_timeout", ip=ip)
            return {}
        except Exception as exc:
            logger.warning("shodan_host_api_error", ip=ip, error=str(exc))
            return {}

        if resp.status_code == 404:
            return {}  # Not indexed — InternetDB data is sufficient
        if resp.status_code == 401:
            logger.error("shodan_invalid_api_key")
            return {}
        if resp.status_code == 429:
            logger.warning("shodan_rate_limit_exceeded")
            return {}
        if not resp.is_success:
            logger.warning("shodan_host_api_http_error", status=resp.status_code)
            return {}

        try:
            d = resp.json()
        except Exception as exc:
            logger.warning("shodan_host_api_parse_error", ip=ip, error=str(exc))
            return {}

        # Parse last_update timestamp
        last_update: datetime | None = None
        raw_ts = d.get("last_update")
        if raw_ts:
            try:
                last_update = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                pass

        # Aggregate ports across all service banners
        ports_from_data: list[int] = [
            svc.get("port") for svc in d.get("data") or []
            if svc.get("port")
        ]

        return {
            "shodan_ports": sorted(set(d.get("ports") or ports_from_data)),
            "shodan_hostnames": list(d.get("hostnames") or []),
            "shodan_domains": list(d.get("domains") or []),
            "shodan_os": d.get("os"),
            "shodan_tags": list(d.get("tags") or []),
            "shodan_vulns": list(d.get("vulns", {}).keys()) if isinstance(d.get("vulns"), dict) else [],
            "shodan_last_update": last_update,
            # Geo from Shodan (supplement only)
            "shodan_country_code": d.get("country_code"),
            "shodan_city": d.get("city"),
            "shodan_asn": d.get("asn"),
            "shodan_isp": d.get("isp"),
            "shodan_org": d.get("org"),
        }
