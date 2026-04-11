"""
Shodan provider — InternetDB (free) + Host API (key optional).

InternetDB: https://internetdb.shodan.io/{ip} — no key, returns ports/vulns/tags.
Host API:   https://api.shodan.io/shodan/host/{ip} — requires key, full banner data.

Falls back to InternetDB-only when no API key is configured.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from .base import BaseProvider

logger = logging.getLogger(__name__)

_INTERNETDB_URL = "https://internetdb.shodan.io"
_HOST_API_URL = "https://api.shodan.io/shodan/host"


class ShodanProvider(BaseProvider):

    provider_name = "shodan"
    timeout_seconds = 15.0

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key
        self._has_key = bool(api_key)

    @property
    def requires_api_key(self) -> bool:
        return False  # InternetDB works without key

    async def is_available(self) -> bool:
        return True  # InternetDB is always available

    async def enrich(self, ip: str) -> dict[str, Any]:
        internetdb_data = await self._query_internetdb(ip)

        host_data: dict[str, Any] = {}
        if self._has_key:
            host_data = await self._query_host_api(ip)

        merged = {**internetdb_data, **host_data}

        tags = merged.get("shodan_tags") or []
        is_tor = any(t.lower() in ("tor", "tor-exit", "tor-exit-node") for t in tags)
        merged["shodan_is_tor_hint"] = is_tor

        return self._ok(merged)

    async def _query_internetdb(self, ip: str) -> dict[str, Any]:
        url = f"{_INTERNETDB_URL}/{ip}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url)
        except httpx.TimeoutException:
            logger.warning("shodan internetdb timeout ip=%s", ip)
            return {}
        except Exception as exc:
            logger.warning("shodan internetdb error ip=%s err=%s", ip, exc)
            return {}

        if resp.status_code == 404:
            return {
                "shodan_ports": [], "shodan_vulns": [],
                "shodan_hostnames": [], "shodan_tags": [], "shodan_cpes": [],
            }
        if not resp.is_success:
            return {}

        try:
            d = resp.json()
        except Exception:
            return {}

        return {
            "shodan_ports": sorted(d.get("ports") or []),
            "shodan_vulns": list(d.get("vulns") or []),
            "shodan_hostnames": list(d.get("hostnames") or []),
            "shodan_tags": list(d.get("tags") or []),
            "shodan_cpes": list(d.get("cpes") or []),
        }

    async def _query_host_api(self, ip: str) -> dict[str, Any]:
        url = f"{_HOST_API_URL}/{ip}"
        params = {"key": self._api_key, "minify": "true"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url, params=params)
        except httpx.TimeoutException:
            logger.warning("shodan host api timeout ip=%s", ip)
            return {}
        except Exception as exc:
            logger.warning("shodan host api error ip=%s err=%s", ip, exc)
            return {}

        if resp.status_code in (401, 404, 429) or not resp.is_success:
            return {}

        try:
            d = resp.json()
        except Exception:
            return {}

        last_update: datetime | None = None
        raw_ts = d.get("last_update")
        if raw_ts:
            try:
                last_update = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                pass

        ports_from_data = [
            svc.get("port") for svc in d.get("data") or [] if svc.get("port")
        ]

        vulns = []
        v = d.get("vulns")
        if isinstance(v, dict):
            vulns = list(v.keys())
        elif isinstance(v, list):
            vulns = v

        return {
            "shodan_ports": sorted(set(d.get("ports") or ports_from_data)),
            "shodan_hostnames": list(d.get("hostnames") or []),
            "shodan_os": d.get("os"),
            "shodan_tags": list(d.get("tags") or []),
            "shodan_vulns": vulns,
            "shodan_last_update": last_update,
            "shodan_country_code": d.get("country_code"),
            "shodan_city": d.get("city"),
            "shodan_asn": d.get("asn"),
            "shodan_isp": d.get("isp"),
            "shodan_org": d.get("org"),
            "shodan_raw": d,
        }
