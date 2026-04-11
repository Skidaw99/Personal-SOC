"""
VirusTotal provider — v3 /ip_addresses endpoint.

Free tier: 4 lookups/min, 500/day.
Returns engine vote counts, community reputation, tags.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from .base import BaseProvider

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(BaseProvider):

    provider_name = "virustotal"
    timeout_seconds = 15.0

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def is_available(self) -> bool:
        if not self._api_key:
            logger.warning("virustotal: no API key configured")
            return False
        return True

    async def enrich(self, ip: str) -> dict[str, Any]:
        url = f"{_BASE_URL}/ip_addresses/{ip}"
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url, headers=headers)
        except httpx.TimeoutException:
            return self._error("request_timeout")
        except Exception as exc:
            return self._error(str(exc))

        if resp.status_code == 401:
            return self._error("invalid_api_key")
        if resp.status_code == 404:
            return self._ok({
                "vt_malicious": 0, "vt_suspicious": 0,
                "vt_harmless": 0, "vt_undetected": 0,
                "vt_total_engines": 0, "vt_last_analysis_date": None,
                "vt_tags": [], "vt_community_score": None, "vt_raw": None,
            })
        if resp.status_code == 429:
            return self._error("rate_limit_exceeded")
        if not resp.is_success:
            return self._error(f"http_{resp.status_code}")

        try:
            body = resp.json()
            attrs = body["data"]["attributes"]
        except Exception as exc:
            return self._error(f"parse_error: {exc}")

        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected

        last_ts: datetime | None = None
        raw_ts = attrs.get("last_analysis_date")
        if raw_ts:
            try:
                last_ts = datetime.fromtimestamp(int(raw_ts), tz=timezone.utc)
            except (ValueError, TypeError):
                pass

        community_score: int | None = attrs.get("reputation")
        tags: list[str] = list(attrs.get("tags") or [])
        is_tor = any("tor" in tag.lower() for tag in tags)

        return self._ok({
            "vt_malicious": malicious,
            "vt_suspicious": suspicious,
            "vt_harmless": harmless,
            "vt_undetected": undetected,
            "vt_total_engines": total,
            "vt_last_analysis_date": last_ts,
            "vt_tags": tags,
            "vt_community_score": community_score,
            "vt_is_tor_hint": is_tor,
            "vt_raw": body.get("data"),
        })
