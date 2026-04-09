"""
VirusTotalEnricher — VirusTotal v3 API IP address lookup.

API docs: https://developers.virustotal.com/reference/ip-info
Free tier: 4 lookups/min, 500/day.
Key: VIRUSTOTAL_API_KEY in .env

Returns engine vote counts (malicious/suspicious/harmless/undetected),
community reputation score, last analysis date, and tags.
"""
from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from .base import BaseEnricher

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalEnricher(BaseEnricher):
    """
    Queries VirusTotal /ip_addresses/{ip} and maps votes + metadata to
    ThreatIntelligence fields.
    """

    provider_name = "virustotal"
    timeout_seconds = 15.0   # VT can be slow

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def is_available(self) -> bool:
        if not self._api_key:
            logger.warning("virustotal_api_key_missing", hint="Set VIRUSTOTAL_API_KEY in .env")
            return False
        return True

    async def enrich(self, ip: str) -> dict[str, Any]:
        # VT v3 uses URL-safe base64 encoded ID for IPs
        # But for plain IPv4/IPv6 the ID is just the IP itself
        url = f"{_BASE_URL}/ip_addresses/{ip}"
        headers = {
            "x-apikey": self._api_key,
            "Accept": "application/json",
        }

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
            # IP not in VT database — not an error, just no data
            return self._ok({
                "vt_malicious": 0,
                "vt_suspicious": 0,
                "vt_harmless": 0,
                "vt_undetected": 0,
                "vt_total_engines": 0,
                "vt_last_analysis_date": None,
                "vt_tags": [],
                "vt_community_score": None,
            })
        if resp.status_code == 429:
            return self._error("rate_limit_exceeded — VT free: 4/min")
        if not resp.is_success:
            return self._error(f"http_{resp.status_code}")

        try:
            body = resp.json()
            attrs = body["data"]["attributes"]
        except Exception as exc:
            return self._error(f"parse_error: {exc}")

        # Vote counts from last_analysis_stats
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected

        # Last analysis timestamp (Unix epoch)
        last_ts: datetime | None = None
        raw_ts = attrs.get("last_analysis_date")
        if raw_ts:
            try:
                last_ts = datetime.fromtimestamp(int(raw_ts), tz=timezone.utc)
            except (ValueError, TypeError):
                pass

        # Community score: positive = reputable, negative = malicious
        community_score: int | None = attrs.get("reputation")

        # Tags from VT (e.g. "tor-exit-node", "scanner", "cdn")
        tags: list[str] = list(attrs.get("tags") or [])

        # VT sometimes marks TOR nodes explicitly
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
            # Surface TOR flag so engine.merge() can set is_tor
            "vt_is_tor_hint": is_tor,
        })
