"""
AbuseIPDBEnricher — AbuseIPDB v2 API lookup.

API docs: https://docs.abuseipdb.com/#check-endpoint
Free tier: 1 000 checks/day, max lookupDays=30.
Key: ABUSEIPDB_API_KEY in .env

Returns confidence score 0-100, total report count, last reported timestamp,
usage type, domain, and whitelist status.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from .base import BaseEnricher

logger = logging.getLogger(__name__)

_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
# Use 90-day window for maximum signal — free tier allows up to 30 d;
# if you have a paid plan use 365. We detect the 422 and fall back.
_LOOKUP_DAYS = 30


class AbuseIPDBEnricher(BaseEnricher):
    """
    Queries AbuseIPDB /check endpoint and maps the response to
    ThreatIntelligence fields.
    """

    provider_name = "abuseipdb"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def is_available(self) -> bool:
        if not self._api_key:
            logger.warning("abuseipdb_api_key_missing", hint="Set ABUSEIPDB_API_KEY in .env")
            return False
        return True

    async def enrich(self, ip: str) -> dict[str, Any]:
        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": _LOOKUP_DAYS,
            "verbose": "",      # include individual report details (free tier)
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(_CHECK_URL, headers=headers, params=params)
        except httpx.TimeoutException:
            return self._error("request_timeout")
        except Exception as exc:
            return self._error(str(exc))

        if resp.status_code == 401:
            return self._error("invalid_api_key")
        if resp.status_code == 429:
            return self._error("rate_limit_exceeded")
        if resp.status_code == 422:
            return self._error("invalid_ip_or_params")
        if not resp.is_success:
            return self._error(f"http_{resp.status_code}")

        try:
            body = resp.json()
            d = body["data"]
        except Exception as exc:
            return self._error(f"parse_error: {exc}")

        # Parse last-reported timestamp
        last_reported_at: datetime | None = None
        raw_ts = d.get("lastReportedAt")
        if raw_ts:
            try:
                # AbuseIPDB returns ISO 8601 with timezone e.g. "2024-01-15T14:22:00+00:00"
                last_reported_at = datetime.fromisoformat(raw_ts)
            except ValueError:
                pass

        return self._ok({
            "abuse_confidence_score": int(d.get("abuseConfidenceScore", 0)),
            "abuse_total_reports": int(d.get("totalReports", 0)),
            "abuse_num_distinct_users": int(d.get("numDistinctUsers", 0)),
            "abuse_last_reported_at": last_reported_at,
            "abuse_usage_type": d.get("usageType"),
            "abuse_domain": d.get("domain"),
            "abuse_is_whitelisted": bool(d.get("isWhitelisted", False)),
            # AbuseIPDB also returns country code — supplement geo if needed
            "abuse_country_code": d.get("countryCode"),
            "abuse_isp": d.get("isp"),
        })
