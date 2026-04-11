"""
ip-api.com provider — free geo + proxy/hosting lookup.

No API key needed. Rate limit: 45 requests/min (HTTP only on free tier).
Used as geo fallback when MaxMind is unavailable,
and as supplementary proxy/hosting flag source.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from .base import BaseProvider

logger = logging.getLogger(__name__)

_FIELDS = (
    "status,message,"
    "country,countryCode,region,regionName,city,zip,"
    "lat,lon,timezone,"
    "isp,org,as,asname,"
    "hosting,proxy,mobile,"
    "query"
)
_BASE_URL = "http://ip-api.com/json"


class IpApiProvider(BaseProvider):

    provider_name = "ipapi"

    @property
    def requires_api_key(self) -> bool:
        return False

    async def is_available(self) -> bool:
        return True

    async def enrich(self, ip: str) -> dict[str, Any]:
        url = f"{_BASE_URL}/{ip}"
        params = {"fields": _FIELDS}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return self._error("request_timeout")
        except httpx.HTTPStatusError as exc:
            return self._error(f"http_{exc.response.status_code}")
        except Exception as exc:
            return self._error(str(exc))

        if data.get("status") != "success":
            return self._ok({
                "ipapi_status": "fail",
                "ipapi_message": data.get("message", "unknown"),
                "ipapi_is_hosting": None,
                "ipapi_is_proxy": None,
                "ipapi_is_mobile": None,
                "geo_source": None,
            })

        # Parse ASN from "AS12345 Organization" string
        asn_raw: str = data.get("as", "") or ""
        asn_number: int | None = None
        if asn_raw.startswith("AS"):
            try:
                asn_number = int(asn_raw.split(" ")[0][2:])
            except ValueError:
                pass

        return self._ok({
            "ipapi_status": "success",
            "ipapi_is_hosting": data.get("hosting"),
            "ipapi_is_proxy": data.get("proxy"),
            "ipapi_is_mobile": data.get("mobile"),
            "geo_source": "ipapi",
            "geo_country_code": data.get("countryCode"),
            "geo_country_name": data.get("country"),
            "geo_region": data.get("regionName"),
            "geo_city": data.get("city"),
            "geo_postal_code": data.get("zip"),
            "geo_latitude": data.get("lat"),
            "geo_longitude": data.get("lon"),
            "geo_timezone": data.get("timezone"),
            "geo_isp": data.get("isp"),
            "geo_org": data.get("org"),
            "geo_asn": asn_number,
            "geo_asn_name": data.get("asname"),
        })
