"""
IpApiEnricher — gratis geo + proxy/hosting lookup via ip-api.com.

Geen API key nodig. Rate limit: 45 requests/min op de free HTTP endpoint.
Gebruikt als primaire geo-fallback wanneer MaxMind DB niet aanwezig is,
en als secundaire bron voor is_proxy / is_hosting flags.

Endpoint: http://ip-api.com/json/{ip}?fields=...
Note: HTTPS vereist een betaald plan. HTTP is voldoende voor intern gebruik
      achter een VPN/Hetzner private network.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from .base import BaseEnricher

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


class IpApiEnricher(BaseEnricher):
    """
    ip-api.com free-tier enricher.

    Provides: geo, ISP/ASN, is_proxy, is_datacenter (hosting flag), is_mobile.
    """

    provider_name = "ipapi"
    requires_api_key = False

    async def is_available(self) -> bool:
        # Always available — no key, no local file
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
            # ip-api returns {"status":"fail","message":"..."} for private IPs etc.
            msg = data.get("message", "unknown_failure")
            return self._ok({
                "ipapi_status": "fail",
                "ipapi_message": msg,
                "ipapi_is_hosting": None,
                "ipapi_is_proxy": None,
                "ipapi_is_mobile": None,
                # Geo fields stay None — MaxMind or other provider covers them
                "geo_source": None,
            })

        # Parse ASN number from "AS##### Organization Name" string
        asn_raw: str = data.get("as", "") or ""
        asn_number: int | None = None
        if asn_raw.startswith("AS"):
            try:
                asn_number = int(asn_raw.split(" ")[0][2:])
            except ValueError:
                pass

        result: dict[str, Any] = {
            "ipapi_status": "success",
            "ipapi_is_hosting": data.get("hosting"),    # bool or None
            "ipapi_is_proxy": data.get("proxy"),        # bool — covers TOR/VPN/proxy
            "ipapi_is_mobile": data.get("mobile"),

            # Geo — used as fallback when MaxMind DB is absent
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
        }

        return self._ok(result)
