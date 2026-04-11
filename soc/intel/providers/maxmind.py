"""
MaxMind provider — local GeoLite2-City + ASN MMDB lookup.

No API calls, no rate limits. Reads .mmdb from disk.
Gracefully unavailable when file is missing.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

from .base import BaseProvider

logger = logging.getLogger(__name__)

try:
    import geoip2.database
    import geoip2.errors
    _HAS_GEOIP2 = True
except ImportError:
    _HAS_GEOIP2 = False
    logger.warning("geoip2 not installed — MaxMind provider disabled")


class MaxMindProvider(BaseProvider):

    provider_name = "maxmind"

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._asn_path = os.path.join(os.path.dirname(db_path), "GeoLite2-ASN.mmdb")
        self._city_reader: Optional[Any] = None
        self._asn_reader: Optional[Any] = None
        self._ready = False

    @property
    def requires_api_key(self) -> bool:
        return False

    async def is_available(self) -> bool:
        if not _HAS_GEOIP2:
            return False
        if not os.path.isfile(self._db_path):
            logger.warning("maxmind db not found at %s", self._db_path)
            return False

        try:
            self._city_reader = geoip2.database.Reader(self._db_path)
            if os.path.isfile(self._asn_path):
                self._asn_reader = geoip2.database.Reader(self._asn_path)
            self._ready = True
            logger.info("maxmind db loaded from %s", self._db_path)
            return True
        except Exception as exc:
            logger.error("maxmind db open failed: %s", exc)
            return False

    async def enrich(self, ip: str) -> dict[str, Any]:
        if not self._ready or self._city_reader is None:
            return self._error("db_not_loaded")

        try:
            city = self._city_reader.city(ip)
        except geoip2.errors.AddressNotFoundError:
            return self._ok({
                "geo_source": "maxmind",
                "geo_country_code": None, "geo_country_name": None,
                "geo_city": None, "geo_region": None,
                "geo_postal_code": None, "geo_latitude": None,
                "geo_longitude": None, "geo_timezone": None,
                "geo_asn": None, "geo_asn_name": None,
                "geo_isp": None, "geo_org": None,
            })
        except Exception as exc:
            return self._error(f"lookup_failed: {exc}")

        result: dict[str, Any] = {
            "geo_source": "maxmind",
            "geo_country_code": city.country.iso_code,
            "geo_country_name": city.country.name,
            "geo_city": city.city.name,
            "geo_region": city.subdivisions.most_specific.name if city.subdivisions else None,
            "geo_postal_code": city.postal.code if city.postal else None,
            "geo_latitude": float(city.location.latitude) if city.location.latitude else None,
            "geo_longitude": float(city.location.longitude) if city.location.longitude else None,
            "geo_timezone": city.location.time_zone,
        }

        if self._asn_reader:
            try:
                asn = self._asn_reader.asn(ip)
                result["geo_asn"] = asn.autonomous_system_number
                result["geo_asn_name"] = asn.autonomous_system_organization
                result["geo_isp"] = asn.autonomous_system_organization
                result["geo_org"] = asn.autonomous_system_organization
            except Exception:
                result.update({"geo_asn": None, "geo_asn_name": None, "geo_isp": None, "geo_org": None})
        else:
            traits = city.traits
            result["geo_asn"] = getattr(traits, "autonomous_system_number", None)
            result["geo_asn_name"] = getattr(traits, "autonomous_system_organization", None)
            result["geo_isp"] = getattr(traits, "isp", None)
            result["geo_org"] = getattr(traits, "organization", None)

        return self._ok(result)

    def close(self) -> None:
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()
