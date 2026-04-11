"""
IntelPersist — L2 persistence to soc_ip_intel_cache (PostgreSQL).

Upserts IntelResult into the IpIntelCache ORM model.
Used after every fresh lookup (not cache hits).
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc.intel.schemas import IntelResult
from soc.models.ip_intel import IpIntelCache, IpReputationCategory

logger = logging.getLogger(__name__)

# Default expiry: 4 hours from last lookup
_DEFAULT_EXPIRY_HOURS = 4


class IntelPersist:
    """Upserts IntelResult → soc_ip_intel_cache."""

    async def upsert(self, session: AsyncSession, intel: IntelResult) -> IpIntelCache:
        """
        Insert or update the IP intel cache record.
        Returns the ORM instance.
        """
        stmt = select(IpIntelCache).where(IpIntelCache.ip_address == intel.ip)
        result = await session.execute(stmt)
        record = result.scalar_one_or_none()

        now = datetime.utcnow()
        expires = now + timedelta(hours=_DEFAULT_EXPIRY_HOURS)

        if record is None:
            record = IpIntelCache(
                ip_address=intel.ip,
                first_seen_at=now,
                lookup_count=1,
            )
            session.add(record)
        else:
            record.lookup_count = (record.lookup_count or 0) + 1

        # Scoring
        record.threat_score = intel.threat_score
        record.reputation = intel.reputation

        # Geo
        record.country_code = intel.geo.country_code
        record.country_name = intel.geo.country_name
        record.city = intel.geo.city
        record.latitude = intel.geo.latitude
        record.longitude = intel.geo.longitude
        record.asn = intel.geo.asn
        record.isp = intel.geo.isp
        record.org = intel.geo.org

        # Anonymization flags
        record.is_tor = intel.is_tor or False
        record.is_vpn = intel.is_vpn or False
        record.is_proxy = intel.is_proxy or False
        record.is_datacenter = intel.is_datacenter or False

        # AbuseIPDB
        record.abuse_confidence_score = intel.abuse_confidence_score
        record.abuse_total_reports = intel.abuse_total_reports
        record.abuse_last_reported_at = intel.abuse_last_reported_at
        record.abuse_usage_type = intel.abuse_usage_type
        record.abuse_raw = intel.abuse_raw

        # VirusTotal
        record.vt_malicious_votes = intel.vt_malicious
        record.vt_suspicious_votes = intel.vt_suspicious
        record.vt_harmless_votes = intel.vt_harmless
        record.vt_undetected_votes = intel.vt_undetected
        record.vt_last_analysis_at = intel.vt_last_analysis_date
        record.vt_tags = intel.vt_tags or []
        record.vt_raw = intel.vt_raw

        # Shodan
        record.shodan_open_ports = intel.shodan_ports or []
        record.shodan_vulnerabilities = intel.shodan_vulns or []
        record.shodan_hostnames = intel.shodan_hostnames or []
        record.shodan_tags = intel.shodan_tags or []
        record.shodan_last_seen = intel.shodan_last_update
        record.shodan_raw = intel.shodan_raw

        # Metadata
        record.providers_queried = intel.providers_used
        record.last_lookup_at = now
        record.expires_at = expires

        await session.flush()
        return record

    async def get_by_ip(self, session: AsyncSession, ip: str) -> Optional[IpIntelCache]:
        """Fetch cached record from Postgres (L2 cache)."""
        stmt = select(IpIntelCache).where(IpIntelCache.ip_address == ip)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_expired(self, session: AsyncSession, limit: int = 50) -> list[IpIntelCache]:
        """Find expired records for background refresh."""
        now = datetime.utcnow()
        stmt = (
            select(IpIntelCache)
            .where(IpIntelCache.expires_at < now)
            .order_by(IpIntelCache.threat_score.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def get_top_threats(self, session: AsyncSession, limit: int = 20) -> list[IpIntelCache]:
        """Get highest-scoring IPs for the dashboard leaderboard."""
        stmt = (
            select(IpIntelCache)
            .order_by(IpIntelCache.threat_score.desc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
