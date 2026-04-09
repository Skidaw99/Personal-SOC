"""
Evidence Collector — verzamelt alle data uit de database voor een evidence package.

Haalt op:
  - SocSecurityEvents (incident tijdlijn)
  - IpIntelCache (volledige enrichment per IP)
  - ThreatActor + ActorIps + ActorEvents (actor profiel)
  - ResponseDecisions + ResponseActions (audit trail)

Bouwt een compleet EvidencePackage dat direct aan de PDF generator
kan worden doorgegeven.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .config import evidence_settings
from .legal import get_legal_references
from .schemas import (
    ActorEvidence,
    EvidencePackage,
    IpEvidence,
    PlatformEvidence,
    ResponseActionEvidence,
    TimelineEntry,
)

logger = logging.getLogger(__name__)


class EvidenceCollector:
    """
    Verzamelt alle evidence data uit de database.

    Usage::

        async with AsyncSessionLocal() as session:
            collector = EvidenceCollector(session)
            package = await collector.collect_for_actor(actor_id, case_id="SOC-2026-001")
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def collect_for_actor(
        self,
        actor_id: uuid.UUID,
        case_id: str,
        analyst_name: Optional[str] = None,
    ) -> EvidencePackage:
        """
        Verzamel een compleet evidence package voor een threat actor.

        Haalt de actor, alle geattribueerde events, IP intel,
        en response acties op.
        """
        # ── 1. Threat actor ophalen ──────────────────────────────────────────
        actor_data = await self._collect_actor(actor_id)

        # ── 2. Events ophalen (tijdlijn) ─────────────────────────────────────
        timeline, event_ips, soc_event_ids = await self._collect_events(actor_id)

        # ── 3. IP intelligence ophalen ───────────────────────────────────────
        ip_evidence = await self._collect_ip_intel(event_ips)

        # ── 4. Response acties ophalen ───────────────────────────────────────
        response_actions = await self._collect_response_actions(soc_event_ids)

        # ── 5. Legal references ──────────────────────────────────────────────
        incident_type = ""
        if timeline:
            incident_type = timeline[0].event_type
        legal_refs = get_legal_references(incident_type)

        # ── 6. IOCs extraheren ───────────────────────────────────────────────
        ioc_ips = sorted(event_ips)
        ioc_domains = []
        for ip_ev in ip_evidence:
            ioc_domains.extend(ip_ev.shodan_hostnames)
        ioc_domains = sorted(set(ioc_domains))

        # ── 7. Package samenstellen ──────────────────────────────────────────
        actor_name = actor_data.display_name if actor_data else "Unknown"
        first_event = min((t.timestamp for t in timeline), default=datetime.utcnow())

        package = EvidencePackage(
            case_id=case_id,
            case_title=f"Threat Actor Investigation: {actor_name}",
            classification=evidence_settings.evidence_classification,
            report_date=datetime.utcnow(),
            analyst_name=analyst_name or evidence_settings.evidence_analyst_name,
            organization=evidence_settings.evidence_org_name,
            incident_type=incident_type,
            incident_date=first_event,
            risk_score=actor_data.confidence_score if actor_data else 0.0,
            severity=(actor_data.threat_level if actor_data else "medium"),
            timeline=sorted(timeline, key=lambda t: t.timestamp),
            ip_evidence=ip_evidence,
            actor=actor_data,
            response_actions=response_actions,
            legal_references=legal_refs,
            ioc_ips=ioc_ips,
            ioc_domains=ioc_domains,
            chain_of_custody=[
                {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "action": "Evidence package generated",
                    "actor": analyst_name or evidence_settings.evidence_analyst_name,
                    "system": "SOC Security Orchestrator — Evidence Builder",
                    "integrity": "Automated collection from immutable audit trail",
                },
            ],
        )

        # Generate executive summary
        package.executive_summary = self._build_executive_summary(package)

        logger.info(
            "evidence_collected",
            case_id=case_id,
            actor=actor_name,
            timeline_entries=len(timeline),
            ips=len(ip_evidence),
            response_actions=len(response_actions),
        )

        return package

    async def collect_for_event(
        self,
        soc_event_id: uuid.UUID,
        case_id: str,
        analyst_name: Optional[str] = None,
    ) -> EvidencePackage:
        """
        Verzamel een evidence package voor een enkel incident (event).

        Handig voor standalone incidenten die niet aan een actor zijn gekoppeld.
        """
        from soc.models.security_event import SocSecurityEvent

        result = await self._session.execute(
            select(SocSecurityEvent).where(SocSecurityEvent.id == soc_event_id)
        )
        event = result.scalar_one_or_none()

        if event is None:
            logger.warning("evidence_event_not_found", soc_event_id=str(soc_event_id))
            return EvidencePackage(
                case_id=case_id,
                case_title=f"Incident Investigation: {soc_event_id}",
                analyst_name=analyst_name or evidence_settings.evidence_analyst_name,
            )

        # Als het event aan een actor is gekoppeld, delegeer naar collect_for_actor
        if event.threat_actor_id:
            return await self.collect_for_actor(
                event.threat_actor_id, case_id, analyst_name
            )

        # Standalone event
        timeline = [
            TimelineEntry(
                timestamp=event.occurred_at,
                event_type=event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type),
                source_ip=event.source_ip,
                severity=event.severity.value if hasattr(event.severity, 'value') else str(event.severity),
                description=event.description,
                source=event.source.value if hasattr(event.source, 'value') else str(event.source),
                soc_event_id=str(event.id),
            )
        ]

        ip_evidence = []
        if event.source_ip:
            ip_evidence = await self._collect_ip_intel({event.source_ip})

        response_actions = await self._collect_response_actions({event.id})
        incident_type = event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type)
        legal_refs = get_legal_references(incident_type)

        package = EvidencePackage(
            case_id=case_id,
            case_title=f"Incident Report: {incident_type} — {event.source_ip or 'N/A'}",
            classification=evidence_settings.evidence_classification,
            report_date=datetime.utcnow(),
            analyst_name=analyst_name or evidence_settings.evidence_analyst_name,
            organization=evidence_settings.evidence_org_name,
            incident_type=incident_type,
            incident_date=event.occurred_at,
            risk_score=event.threat_score or event.raw_risk_score,
            severity=event.severity.value if hasattr(event.severity, 'value') else str(event.severity),
            timeline=timeline,
            ip_evidence=ip_evidence,
            response_actions=response_actions,
            legal_references=legal_refs,
            ioc_ips=[event.source_ip] if event.source_ip else [],
            chain_of_custody=[
                {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "action": "Evidence package generated",
                    "actor": analyst_name or evidence_settings.evidence_analyst_name,
                    "system": "SOC Security Orchestrator — Evidence Builder",
                },
            ],
        )
        package.executive_summary = self._build_executive_summary(package)
        return package

    # ── Internal collectors ──────────────────────────────────────────────────

    async def _collect_actor(
        self, actor_id: uuid.UUID
    ) -> Optional[ActorEvidence]:
        """Haal threat actor profiel op."""
        from security_orchestrator.correlation.models import ThreatActor

        result = await self._session.execute(
            select(ThreatActor)
            .where(ThreatActor.id == actor_id)
            .options(selectinload(ThreatActor.ips))
        )
        actor = result.scalar_one_or_none()

        if actor is None:
            return None

        return ActorEvidence(
            actor_id=str(actor.id),
            display_name=actor.display_name,
            alias=actor.alias,
            threat_level=actor.threat_level.value,
            confidence_score=actor.confidence_score,
            status=actor.status.value,
            total_events=actor.total_events,
            known_ips=list(actor.known_ips or []),
            known_countries=list(actor.known_countries or []),
            attack_categories=list(actor.attack_categories or []),
            platforms_targeted=list(actor.platforms_targeted or []),
            typical_hours=list(actor.typical_hours or []),
            is_tor=bool(actor.is_tor),
            is_vpn=bool(actor.is_vpn),
            uses_automation=bool(actor.uses_automation),
            is_cross_platform=actor.is_cross_platform,
            first_seen=actor.first_seen_at.isoformat() if actor.first_seen_at else None,
            last_seen=actor.last_seen_at.isoformat() if actor.last_seen_at else None,
            analyst_notes=actor.analyst_notes,
            tags=list(actor.tags or []),
        )

    async def _collect_events(
        self, actor_id: uuid.UUID
    ) -> tuple[list[TimelineEntry], set[str], set[uuid.UUID]]:
        """
        Haal alle events op die aan deze actor zijn geattribueerd.

        Returns:
            (timeline_entries, unique_ips, soc_event_ids)
        """
        from soc.models.security_event import SocSecurityEvent

        result = await self._session.execute(
            select(SocSecurityEvent)
            .where(SocSecurityEvent.threat_actor_id == actor_id)
            .order_by(SocSecurityEvent.occurred_at.asc())
        )
        events = result.scalars().all()

        timeline: list[TimelineEntry] = []
        ips: set[str] = set()
        event_ids: set[uuid.UUID] = set()

        for ev in events:
            timeline.append(TimelineEntry(
                timestamp=ev.occurred_at,
                event_type=ev.event_type.value if hasattr(ev.event_type, 'value') else str(ev.event_type),
                source_ip=ev.source_ip,
                severity=ev.severity.value if hasattr(ev.severity, 'value') else str(ev.severity),
                description=ev.description,
                source=ev.source.value if hasattr(ev.source, 'value') else str(ev.source),
                soc_event_id=str(ev.id),
            ))
            if ev.source_ip:
                ips.add(ev.source_ip)
            event_ids.add(ev.id)

        return timeline, ips, event_ids

    async def _collect_ip_intel(self, ips: set[str]) -> list[IpEvidence]:
        """Haal IP intelligence op voor alle betrokken IP-adressen."""
        if not ips:
            return []

        from soc.models.ip_intel import IpIntelCache

        result = await self._session.execute(
            select(IpIntelCache).where(IpIntelCache.ip_address.in_(list(ips)))
        )
        records = result.scalars().all()

        evidence: list[IpEvidence] = []
        found_ips = set()

        for rec in records:
            found_ips.add(rec.ip_address)
            evidence.append(IpEvidence(
                ip_address=rec.ip_address,
                threat_score=rec.threat_score,
                reputation=rec.reputation,
                country_code=rec.country_code,
                country_name=rec.country_name,
                city=rec.city,
                latitude=rec.latitude,
                longitude=rec.longitude,
                asn=rec.asn,
                isp=rec.isp,
                org=rec.org,
                is_tor=bool(rec.is_tor),
                is_vpn=bool(rec.is_vpn),
                is_proxy=bool(rec.is_proxy),
                is_datacenter=bool(rec.is_datacenter),
                abuse_confidence=rec.abuse_confidence_score,
                abuse_total_reports=rec.abuse_total_reports,
                abuse_last_reported=(
                    rec.abuse_last_reported_at.isoformat()
                    if rec.abuse_last_reported_at else None
                ),
                vt_malicious=rec.vt_malicious_votes,
                vt_suspicious=rec.vt_suspicious_votes,
                vt_total_engines=(
                    (rec.vt_malicious_votes or 0)
                    + (rec.vt_suspicious_votes or 0)
                    + (rec.vt_harmless_votes or 0)
                    + (rec.vt_undetected_votes or 0)
                ) or None,
                shodan_ports=list(rec.shodan_open_ports or []),
                shodan_vulns=list(rec.shodan_vulnerabilities or []),
                shodan_hostnames=list(rec.shodan_hostnames or []),
                first_seen=(
                    rec.first_seen_at.isoformat() if rec.first_seen_at else None
                ),
                last_seen=(
                    rec.last_lookup_at.isoformat() if rec.last_lookup_at else None
                ),
            ))

        # IPs zonder intel record toch opnemen (met minimale data)
        for ip in ips - found_ips:
            evidence.append(IpEvidence(ip_address=ip))

        return sorted(evidence, key=lambda e: e.threat_score, reverse=True)

    async def _collect_response_actions(
        self, soc_event_ids: set[uuid.UUID]
    ) -> list[ResponseActionEvidence]:
        """Haal response audit trail op voor de betrokken events."""
        if not soc_event_ids:
            return []

        from security_orchestrator.response.models import (
            ResponseAction,
            ResponseDecision,
        )

        result = await self._session.execute(
            select(ResponseAction)
            .join(ResponseDecision)
            .where(ResponseDecision.soc_event_id.in_(list(soc_event_ids)))
            .order_by(ResponseAction.created_at.asc())
        )
        actions = result.scalars().all()

        return [
            ResponseActionEvidence(
                action_type=a.action_type.value if hasattr(a.action_type, 'value') else str(a.action_type),
                status=a.status.value if hasattr(a.status, 'value') else str(a.status),
                target=a.target,
                executed_at=a.created_at.isoformat() if a.created_at else None,
                duration_ms=a.duration_ms or 0.0,
                error=a.error_message,
            )
            for a in actions
        ]

    @staticmethod
    def _build_executive_summary(package: EvidencePackage) -> str:
        """Genereer een automatische executive summary op basis van de data."""
        actor_name = package.actor.display_name if package.actor else "an unknown actor"
        ip_count = len(package.ip_evidence)
        event_count = len(package.timeline)
        severity = package.severity.upper()

        # Anonimisatie flags
        anon_flags = []
        if package.actor:
            if package.actor.is_tor:
                anon_flags.append("TOR")
            if package.actor.is_vpn:
                anon_flags.append("VPN")
        anon_str = f" using {'/'.join(anon_flags)} anonymization" if anon_flags else ""

        # Landen
        countries = []
        if package.actor and package.actor.known_countries:
            countries = package.actor.known_countries[:5]
        country_str = f" originating from {', '.join(countries)}" if countries else ""

        date_str = package.incident_date.strftime("%Y-%m-%d %H:%M UTC") if package.incident_date else "unknown date"

        return (
            f"This report documents a {severity} severity {package.incident_type} "
            f"incident attributed to {actor_name}{anon_str}{country_str}. "
            f"The investigation covers {event_count} security events involving "
            f"{ip_count} unique IP addresses, first observed on {date_str}. "
            f"The overall risk score for this case is {package.risk_score:.0f}/100. "
            f"All evidence has been collected from immutable audit trails and "
            f"enriched through automated threat intelligence providers."
        )
