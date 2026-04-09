"""
Evidence Builder — hoofd-orchestrator voor evidence package generatie.

Publieke API
────────────
    builder = EvidenceBuilder(session)

    # Per threat actor
    pdf_path = await builder.build_actor_report(actor_id, case_id="SOC-2026-001")

    # Per incident
    pdf_path = await builder.build_incident_report(event_id, case_id="SOC-2026-002")

    # Retourneer bytes (voor streaming via API response)
    pdf_bytes = await builder.build_actor_report_bytes(actor_id, case_id="SOC-2026-001")

Flow
────
  1. EvidenceCollector verzamelt alle data uit DB
  2. EvidencePDFGenerator rendert het PDF rapport
  3. Resultaat wordt opgeslagen op disk en/of als bytes geretourneerd
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from .collector import EvidenceCollector
from .config import evidence_settings
from .pdf import EvidencePDFGenerator
from .schemas import EvidencePackage, PlatformEvidence

logger = logging.getLogger(__name__)


class EvidenceBuilder:
    """
    Hoofd-orchestrator: verzamelt evidence en genereert PDF rapporten.

    Instantieer per DB session.

    Usage::

        async with AsyncSessionLocal() as session:
            builder = EvidenceBuilder(session)
            pdf_path = await builder.build_actor_report(
                actor_id=actor_uuid,
                case_id="SOC-2026-0042",
                analyst_name="J. van der Berg",
            )
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._collector = EvidenceCollector(session)
        self._pdf = EvidencePDFGenerator()

    # ── Actor report ─────────────────────────────────────────────────────────

    async def build_actor_report(
        self,
        actor_id: uuid.UUID,
        case_id: str,
        analyst_name: Optional[str] = None,
        output_dir: Optional[str] = None,
        platform_evidence: Optional[list[PlatformEvidence]] = None,
    ) -> str:
        """
        Genereer een FBI-ready PDF rapport voor een threat actor.

        Returns:
            Volledig pad naar het gegenereerde PDF bestand.
        """
        package = await self._collector.collect_for_actor(
            actor_id=actor_id,
            case_id=case_id,
            analyst_name=analyst_name,
        )

        if platform_evidence:
            package.platform_evidence = platform_evidence

        filepath = self._pdf.generate_to_file(
            package,
            output_dir=output_dir or evidence_settings.evidence_output_dir,
        )

        logger.info(
            "evidence_actor_report_built",
            case_id=case_id,
            actor_id=str(actor_id),
            path=filepath,
        )
        return filepath

    async def build_actor_report_bytes(
        self,
        actor_id: uuid.UUID,
        case_id: str,
        analyst_name: Optional[str] = None,
        platform_evidence: Optional[list[PlatformEvidence]] = None,
    ) -> bytes:
        """
        Genereer een PDF rapport als bytes (voor streaming via API/dashboard).

        Gebruik dit voor de dashboard export knop.
        """
        package = await self._collector.collect_for_actor(
            actor_id=actor_id,
            case_id=case_id,
            analyst_name=analyst_name,
        )

        if platform_evidence:
            package.platform_evidence = platform_evidence

        return self._pdf.generate(package)

    # ── Incident report ──────────────────────────────────────────────────────

    async def build_incident_report(
        self,
        soc_event_id: uuid.UUID,
        case_id: str,
        analyst_name: Optional[str] = None,
        output_dir: Optional[str] = None,
        platform_evidence: Optional[list[PlatformEvidence]] = None,
    ) -> str:
        """
        Genereer een PDF rapport voor een enkel incident.

        Returns:
            Volledig pad naar het gegenereerde PDF bestand.
        """
        package = await self._collector.collect_for_event(
            soc_event_id=soc_event_id,
            case_id=case_id,
            analyst_name=analyst_name,
        )

        if platform_evidence:
            package.platform_evidence = platform_evidence

        filepath = self._pdf.generate_to_file(
            package,
            output_dir=output_dir or evidence_settings.evidence_output_dir,
        )

        logger.info(
            "evidence_incident_report_built",
            case_id=case_id,
            soc_event_id=str(soc_event_id),
            path=filepath,
        )
        return filepath

    async def build_incident_report_bytes(
        self,
        soc_event_id: uuid.UUID,
        case_id: str,
        analyst_name: Optional[str] = None,
        platform_evidence: Optional[list[PlatformEvidence]] = None,
    ) -> bytes:
        """Genereer een incident PDF als bytes."""
        package = await self._collector.collect_for_event(
            soc_event_id=soc_event_id,
            case_id=case_id,
            analyst_name=analyst_name,
        )

        if platform_evidence:
            package.platform_evidence = platform_evidence

        return self._pdf.generate(package)

    # ── Custom package ───────────────────────────────────────────────────────

    def build_from_package(
        self,
        package: EvidencePackage,
        output_dir: Optional[str] = None,
    ) -> str:
        """
        Genereer een PDF van een handmatig samengesteld EvidencePackage.

        Handig voor custom rapporten of testing.
        """
        return self._pdf.generate_to_file(
            package,
            output_dir=output_dir or evidence_settings.evidence_output_dir,
        )

    def build_from_package_bytes(self, package: EvidencePackage) -> bytes:
        """Genereer PDF bytes van een handmatig samengesteld package."""
        return self._pdf.generate(package)
