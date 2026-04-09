"""
PDF Generator — genereert FBI-ready PDF rapporten met ReportLab.

Produceert een professioneel, forensisch rapport met:
  - Cover page met classificatie banner en case metadata
  - Inhoudsopgave
  - Executive summary
  - Incident tijdlijn (chronologische tabel)
  - IP intelligence tabellen (volledige enrichment per IP)
  - Threat actor profiel
  - Platform bewijsmateriaal
  - Response acties audit trail
  - Wettelijk kader (CFAA, NIS2, GDPR)
  - IOC overzicht
  - Chain of custody log
"""
from __future__ import annotations

import io
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .schemas import (
    ActorEvidence,
    EvidencePackage,
    IpEvidence,
    LegalReference,
    ResponseActionEvidence,
    TimelineEntry,
)

logger = logging.getLogger(__name__)

# ── Color scheme ─────────────────────────────────────────────────────────────

_DARK_BG = colors.HexColor("#1a1a2e")
_ACCENT = colors.HexColor("#e74c3c")
_ACCENT_DARK = colors.HexColor("#c0392b")
_HEADER_BG = colors.HexColor("#16213e")
_ROW_ALT = colors.HexColor("#f8f9fa")
_TEXT_DARK = colors.HexColor("#2c3e50")
_TEXT_LIGHT = colors.HexColor("#ecf0f1")
_BORDER = colors.HexColor("#bdc3c7")
_SUCCESS = colors.HexColor("#27ae60")
_WARNING = colors.HexColor("#f39c12")
_DANGER = colors.HexColor("#e74c3c")

# ── Classification banner colors ─────────────────────────────────────────────

_TLP_COLORS = {
    "TLP:RED": colors.HexColor("#FF0000"),
    "TLP:AMBER": colors.HexColor("#FFC000"),
    "TLP:GREEN": colors.HexColor("#33FF00"),
    "TLP:CLEAR": colors.HexColor("#FFFFFF"),
}


class EvidencePDFGenerator:
    """
    Genereert een compleet FBI-ready PDF rapport uit een EvidencePackage.

    Usage::

        generator = EvidencePDFGenerator()
        pdf_bytes = generator.generate(package)
        # of
        filepath = generator.generate_to_file(package, "/data/evidence/")
    """

    def __init__(self) -> None:
        self._styles = self._build_styles()
        self._page_width, self._page_height = A4

    def generate(self, package: EvidencePackage) -> bytes:
        """Genereer PDF en retourneer als bytes."""
        buffer = io.BytesIO()
        self._build_pdf(buffer, package)
        return buffer.getvalue()

    def generate_to_file(
        self, package: EvidencePackage, output_dir: str
    ) -> str:
        """Genereer PDF en schrijf naar bestand. Retourneert het volledige pad."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_case = package.case_id.replace("/", "-").replace(" ", "_")
        filename = f"{safe_case}_{timestamp}.pdf"
        filepath = out_path / filename

        with open(filepath, "wb") as f:
            pdf_bytes = self.generate(package)
            f.write(pdf_bytes)

        logger.info("evidence_pdf_generated", path=str(filepath), size=len(pdf_bytes))
        return str(filepath)

    # ── PDF construction ─────────────────────────────────────────────────────

    def _build_pdf(self, buffer: io.BytesIO, pkg: EvidencePackage) -> None:
        """Bouw het volledige PDF document."""
        doc = BaseDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2 * cm,
            title=f"Evidence Report — {pkg.case_id}",
            author=pkg.analyst_name,
            subject=pkg.case_title,
        )

        # Page templates
        cover_frame = Frame(
            0, 0, self._page_width, self._page_height,
            leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
            id="cover",
        )
        content_frame = Frame(
            2 * cm, 2 * cm,
            self._page_width - 4 * cm,
            self._page_height - 4.5 * cm,
            id="content",
        )

        classification = pkg.classification
        org = pkg.organization

        def _content_header_footer(canvas, doc):
            self._draw_header_footer(canvas, doc, classification, org, pkg.case_id)

        doc.addPageTemplates([
            PageTemplate(id="Cover", frames=[cover_frame]),
            PageTemplate(
                id="Content",
                frames=[content_frame],
                onPage=_content_header_footer,
            ),
        ])

        # Build story
        story = []
        story.extend(self._cover_page(pkg))
        story.append(NextPageTemplate("Content"))
        story.append(PageBreak())

        # Table of contents (manual)
        story.extend(self._table_of_contents())
        story.append(PageBreak())

        # Sections
        story.extend(self._section_executive_summary(pkg))
        story.extend(self._section_incident_details(pkg))
        story.extend(self._section_timeline(pkg))
        story.extend(self._section_ip_intelligence(pkg))
        story.extend(self._section_threat_actor(pkg))
        story.extend(self._section_response_actions(pkg))
        story.extend(self._section_legal_framework(pkg))
        story.extend(self._section_iocs(pkg))
        story.extend(self._section_chain_of_custody(pkg))

        doc.build(story)

    # ── Cover page ───────────────────────────────────────────────────────────

    def _cover_page(self, pkg: EvidencePackage) -> list:
        """Bouw de cover page met classificatie banner."""
        s = self._styles
        elements = []

        # Top classification banner
        tlp_color = _TLP_COLORS.get(pkg.classification, _WARNING)
        banner_text = f'<font color="black"><b>{pkg.classification}</b></font>'
        banner_style = ParagraphStyle(
            "Banner", parent=s["Normal"],
            fontSize=14, alignment=TA_CENTER,
            textColor=colors.black,
            backColor=tlp_color,
            spaceBefore=0, spaceAfter=0,
            leftIndent=-2 * cm, rightIndent=-2 * cm,
        )

        elements.append(Spacer(1, 3 * cm))

        # Classification banner as table for full-width background
        banner_table = Table(
            [[Paragraph(pkg.classification, banner_style)]],
            colWidths=[self._page_width],
        )
        banner_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), tlp_color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(banner_table)

        elements.append(Spacer(1, 4 * cm))

        # Title block
        elements.append(Paragraph("CYBER INCIDENT", s["CoverSubtitle"]))
        elements.append(Paragraph("EVIDENCE REPORT", s["CoverTitle"]))
        elements.append(Spacer(1, 1.5 * cm))

        # Case details
        details = [
            ("Case Reference", pkg.case_id),
            ("Report Date", pkg.report_date.strftime("%Y-%m-%d %H:%M UTC")),
            ("Incident Type", pkg.incident_type.upper().replace("_", " ")),
            ("Severity", pkg.severity.upper()),
            ("Risk Score", f"{pkg.risk_score:.0f} / 100"),
            ("Analyst", pkg.analyst_name),
            ("Organization", pkg.organization),
        ]

        detail_data = [[
            Paragraph(f'<b>{label}</b>', s["CoverDetail"]),
            Paragraph(value, s["CoverDetail"]),
        ] for label, value in details]

        detail_table = Table(detail_data, colWidths=[5.5 * cm, 10 * cm])
        detail_table.setStyle(TableStyle([
            ("TEXTCOLOR", (0, 0), (-1, -1), _TEXT_DARK),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, -2), 0.5, _BORDER),
            ("ALIGN", (0, 0), (0, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (0, -1), 2 * cm),
        ]))
        elements.append(detail_table)

        elements.append(Spacer(1, 3 * cm))

        # Bottom banner
        elements.append(banner_table)

        return elements

    # ── Table of contents ────────────────────────────────────────────────────

    def _table_of_contents(self) -> list:
        s = self._styles
        elements = [
            Paragraph("TABLE OF CONTENTS", s["SectionHeader"]),
            Spacer(1, 0.5 * cm),
        ]

        toc_items = [
            "1. Executive Summary",
            "2. Incident Details",
            "3. Event Timeline",
            "4. IP Intelligence Analysis",
            "5. Threat Actor Profile",
            "6. Response Actions Audit",
            "7. Legal Framework",
            "8. Indicators of Compromise (IOCs)",
            "9. Chain of Custody",
        ]

        for item in toc_items:
            elements.append(Paragraph(item, s["TOCEntry"]))

        return elements

    # ── Section: Executive Summary ───────────────────────────────────────────

    def _section_executive_summary(self, pkg: EvidencePackage) -> list:
        s = self._styles
        return [
            Paragraph("1. EXECUTIVE SUMMARY", s["SectionHeader"]),
            Spacer(1, 0.3 * cm),
            Paragraph(pkg.executive_summary, s["BodyText"]),
            Spacer(1, 0.8 * cm),
        ]

    # ── Section: Incident Details ────────────────────────────────────────────

    def _section_incident_details(self, pkg: EvidencePackage) -> list:
        s = self._styles
        elements = [
            Paragraph("2. INCIDENT DETAILS", s["SectionHeader"]),
            Spacer(1, 0.3 * cm),
        ]

        rows = [
            ["Field", "Value"],
            ["Case Reference", pkg.case_id],
            ["Incident Type", pkg.incident_type.upper().replace("_", " ")],
            [
                "Incident Date",
                pkg.incident_date.strftime("%Y-%m-%d %H:%M UTC")
                if pkg.incident_date else "Unknown",
            ],
            ["Report Date", pkg.report_date.strftime("%Y-%m-%d %H:%M UTC")],
            ["Severity", pkg.severity.upper()],
            ["Risk Score", f"{pkg.risk_score:.0f} / 100"],
            ["Classification", pkg.classification],
            ["Total Events", str(len(pkg.timeline))],
            ["Unique IPs", str(len(pkg.ip_evidence))],
            ["Analyst", pkg.analyst_name],
        ]

        table = self._make_kv_table(rows)
        elements.append(table)
        elements.append(Spacer(1, 0.8 * cm))
        return elements

    # ── Section: Timeline ────────────────────────────────────────────────────

    def _section_timeline(self, pkg: EvidencePackage) -> list:
        s = self._styles
        elements = [
            Paragraph("3. EVENT TIMELINE", s["SectionHeader"]),
            Spacer(1, 0.3 * cm),
        ]

        if not pkg.timeline:
            elements.append(Paragraph("No events recorded.", s["BodyText"]))
            elements.append(Spacer(1, 0.8 * cm))
            return elements

        header = ["#", "Timestamp (UTC)", "Type", "Source IP", "Severity", "Source"]
        rows = [header]

        for i, entry in enumerate(pkg.timeline, 1):
            rows.append([
                str(i),
                entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                entry.event_type.replace("_", " "),
                entry.source_ip or "N/A",
                entry.severity.upper(),
                entry.source or "N/A",
            ])

        table = self._make_data_table(
            rows,
            col_widths=[1 * cm, 3.5 * cm, 3.5 * cm, 3 * cm, 2 * cm, 3 * cm],
        )
        elements.append(table)
        elements.append(Spacer(1, 0.8 * cm))
        return elements

    # ── Section: IP Intelligence ─────────────────────────────────────────────

    def _section_ip_intelligence(self, pkg: EvidencePackage) -> list:
        s = self._styles
        elements = [
            Paragraph("4. IP INTELLIGENCE ANALYSIS", s["SectionHeader"]),
            Spacer(1, 0.3 * cm),
        ]

        if not pkg.ip_evidence:
            elements.append(Paragraph("No IP intelligence data available.", s["BodyText"]))
            elements.append(Spacer(1, 0.8 * cm))
            return elements

        for ip_ev in pkg.ip_evidence:
            elements.append(Paragraph(
                f'<b>IP Address: {ip_ev.ip_address}</b>', s["SubHeader"]
            ))
            elements.append(Spacer(1, 0.2 * cm))

            # Flags
            flags = []
            if ip_ev.is_tor:
                flags.append("TOR EXIT NODE")
            if ip_ev.is_vpn:
                flags.append("VPN")
            if ip_ev.is_proxy:
                flags.append("PROXY")
            if ip_ev.is_datacenter:
                flags.append("DATACENTER")
            flag_str = " | ".join(flags) if flags else "None detected"

            rows = [
                ["Field", "Value"],
                ["Threat Score", f"{ip_ev.threat_score:.1f} / 100"],
                ["Reputation", ip_ev.reputation.upper()],
                ["Country", f"{ip_ev.country_name or 'Unknown'} ({ip_ev.country_code or '??'})"],
                ["City", ip_ev.city or "Unknown"],
                ["ASN", str(ip_ev.asn or "Unknown")],
                ["ISP", ip_ev.isp or "Unknown"],
                ["Organization", ip_ev.org or "Unknown"],
                ["Anonymization Flags", flag_str],
                ["AbuseIPDB Confidence", f"{ip_ev.abuse_confidence or 0}/100"],
                ["AbuseIPDB Reports", str(ip_ev.abuse_total_reports or 0)],
                [
                    "VirusTotal",
                    f"{ip_ev.vt_malicious or 0} malicious / "
                    f"{ip_ev.vt_total_engines or 0} engines",
                ],
                [
                    "Open Ports",
                    ", ".join(str(p) for p in ip_ev.shodan_ports[:15]) or "None",
                ],
                [
                    "Known Vulnerabilities",
                    ", ".join(ip_ev.shodan_vulns[:10]) or "None",
                ],
                [
                    "Hostnames",
                    ", ".join(ip_ev.shodan_hostnames[:5]) or "None",
                ],
            ]

            table = self._make_kv_table(rows)
            elements.append(table)
            elements.append(Spacer(1, 0.5 * cm))

        elements.append(Spacer(1, 0.3 * cm))
        return elements

    # ── Section: Threat Actor ────────────────────────────────────────────────

    def _section_threat_actor(self, pkg: EvidencePackage) -> list:
        s = self._styles
        elements = [
            Paragraph("5. THREAT ACTOR PROFILE", s["SectionHeader"]),
            Spacer(1, 0.3 * cm),
        ]

        actor = pkg.actor
        if not actor:
            elements.append(Paragraph(
                "No threat actor has been attributed to this incident.",
                s["BodyText"],
            ))
            elements.append(Spacer(1, 0.8 * cm))
            return elements

        flags = []
        if actor.is_tor:
            flags.append("TOR")
        if actor.is_vpn:
            flags.append("VPN")
        if actor.uses_automation:
            flags.append("AUTOMATED/BOT")
        if actor.is_cross_platform:
            flags.append("CROSS-PLATFORM")

        rows = [
            ["Field", "Value"],
            ["Display Name", actor.display_name],
            ["Alias", actor.alias or "None assigned"],
            ["Threat Level", actor.threat_level.upper()],
            ["Confidence Score", f"{actor.confidence_score:.0f}/100"],
            ["Status", actor.status.upper()],
            ["Total Events", str(actor.total_events)],
            ["Known IPs", str(len(actor.known_ips))],
            ["Countries", ", ".join(actor.known_countries) or "Unknown"],
            ["Attack Categories", ", ".join(c.replace("_", " ") for c in actor.attack_categories) or "None"],
            ["Platforms Targeted", ", ".join(actor.platforms_targeted) or "None"],
            ["Behavioral Flags", " | ".join(flags) if flags else "None"],
            [
                "Typical Active Hours (UTC)",
                ", ".join(f"{h:02d}:00" for h in sorted(actor.typical_hours)) or "Unknown",
            ],
            ["First Seen", actor.first_seen or "Unknown"],
            ["Last Seen", actor.last_seen or "Unknown"],
        ]

        table = self._make_kv_table(rows)
        elements.append(table)

        if actor.analyst_notes:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph("<b>Analyst Notes:</b>", s["BodyText"]))
            elements.append(Paragraph(actor.analyst_notes, s["BodyText"]))

        if actor.tags:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph(
                f'<b>Tags:</b> {", ".join(actor.tags)}', s["BodyText"]
            ))

        elements.append(Spacer(1, 0.8 * cm))
        return elements

    # ── Section: Response Actions ────────────────────────────────────────────

    def _section_response_actions(self, pkg: EvidencePackage) -> list:
        s = self._styles
        elements = [
            Paragraph("6. RESPONSE ACTIONS AUDIT", s["SectionHeader"]),
            Spacer(1, 0.3 * cm),
        ]

        if not pkg.response_actions:
            elements.append(Paragraph(
                "No automated response actions were triggered.",
                s["BodyText"],
            ))
            elements.append(Spacer(1, 0.8 * cm))
            return elements

        header = ["#", "Action", "Status", "Target", "Executed At", "Duration"]
        rows = [header]

        for i, action in enumerate(pkg.response_actions, 1):
            rows.append([
                str(i),
                action.action_type.replace("_", " ").upper(),
                action.status.upper(),
                action.target or "N/A",
                action.executed_at or "N/A",
                f"{action.duration_ms:.0f}ms" if action.duration_ms else "N/A",
            ])

        table = self._make_data_table(
            rows,
            col_widths=[1 * cm, 3 * cm, 2 * cm, 3.5 * cm, 3.5 * cm, 2 * cm],
        )
        elements.append(table)

        # Errors
        errors = [a for a in pkg.response_actions if a.error]
        if errors:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph("<b>Action Errors:</b>", s["BodyText"]))
            for err in errors:
                elements.append(Paragraph(
                    f'• <b>{err.action_type}</b>: {err.error}',
                    s["BodyText"],
                ))

        elements.append(Spacer(1, 0.8 * cm))
        return elements

    # ── Section: Legal Framework ─────────────────────────────────────────────

    def _section_legal_framework(self, pkg: EvidencePackage) -> list:
        s = self._styles
        elements = [
            Paragraph("7. APPLICABLE LEGAL FRAMEWORK", s["SectionHeader"]),
            Spacer(1, 0.3 * cm),
            Paragraph(
                "The following statutes and regulations may be applicable to "
                "this incident. This section is provided for reference only "
                "and does not constitute legal advice.",
                s["BodyText"],
            ),
            Spacer(1, 0.3 * cm),
        ]

        if not pkg.legal_references:
            elements.append(Paragraph("No legal references configured.", s["BodyText"]))
            elements.append(Spacer(1, 0.8 * cm))
            return elements

        # Group by jurisdiction
        by_jurisdiction: dict[str, list[LegalReference]] = {}
        for ref in pkg.legal_references:
            by_jurisdiction.setdefault(ref.jurisdiction, []).append(ref)

        for jurisdiction, refs in by_jurisdiction.items():
            elements.append(Paragraph(
                f'<b>{jurisdiction} Jurisdiction</b>', s["SubHeader"]
            ))
            elements.append(Spacer(1, 0.2 * cm))

            for ref in refs:
                elements.append(Paragraph(
                    f'<b>{ref.statute}</b> — {ref.name}',
                    s["BodyText"],
                ))
                if ref.relevance:
                    elements.append(Paragraph(ref.relevance, s["SmallText"]))
                elements.append(Spacer(1, 0.2 * cm))

            elements.append(Spacer(1, 0.3 * cm))

        return elements

    # ── Section: IOCs ────────────────────────────────────────────────────────

    def _section_iocs(self, pkg: EvidencePackage) -> list:
        s = self._styles
        elements = [
            Paragraph("8. INDICATORS OF COMPROMISE (IOCs)", s["SectionHeader"]),
            Spacer(1, 0.3 * cm),
        ]

        has_iocs = any([pkg.ioc_ips, pkg.ioc_domains, pkg.ioc_hashes, pkg.ioc_urls])

        if not has_iocs:
            elements.append(Paragraph("No IOCs identified.", s["BodyText"]))
            elements.append(Spacer(1, 0.8 * cm))
            return elements

        if pkg.ioc_ips:
            elements.append(Paragraph("<b>IP Addresses:</b>", s["BodyText"]))
            for ip in pkg.ioc_ips:
                elements.append(Paragraph(f"  •  {ip}", s["MonoText"]))
            elements.append(Spacer(1, 0.3 * cm))

        if pkg.ioc_domains:
            elements.append(Paragraph("<b>Domains / Hostnames:</b>", s["BodyText"]))
            for domain in pkg.ioc_domains:
                elements.append(Paragraph(f"  •  {domain}", s["MonoText"]))
            elements.append(Spacer(1, 0.3 * cm))

        if pkg.ioc_hashes:
            elements.append(Paragraph("<b>File Hashes:</b>", s["BodyText"]))
            for h in pkg.ioc_hashes:
                elements.append(Paragraph(f"  •  {h}", s["MonoText"]))
            elements.append(Spacer(1, 0.3 * cm))

        if pkg.ioc_urls:
            elements.append(Paragraph("<b>URLs:</b>", s["BodyText"]))
            for url in pkg.ioc_urls:
                elements.append(Paragraph(f"  •  {url}", s["MonoText"]))
            elements.append(Spacer(1, 0.3 * cm))

        elements.append(Spacer(1, 0.5 * cm))
        return elements

    # ── Section: Chain of Custody ────────────────────────────────────────────

    def _section_chain_of_custody(self, pkg: EvidencePackage) -> list:
        s = self._styles
        elements = [
            Paragraph("9. CHAIN OF CUSTODY", s["SectionHeader"]),
            Spacer(1, 0.3 * cm),
            Paragraph(
                "This section documents the provenance and handling of all "
                "digital evidence referenced in this report. All data has been "
                "collected from immutable, append-only audit trails.",
                s["BodyText"],
            ),
            Spacer(1, 0.3 * cm),
        ]

        if not pkg.chain_of_custody:
            elements.append(Paragraph("No custody records.", s["BodyText"]))
            return elements

        header = ["#", "Timestamp", "Action", "Actor", "System"]
        rows = [header]

        for i, entry in enumerate(pkg.chain_of_custody, 1):
            rows.append([
                str(i),
                str(entry.get("timestamp", "N/A")),
                str(entry.get("action", "N/A")),
                str(entry.get("actor", "N/A")),
                str(entry.get("system", "N/A")),
            ])

        table = self._make_data_table(
            rows,
            col_widths=[1 * cm, 3.5 * cm, 4 * cm, 3.5 * cm, 4 * cm],
        )
        elements.append(table)
        elements.append(Spacer(1, 1 * cm))

        # End marker
        elements.append(Paragraph(
            "— END OF REPORT —",
            ParagraphStyle(
                "EndMarker", parent=s["Normal"],
                fontSize=10, alignment=TA_CENTER,
                textColor=_TEXT_DARK, spaceBefore=1 * cm,
            ),
        ))

        return elements

    # ── Header / footer ──────────────────────────────────────────────────────

    def _draw_header_footer(
        self, canvas, doc, classification: str, org: str, case_id: str
    ) -> None:
        """Teken header en footer op elke content page."""
        canvas.saveState()
        width, height = A4

        # Header: classification banner
        tlp_color = _TLP_COLORS.get(classification, _WARNING)
        canvas.setFillColor(tlp_color)
        canvas.rect(0, height - 1.2 * cm, width, 1.2 * cm, fill=True, stroke=False)
        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawCentredString(width / 2, height - 0.8 * cm, classification)

        # Header: case ID
        canvas.setFillColor(_TEXT_DARK)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(2 * cm, height - 1.8 * cm, f"Case: {case_id}")
        canvas.drawRightString(
            width - 2 * cm, height - 1.8 * cm,
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        )

        # Footer
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(_BORDER)
        canvas.line(2 * cm, 1.5 * cm, width - 2 * cm, 1.5 * cm)
        canvas.setFillColor(_TEXT_DARK)
        canvas.drawString(2 * cm, 1 * cm, f"{org} — Confidential")
        canvas.drawRightString(
            width - 2 * cm, 1 * cm, f"Page {doc.page}"
        )

        canvas.restoreState()

    # ── Table helpers ────────────────────────────────────────────────────────

    def _make_kv_table(self, rows: list[list[str]]) -> Table:
        """Maak een key-value tabel (2 kolommen, header row)."""
        styled_rows = []
        for row in rows:
            styled_rows.append([
                Paragraph(str(cell), self._styles["TableCell"])
                for cell in row
            ])

        table = Table(styled_rows, colWidths=[5 * cm, 11 * cm])
        table.setStyle(TableStyle([
            # Header
            ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), _TEXT_LIGHT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            # Body
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ROW_ALT]),
            # Grid
            ("GRID", (0, 0), (-1, -1), 0.5, _BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        return table

    def _make_data_table(
        self, rows: list[list[str]], col_widths: list[float]
    ) -> Table:
        """Maak een data tabel met header en alternerende rij-kleuren."""
        styled_rows = []
        for row in rows:
            styled_rows.append([
                Paragraph(str(cell), self._styles["TableCell"])
                for cell in row
            ])

        table = Table(styled_rows, colWidths=col_widths)

        style_commands = [
            # Header
            ("BACKGROUND", (0, 0), (-1, 0), _HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), _TEXT_LIGHT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            # Body
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ROW_ALT]),
            # Grid
            ("GRID", (0, 0), (-1, -1), 0.5, _BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]

        # Color-code severity columns if present
        for row_idx in range(1, len(rows)):
            for col_idx, cell in enumerate(rows[row_idx]):
                cell_upper = str(cell).upper()
                if cell_upper in ("CRITICAL", "FAILED"):
                    style_commands.append(
                        ("TEXTCOLOR", (col_idx, row_idx), (col_idx, row_idx), _DANGER)
                    )
                elif cell_upper in ("HIGH", "WARNING"):
                    style_commands.append(
                        ("TEXTCOLOR", (col_idx, row_idx), (col_idx, row_idx), _WARNING)
                    )
                elif cell_upper in ("SUCCESS",):
                    style_commands.append(
                        ("TEXTCOLOR", (col_idx, row_idx), (col_idx, row_idx), _SUCCESS)
                    )

        table.setStyle(TableStyle(style_commands))
        return table

    # ── Styles ───────────────────────────────────────────────────────────────

    @staticmethod
    def _build_styles() -> dict[str, ParagraphStyle]:
        """Bouw alle paragraph styles voor het rapport."""
        base = getSampleStyleSheet()

        return {
            "Normal": base["Normal"],
            "CoverTitle": ParagraphStyle(
                "CoverTitle", parent=base["Title"],
                fontSize=32, leading=38, alignment=TA_CENTER,
                textColor=_TEXT_DARK, spaceAfter=0.5 * cm,
                fontName="Helvetica-Bold",
            ),
            "CoverSubtitle": ParagraphStyle(
                "CoverSubtitle", parent=base["Normal"],
                fontSize=14, alignment=TA_CENTER,
                textColor=_ACCENT, spaceAfter=0.2 * cm,
                fontName="Helvetica",
            ),
            "CoverDetail": ParagraphStyle(
                "CoverDetail", parent=base["Normal"],
                fontSize=10, textColor=_TEXT_DARK,
            ),
            "SectionHeader": ParagraphStyle(
                "SectionHeader", parent=base["Heading1"],
                fontSize=14, leading=18, textColor=_ACCENT_DARK,
                fontName="Helvetica-Bold",
                spaceBefore=0.5 * cm, spaceAfter=0.2 * cm,
                borderWidth=0, borderPadding=0,
                borderColor=_ACCENT, borderRadius=0,
            ),
            "SubHeader": ParagraphStyle(
                "SubHeader", parent=base["Heading2"],
                fontSize=11, leading=14, textColor=_TEXT_DARK,
                fontName="Helvetica-Bold",
                spaceBefore=0.3 * cm, spaceAfter=0.1 * cm,
            ),
            "BodyText": ParagraphStyle(
                "BodyText", parent=base["Normal"],
                fontSize=9, leading=13, textColor=_TEXT_DARK,
                spaceBefore=0.1 * cm, spaceAfter=0.1 * cm,
            ),
            "SmallText": ParagraphStyle(
                "SmallText", parent=base["Normal"],
                fontSize=8, leading=11, textColor=colors.HexColor("#7f8c8d"),
                leftIndent=0.5 * cm,
            ),
            "MonoText": ParagraphStyle(
                "MonoText", parent=base["Normal"],
                fontSize=8, leading=11, fontName="Courier",
                textColor=_TEXT_DARK, leftIndent=0.5 * cm,
            ),
            "TableCell": ParagraphStyle(
                "TableCell", parent=base["Normal"],
                fontSize=8, leading=10, textColor=_TEXT_DARK,
            ),
            "TOCEntry": ParagraphStyle(
                "TOCEntry", parent=base["Normal"],
                fontSize=11, leading=18, textColor=_TEXT_DARK,
                leftIndent=1 * cm,
            ),
        }
