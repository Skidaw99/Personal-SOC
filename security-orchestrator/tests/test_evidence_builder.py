"""
Tests voor de Evidence Builder — schemas, legal references, PDF generatie, collector.

PDF tests valideren dat ReportLab een geldig PDF genereert zonder DB dependencies.
Collector tests gebruiken gemockte DB sessions.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from security_orchestrator.evidence.schemas import (
    ActorEvidence,
    EvidencePackage,
    IpEvidence,
    LegalReference,
    PlatformEvidence,
    ResponseActionEvidence,
    TimelineEntry,
)
from security_orchestrator.evidence.legal import get_legal_references
from security_orchestrator.evidence.pdf import EvidencePDFGenerator
from security_orchestrator.evidence.collector import EvidenceCollector


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_package(**overrides) -> EvidencePackage:
    """Maak een volledig gevuld EvidencePackage voor testing."""
    now = datetime.utcnow()

    defaults = dict(
        case_id="SOC-2026-TEST-001",
        case_title="Test Investigation: TOR-BF-A3F2",
        classification="TLP:AMBER",
        report_date=now,
        analyst_name="Test Analyst",
        organization="Test SOC",
        incident_type="brute_force",
        incident_date=now - timedelta(days=2),
        executive_summary=(
            "This report documents a HIGH severity brute_force incident "
            "attributed to TOR-BF-A3F2 using TOR anonymization originating "
            "from DE, NL. The investigation covers 5 security events involving "
            "3 unique IP addresses."
        ),
        risk_score=82.0,
        severity="high",
        timeline=[
            TimelineEntry(
                timestamp=now - timedelta(hours=48),
                event_type="brute_force",
                source_ip="185.220.101.42",
                severity="high",
                description="Multiple failed SSH login attempts",
                source="suricata",
                soc_event_id=str(uuid.uuid4()),
            ),
            TimelineEntry(
                timestamp=now - timedelta(hours=36),
                event_type="brute_force",
                source_ip="185.220.101.43",
                severity="high",
                description="Continued brute force from related IP",
                source="crowdsec",
                soc_event_id=str(uuid.uuid4()),
            ),
            TimelineEntry(
                timestamp=now - timedelta(hours=12),
                event_type="unauthorized_login",
                source_ip="185.220.101.42",
                severity="critical",
                description="Successful login after brute force campaign",
                source="social_fraud_detector",
                soc_event_id=str(uuid.uuid4()),
            ),
        ],
        ip_evidence=[
            IpEvidence(
                ip_address="185.220.101.42",
                threat_score=91.5,
                reputation="critical",
                country_code="DE",
                country_name="Germany",
                city="Frankfurt",
                latitude=50.1109,
                longitude=8.6821,
                asn=24940,
                isp="Hetzner Online GmbH",
                org="Hetzner",
                is_tor=True,
                is_datacenter=True,
                abuse_confidence=95,
                abuse_total_reports=1247,
                abuse_last_reported="2026-04-09T14:30:00",
                vt_malicious=12,
                vt_suspicious=3,
                vt_total_engines=87,
                shodan_ports=[22, 80, 443, 9001],
                shodan_vulns=["CVE-2023-4567"],
                shodan_hostnames=["tor-exit.example.de"],
            ),
            IpEvidence(
                ip_address="185.220.101.43",
                threat_score=78.2,
                reputation="malicious",
                country_code="DE",
                country_name="Germany",
                city="Frankfurt",
                is_tor=True,
                abuse_confidence=88,
                shodan_ports=[22, 9001],
            ),
            IpEvidence(
                ip_address="10.0.0.1",
                threat_score=0.0,
                reputation="clean",
                country_code="XX",
                country_name="Private Network",
            ),
        ],
        actor=ActorEvidence(
            actor_id=str(uuid.uuid4()),
            display_name="TOR-BF-A3F2",
            threat_level="high",
            confidence_score=85.0,
            status="active",
            total_events=42,
            known_ips=["185.220.101.42", "185.220.101.43"],
            known_countries=["DE", "NL"],
            attack_categories=["brute_force", "unauthorized_login"],
            platforms_targeted=["ssh", "web"],
            typical_hours=[2, 3, 4, 14, 15],
            is_tor=True,
            uses_automation=True,
            is_cross_platform=True,
            first_seen="2026-03-15T08:00:00",
            last_seen="2026-04-09T14:30:00",
            analyst_notes="Suspected automated scanning operation from Hetzner infrastructure.",
            tags=["tor-exit", "automated", "hetzner"],
        ),
        response_actions=[
            ResponseActionEvidence(
                action_type="ip_block",
                status="success",
                target="185.220.101.42",
                executed_at="2026-04-09T14:35:00",
                duration_ms=245.0,
            ),
            ResponseActionEvidence(
                action_type="email_alert",
                status="success",
                target="soc@example.com",
                executed_at="2026-04-09T14:35:01",
                duration_ms=1200.0,
            ),
            ResponseActionEvidence(
                action_type="webhook_alert",
                status="failed",
                target="https://hooks.slack.com/...",
                executed_at="2026-04-09T14:35:01",
                duration_ms=10050.0,
                error="Connection timeout after 10s",
            ),
        ],
        legal_references=get_legal_references("brute_force"),
        ioc_ips=["185.220.101.42", "185.220.101.43"],
        ioc_domains=["tor-exit.example.de"],
        chain_of_custody=[
            {
                "timestamp": now.isoformat() + "Z",
                "action": "Evidence package generated",
                "actor": "Test Analyst",
                "system": "SOC Security Orchestrator — Evidence Builder",
            },
        ],
    )
    defaults.update(overrides)
    return EvidencePackage(**defaults)


# ═══════════════════════════════════════════════════════════════════════════════
# LEGAL REFERENCES TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestLegalReferences:
    """Test dat de juiste wetsartikelen worden geselecteerd per incident type."""

    def test_brute_force_includes_cfaa_unauthorized(self):
        refs = get_legal_references("brute_force")
        statutes = [r.statute for r in refs]

        assert "18 U.S.C. § 1030" in statutes  # CFAA basis
        assert "18 U.S.C. § 1030(a)(2)" in statutes  # Unauthorized access

    def test_account_takeover_includes_identity_theft(self):
        refs = get_legal_references("account_takeover")
        statutes = [r.statute for r in refs]

        assert "18 U.S.C. § 1028A" in statutes  # Aggravated Identity Theft

    def test_data_exfiltration_includes_wire_fraud(self):
        refs = get_legal_references("data_exfiltration")
        statutes = [r.statute for r in refs]

        assert "18 U.S.C. § 1343" in statutes  # Wire Fraud

    def test_always_includes_nis2(self):
        refs = get_legal_references("port_scan")
        names = [r.name for r in refs]

        assert "NIS2 Directive" in names

    def test_always_includes_gdpr_breach(self):
        refs = get_legal_references("anomaly")
        names = [r.name for r in refs]

        assert "GDPR — Personal Data Breach Notification" in names

    def test_always_includes_budapest_convention(self):
        refs = get_legal_references("brute_force")
        names = [r.name for r in refs]

        assert "Council of Europe Convention on Cybercrime" in names

    def test_unknown_incident_type_gets_default_refs(self):
        refs = get_legal_references("totally_unknown_type")
        # Should still return base CFAA + NIS2 + GDPR
        assert len(refs) >= 3


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestEvidenceSchemas:
    """Test de evidence data schemas."""

    def test_evidence_package_defaults(self):
        pkg = EvidencePackage(case_id="TEST-001", case_title="Test")
        assert pkg.case_id == "TEST-001"
        assert pkg.timeline == []
        assert pkg.ip_evidence == []
        assert pkg.actor is None
        assert pkg.classification == "TLP:AMBER"

    def test_ip_evidence_defaults(self):
        ip = IpEvidence(ip_address="1.2.3.4")
        assert ip.threat_score == 0.0
        assert ip.is_tor is False
        assert ip.shodan_ports == []

    def test_timeline_entry_required_fields(self):
        entry = TimelineEntry(
            timestamp=datetime.utcnow(),
            event_type="brute_force",
        )
        assert entry.severity == "medium"
        assert entry.source_ip is None

    def test_full_package_has_all_sections(self):
        pkg = _make_package()
        assert len(pkg.timeline) == 3
        assert len(pkg.ip_evidence) == 3
        assert pkg.actor is not None
        assert pkg.actor.display_name == "TOR-BF-A3F2"
        assert len(pkg.response_actions) == 3
        assert len(pkg.legal_references) > 0
        assert len(pkg.ioc_ips) == 2
        assert len(pkg.chain_of_custody) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# PDF GENERATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestPDFGenerator:
    """Test dat de PDF generator geldige PDF bestanden produceert."""

    def test_generate_full_report_produces_valid_pdf(self):
        """Een volledig gevuld package moet een geldige PDF opleveren."""
        pkg = _make_package()
        generator = EvidencePDFGenerator()
        pdf_bytes = generator.generate(pkg)

        # PDF magic bytes
        assert pdf_bytes[:5] == b"%PDF-"
        # Minimale grootte (een paar pagina's)
        assert len(pdf_bytes) > 5000

    def test_generate_minimal_report(self):
        """Een minimaal package (geen events/IPs/actor) moet ook werken."""
        pkg = EvidencePackage(
            case_id="MINIMAL-001",
            case_title="Minimal Test",
            executive_summary="No data available.",
        )
        generator = EvidencePDFGenerator()
        pdf_bytes = generator.generate(pkg)

        assert pdf_bytes[:5] == b"%PDF-"
        assert len(pdf_bytes) > 1000

    def test_generate_report_without_actor(self):
        """Rapport zonder threat actor moet gracefully renderen."""
        pkg = _make_package(actor=None)
        generator = EvidencePDFGenerator()
        pdf_bytes = generator.generate(pkg)

        assert pdf_bytes[:5] == b"%PDF-"

    def test_generate_report_with_many_ips(self):
        """Test met veel IPs dat de PDF niet crasht."""
        ips = [
            IpEvidence(
                ip_address=f"10.0.{i // 256}.{i % 256}",
                threat_score=float(i % 100),
                reputation="suspicious",
            )
            for i in range(25)
        ]
        pkg = _make_package(ip_evidence=ips)
        generator = EvidencePDFGenerator()
        pdf_bytes = generator.generate(pkg)

        assert pdf_bytes[:5] == b"%PDF-"

    def test_generate_report_all_tlp_levels(self):
        """Test alle TLP classificatieniveaus."""
        generator = EvidencePDFGenerator()
        for tlp in ["TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"]:
            pkg = _make_package(classification=tlp)
            pdf_bytes = generator.generate(pkg)
            assert pdf_bytes[:5] == b"%PDF-"

    def test_generate_to_file(self, tmp_path):
        """Test dat generate_to_file een bestand aanmaakt."""
        pkg = _make_package()
        generator = EvidencePDFGenerator()
        filepath = generator.generate_to_file(pkg, str(tmp_path))

        assert filepath.endswith(".pdf")
        assert "SOC-2026-TEST-001" in filepath

        import os
        assert os.path.exists(filepath)
        assert os.path.getsize(filepath) > 5000

    def test_generate_report_with_long_descriptions(self):
        """Test dat lange teksten correct wrappen en niet crashen."""
        long_text = "A" * 2000
        pkg = _make_package(
            executive_summary=long_text,
            actor=ActorEvidence(
                display_name="LONG-TEXT-ACTOR",
                analyst_notes=long_text,
            ),
        )
        generator = EvidencePDFGenerator()
        pdf_bytes = generator.generate(pkg)
        assert pdf_bytes[:5] == b"%PDF-"

    def test_generate_report_with_response_errors(self):
        """Test dat failed acties correct in het rapport verschijnen."""
        actions = [
            ResponseActionEvidence(
                action_type="ip_block",
                status="failed",
                target="1.2.3.4",
                error="CrowdSec connection refused: dial tcp 127.0.0.1:8080",
            ),
        ]
        pkg = _make_package(response_actions=actions)
        generator = EvidencePDFGenerator()
        pdf_bytes = generator.generate(pkg)
        assert pdf_bytes[:5] == b"%PDF-"

    def test_generate_report_with_special_characters(self):
        """Test dat speciale tekens niet crashen."""
        pkg = _make_package(
            case_title='Test & "Special" <Characters> Ö Ü Ä',
            executive_summary="Tekst met accenten: café, naïve, über",
        )
        generator = EvidencePDFGenerator()
        pdf_bytes = generator.generate(pkg)
        assert pdf_bytes[:5] == b"%PDF-"


# ═══════════════════════════════════════════════════════════════════════════════
# COLLECTOR TESTS (gemockte DB)
# ═══════════════════════════════════════════════════════════════════════════════


class TestEvidenceCollector:
    """Test de collector met gemockte database session."""

    def test_build_executive_summary_with_actor(self):
        """Test dat de summary generator correcte tekst produceert."""
        pkg = _make_package()
        summary = EvidenceCollector._build_executive_summary(pkg)

        assert "TOR-BF-A3F2" in summary
        assert "HIGH" in summary
        assert "brute_force" in summary
        assert "3 unique IP addresses" in summary

    def test_build_executive_summary_without_actor(self):
        """Summary zonder actor moet ook werken."""
        pkg = _make_package(actor=None)
        summary = EvidenceCollector._build_executive_summary(pkg)

        assert "unknown actor" in summary

    def test_build_executive_summary_with_anon_flags(self):
        """Summary met TOR/VPN flags."""
        pkg = _make_package()
        summary = EvidenceCollector._build_executive_summary(pkg)

        assert "TOR" in summary
