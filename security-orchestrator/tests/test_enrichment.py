"""
Integration test — IP Intelligence Engine tegen 185.220.101.45

Dit is een bekende Tor exit node. Verwachte resultaten:
  - AbuseIPDB: abuse_confidence_score >= 80
  - VirusTotal: vt_malicious >= 5
  - Shodan:     poort 9001 of 9030 aanwezig (Tor relay)
  - ip-api.com: ipapi_is_proxy = True
  - Scorer:     threat_score >= 75 (reputation = "critical")
  - is_tor:     True

Gebruik:
  pip install -r requirements.txt
  ABUSEIPDB_API_KEY=... VIRUSTOTAL_API_KEY=... pytest tests/ -v -s

Zonder API keys draaien alleen MaxMind (als DB aanwezig) en ip-api.com.
De test past de assertions dan aan op basis van welke providers actief zijn.
"""
from __future__ import annotations

import os
import asyncio
import pytest
import pytest_asyncio

# Pad aanpassen zodat de enrichment package vindbaar is
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from enrichment.engine import EnrichmentEngine
from enrichment.models import ThreatIntelligence

TEST_IP = "185.220.101.45"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def engine():
    """Start de EnrichmentEngine met keys uit de environment."""
    eng = EnrichmentEngine.from_env()
    await eng.startup()
    yield eng
    await eng.shutdown()


@pytest_asyncio.fixture(scope="session")
async def intel(engine: EnrichmentEngine) -> ThreatIntelligence:
    """Enrich het test IP eenmalig voor alle tests in de sessie."""
    return await engine.enrich(TEST_IP, force_refresh=True)


# ── Basis sanity checks ────────────────────────────────────────────────────────

class TestThreatIntelligenceStructure:
    def test_ip_is_set(self, intel: ThreatIntelligence):
        assert intel.ip == TEST_IP

    def test_has_at_least_one_provider(self, intel: ThreatIntelligence):
        assert len(intel.providers_used) >= 1, (
            f"Geen enkele provider succesvol. Fouten: {intel.providers_failed}"
        )

    def test_threat_score_in_range(self, intel: ThreatIntelligence):
        assert 0.0 <= intel.threat_score <= 100.0

    def test_reputation_is_valid_bucket(self, intel: ThreatIntelligence):
        assert intel.reputation in {"clean", "suspicious", "malicious", "critical"}

    def test_geo_has_country(self, intel: ThreatIntelligence):
        # Ten minste ip-api.com geeft altijd een country — tenzij private IP
        assert intel.geo.country_code is not None, (
            "Geen land gevonden. ip-api.com should always return a country for public IPs."
        )

    def test_enriched_at_is_set(self, intel: ThreatIntelligence):
        from datetime import datetime
        assert isinstance(intel.enriched_at, datetime)


# ── ip-api.com (altijd actief, geen key) ──────────────────────────────────────

class TestIpApi:
    def test_ipapi_active(self, intel: ThreatIntelligence):
        assert "ipapi" in intel.providers_used, (
            "ip-api.com zou altijd actief moeten zijn (geen key vereist)"
        )

    def test_proxy_flag(self, intel: ThreatIntelligence):
        # 185.220.101.45 is een Tor exit — ip-api.com markeert dit als proxy
        assert intel.ipapi_is_proxy is True, (
            f"Verwacht ipapi_is_proxy=True voor {TEST_IP}. "
            f"Gekregen: {intel.ipapi_is_proxy}"
        )

    def test_is_datacenter_or_hosting(self, intel: ThreatIntelligence):
        # Tor exits draaien op servers, niet residentieel
        assert intel.ipapi_is_hosting is True or intel.is_datacenter is True


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

class TestAbuseIPDB:
    def test_abuseipdb_active_when_key_present(self, intel: ThreatIntelligence):
        if not os.getenv("ABUSEIPDB_API_KEY"):
            pytest.skip("ABUSEIPDB_API_KEY niet geconfigureerd")
        assert "abuseipdb" in intel.providers_used, (
            f"AbuseIPDB provider gefaald: {intel.providers_failed.get('abuseipdb')}"
        )

    def test_high_abuse_score(self, intel: ThreatIntelligence):
        if "abuseipdb" not in intel.providers_used:
            pytest.skip("AbuseIPDB niet actief")
        assert intel.abuse_confidence_score is not None
        assert intel.abuse_confidence_score >= 80, (
            f"Verwacht score >= 80 voor bekend Tor exit node. "
            f"Gekregen: {intel.abuse_confidence_score}"
        )

    def test_has_reports(self, intel: ThreatIntelligence):
        if "abuseipdb" not in intel.providers_used:
            pytest.skip("AbuseIPDB niet actief")
        assert (intel.abuse_total_reports or 0) > 0


# ── VirusTotal ────────────────────────────────────────────────────────────────

class TestVirusTotal:
    def test_virustotal_active_when_key_present(self, intel: ThreatIntelligence):
        if not os.getenv("VIRUSTOTAL_API_KEY"):
            pytest.skip("VIRUSTOTAL_API_KEY niet geconfigureerd")
        assert "virustotal" in intel.providers_used, (
            f"VirusTotal provider gefaald: {intel.providers_failed.get('virustotal')}"
        )

    def test_malicious_detections(self, intel: ThreatIntelligence):
        if "virustotal" not in intel.providers_used:
            pytest.skip("VirusTotal niet actief")
        assert (intel.vt_malicious or 0) >= 5, (
            f"Verwacht >= 5 malicious detections. Gekregen: {intel.vt_malicious}"
        )

    def test_total_engines_positive(self, intel: ThreatIntelligence):
        if "virustotal" not in intel.providers_used:
            pytest.skip("VirusTotal niet actief")
        assert (intel.vt_total_engines or 0) > 0


# ── Shodan ────────────────────────────────────────────────────────────────────

class TestShodan:
    def test_shodan_active(self, intel: ThreatIntelligence):
        # Shodan draait altijd via InternetDB (geen key nodig)
        assert "shodan" in intel.providers_used, (
            f"Shodan provider gefaald: {intel.providers_failed.get('shodan')}"
        )

    def test_tor_port_present(self, intel: ThreatIntelligence):
        if "shodan" not in intel.providers_used:
            pytest.skip("Shodan niet actief")
        tor_ports = {9001, 9030, 9050, 9051}
        found = tor_ports & set(intel.shodan_ports or [])
        assert found, (
            f"Verwacht Tor-gerelateerde poort in {tor_ports}. "
            f"Gevonden poorten: {intel.shodan_ports}"
        )


# ── Scoring & aggregatie ──────────────────────────────────────────────────────

class TestScoring:
    def test_is_tor_detected(self, intel: ThreatIntelligence):
        # ip-api.com alleen zou dit al moeten triggeren (proxy flag)
        # Met AbuseIPDB + Shodan tags is het zeker
        assert intel.is_tor is True or intel.ipapi_is_proxy is True, (
            "Verwacht dat het IP als TOR/proxy herkend wordt"
        )

    def test_high_threat_score_with_full_providers(self, intel: ThreatIntelligence):
        active = set(intel.providers_used)
        if not {"abuseipdb", "virustotal"}.issubset(active):
            pytest.skip(
                "Volledige score test vereist AbuseIPDB + VirusTotal API keys"
            )
        assert intel.threat_score >= 75.0, (
            f"Verwacht threat_score >= 75 (critical). "
            f"Gekregen: {intel.threat_score}"
        )
        assert intel.reputation == "critical"

    def test_at_least_suspicious_with_ipapi_only(self, intel: ThreatIntelligence):
        # Zelfs zonder betaalde API keys moet het IP als minstens suspicious scoren
        # vanwege ip-api.com proxy flag
        assert intel.threat_score >= 20.0, (
            f"Verwacht minstens 'suspicious' score. Gekregen: {intel.threat_score}"
        )


# ── Serialisatie ──────────────────────────────────────────────────────────────

class TestSerialization:
    def test_to_dict_and_back(self, intel: ThreatIntelligence):
        d = intel.to_dict()
        restored = ThreatIntelligence.from_dict(d)
        assert restored.ip == intel.ip
        assert restored.threat_score == intel.threat_score
        assert restored.reputation == intel.reputation
        assert restored.geo.country_code == intel.geo.country_code

    def test_to_json_and_back(self, intel: ThreatIntelligence):
        raw = intel.to_json()
        restored = ThreatIntelligence.from_json(raw)
        assert restored.ip == intel.ip
        assert restored.vt_tags == intel.vt_tags
        assert restored.shodan_ports == intel.shodan_ports


# ── CLI runner (python tests/test_enrichment.py) ──────────────────────────────

if __name__ == "__main__":
    import json

    async def main():
        print(f"\n{'='*60}")
        print(f"  IP Intelligence Engine — Test run")
        print(f"  Target: {TEST_IP} (known Tor exit node)")
        print(f"{'='*60}\n")

        eng = EnrichmentEngine.from_env()
        await eng.startup()

        health = await eng.health()
        print(f"Active enrichers:  {health['active_enrichers']}")
        print(f"Skipped enrichers: {health['skipped_enrichers']}")
        print(f"Cache available:   {health['cache_available']}\n")

        intel = await eng.enrich(TEST_IP, force_refresh=True)

        print(intel.summary_line())
        print()
        print(f"  Geo:         {intel.geo.city}, {intel.geo.country_code} "
              f"(ASN {intel.geo.asn} / {intel.geo.isp})")
        print(f"  TOR:         {intel.is_tor}")
        print(f"  VPN/Proxy:   {intel.is_vpn or intel.is_proxy}")
        print(f"  Datacenter:  {intel.is_datacenter or intel.ipapi_is_hosting}")
        print(f"  AbuseIPDB:   confidence={intel.abuse_confidence_score}  "
              f"reports={intel.abuse_total_reports}")
        print(f"  VirusTotal:  malicious={intel.vt_malicious}  "
              f"suspicious={intel.vt_suspicious}  "
              f"total_engines={intel.vt_total_engines}")
        print(f"  Shodan:      ports={intel.shodan_ports}  "
              f"vulns={intel.shodan_vulns}  "
              f"tags={intel.shodan_tags}")
        print(f"  Providers OK:     {intel.providers_used}")
        print(f"  Providers FAILED: {intel.providers_failed}")
        print()
        print(f"  ► THREAT SCORE:  {intel.threat_score:.1f} / 100")
        print(f"  ► REPUTATION:    {intel.reputation.upper()}")
        print()

        await eng.shutdown()

    asyncio.run(main())
