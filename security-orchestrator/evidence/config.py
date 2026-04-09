"""
Evidence Builder configuratie.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class EvidenceSettings(BaseSettings):
    """
    Configuratie voor de Evidence Builder.

    Env vars:
      EVIDENCE_OUTPUT_DIR     — Map waar gegenereerde PDF's worden opgeslagen
      EVIDENCE_ORG_NAME       — Organisatienaam voor rapport headers
      EVIDENCE_CLASSIFICATION — Classificatieniveau (TLP:RED, TLP:AMBER, etc.)
    """

    evidence_output_dir: str = Field(
        default="/data/evidence",
        description="Output directory voor gegenereerde PDF rapporten",
    )
    evidence_org_name: str = Field(
        default="SOC Security Operations Center",
        description="Organisatienaam op het rapport",
    )
    evidence_classification: str = Field(
        default="TLP:AMBER",
        description="Classificatieniveau voor het rapport (TLP:RED/AMBER/GREEN/CLEAR)",
    )
    evidence_analyst_name: str = Field(
        default="SOC Automated System",
        description="Standaard analist naam als geen specifieke analist is opgegeven",
    )
    evidence_logo_path: str = Field(
        default="",
        description="Pad naar organisatie logo (PNG/JPG) voor de cover page",
    )

    model_config = {"env_prefix": "", "case_sensitive": False}


evidence_settings = EvidenceSettings()
