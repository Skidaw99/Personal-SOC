"""
AI Copilot — request / response schemas.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────

class CopilotCapability(str, Enum):
    """Beschikbare copilot acties."""
    ALERT_ANALYSIS = "alert_analysis"
    THREAT_PROFILE = "threat_profile"
    FBI_REPORT = "fbi_report"
    CHAT = "chat"


class AIBackend(str, Enum):
    """Welke backend is gebruikt voor de response."""
    OLLAMA = "ollama"
    CLAUDE = "claude"


# ── Request models ───────────────────────────────────────────────────────────

class AlertAnalysisRequest(BaseModel):
    """Input voor alert analyse."""
    alert_id: Optional[UUID] = None
    event_type: str = Field(..., description="Type event, bijv. brute_force, malware_callback")
    source_ip: Optional[str] = None
    severity: str = Field(default="medium", description="info/low/medium/high/critical")
    risk_score: float = Field(default=0.0, ge=0, le=100, description="Risk score 0-100")
    description: Optional[str] = None
    raw_payload: Optional[dict] = None
    # Enrichment data (optioneel, van enrichment engine)
    threat_intel: Optional[dict] = None


class ThreatProfileRequest(BaseModel):
    """Input voor threat actor profiel samenvatting."""
    actor_id: Optional[UUID] = None
    display_name: Optional[str] = None
    threat_level: str = Field(default="medium")
    risk_score: float = Field(default=50.0, ge=0, le=100)
    known_ips: list[str] = Field(default_factory=list)
    known_countries: list[str] = Field(default_factory=list)
    attack_categories: list[str] = Field(default_factory=list)
    platforms_targeted: list[str] = Field(default_factory=list)
    total_events: int = Field(default=0)
    is_tor: Optional[bool] = None
    is_vpn: Optional[bool] = None
    uses_automation: Optional[bool] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    analyst_notes: Optional[str] = None
    # Enrichment intel voor de IPs (optioneel)
    ip_intel: Optional[list[dict]] = None


class FBIReportRequest(BaseModel):
    """Input voor FBI Internet Crime Complaint Center (IC3) rapport."""
    case_reference: str = Field(..., description="Intern case referentienummer")
    risk_score: float = Field(default=80.0, ge=0, le=100)
    incident_type: str = Field(..., description="Type incident bijv. unauthorized_access, ransomware")
    incident_date: datetime = Field(default_factory=datetime.utcnow)
    # Threat actor data
    actor_profile: Optional[dict] = None
    # Alle gerelateerde IPs met enrichment data
    involved_ips: list[dict] = Field(default_factory=list)
    # Timeline van events
    event_timeline: list[dict] = Field(default_factory=list)
    # Getroffen systemen/accounts
    affected_systems: list[str] = Field(default_factory=list)
    # Geschatte schade
    estimated_impact: Optional[str] = None
    # Bewijsstukken (referenties naar bestanden/logs)
    evidence_references: list[str] = Field(default_factory=list)
    # Aanvullende context
    additional_context: Optional[str] = None


class ChatRequest(BaseModel):
    """Vrije SOC chat vraag."""
    message: str = Field(..., description="Vraag of opdracht van de analist")
    risk_score: float = Field(default=0.0, ge=0, le=100, description="Optioneel: risk context")
    context: Optional[dict] = None


# ── Response model ───────────────────────────────────────────────────────────

class CopilotResponse(BaseModel):
    """Gestandaardiseerd antwoord van de AI Copilot."""
    capability: CopilotCapability
    backend_used: AIBackend
    model_used: str
    content: str = Field(..., description="LLM-gegenereerde output (markdown)")
    risk_score: float = Field(description="Risk score die routing bepaalde")
    processing_time_ms: float = Field(description="Totale verwerkingstijd in ms")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None
