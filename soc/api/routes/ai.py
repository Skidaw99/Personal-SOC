"""
AI Copilot API routes — /api/soc/ai/*
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from soc.ai.copilot import SOCCopilot

router = APIRouter(prefix="/api/soc/ai", tags=["ai"])

# Lazy singleton — initialized on first request
_copilot: Optional[SOCCopilot] = None


def _get_copilot() -> SOCCopilot:
    global _copilot
    if _copilot is None:
        _copilot = SOCCopilot()
    return _copilot


# ── Request schemas ──────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    event_type: str = "unknown"
    severity: str = "medium"
    risk_score: float = Field(default=0.0, ge=0, le=100)
    source_ip: Optional[str] = None
    source_country: Optional[str] = None
    description: Optional[str] = None
    intel: Optional[dict] = None
    raw_payload: Optional[dict] = None


class ChatRequest(BaseModel):
    message: str
    risk_score: float = Field(default=0.0, ge=0, le=100)
    context: Optional[dict] = None


class ActorProfileRequest(BaseModel):
    display_name: Optional[str] = None
    threat_level: str = "medium"
    risk_score: float = Field(default=50.0, ge=0, le=100)
    total_events: int = 0
    known_ips: list[str] = Field(default_factory=list)
    known_countries: list[str] = Field(default_factory=list)
    platforms_targeted: list[str] = Field(default_factory=list)
    attack_categories: list[str] = Field(default_factory=list)
    is_tor: Optional[bool] = None
    is_vpn: Optional[bool] = None
    uses_automation: Optional[bool] = None
    ip_intel: Optional[list[dict]] = None


class FBIBriefRequest(BaseModel):
    case_reference: str
    incident_type: str
    risk_score: float = Field(default=80.0, ge=0, le=100)
    incident_date: Optional[str] = None
    actor_profile: Optional[dict] = None
    involved_ips: list[dict] = Field(default_factory=list)
    timeline: list[dict] = Field(default_factory=list)


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/analyze")
async def analyze_alert(req: AnalyzeRequest) -> dict[str, Any]:
    """Analyze a security alert — returns structured threat assessment."""
    copilot = _get_copilot()
    result = await copilot.analyze_alert(req.model_dump(), req.risk_score)
    return result.to_dict()


@router.post("/chat")
async def chat(req: ChatRequest) -> dict[str, Any]:
    """Free-form SOC analyst question."""
    copilot = _get_copilot()
    result = await copilot.answer_question(req.message, req.context, req.risk_score)
    return result.to_dict()


@router.post("/profile")
async def actor_profile(req: ActorProfileRequest) -> dict[str, Any]:
    """Generate a threat actor profile summary."""
    copilot = _get_copilot()
    result = await copilot.summarize_actor(req.model_dump(), req.risk_score)
    return result.to_dict()


@router.post("/fbi-brief")
async def fbi_brief(req: FBIBriefRequest) -> dict[str, Any]:
    """Generate FBI IC3-format incident brief."""
    copilot = _get_copilot()
    result = await copilot.generate_fbi_brief(req.model_dump(), req.risk_score)
    return result.to_dict()


@router.get("/health")
async def ai_health() -> dict[str, Any]:
    """Check AI backend availability."""
    copilot = _get_copilot()
    return await copilot.health()
