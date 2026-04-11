"""
Intel API routes — /api/soc/intel/*

Exposes the IntelEngine lookup via REST.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/soc/intel", tags=["intel"])


class LookupRequest(BaseModel):
    ip: str


@router.post("/lookup")
async def lookup_ip(req: LookupRequest) -> dict:
    """Full IP intelligence enrichment lookup."""
    from soc.main import _intel_engine

    if _intel_engine is None:
        raise HTTPException(status_code=503, detail="Intel engine not initialized")

    try:
        result = await _intel_engine.lookup(req.ip)
        return result.to_api_response()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
