"""
Threat Actor API routes — /api/soc/actors/*

Aggregates threat actors from correlated security events.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func, distinct, desc
from sqlalchemy.ext.asyncio import AsyncSession

from soc.database import get_db
from soc.models.security_event import SocSecurityEvent

router = APIRouter(prefix="/api/soc/actors", tags=["actors"])


def _threat_level(max_risk: float) -> str:
    if max_risk >= 90:
        return "critical"
    if max_risk >= 70:
        return "high"
    if max_risk >= 50:
        return "medium"
    return "low"


@router.get("/")
async def list_actors(db: AsyncSession = Depends(get_db)) -> list[dict[str, Any]]:
    """List all detected threat actors with aggregated stats."""
    stmt = (
        select(
            SocSecurityEvent.threat_actor_id,
            func.count(SocSecurityEvent.id).label("event_count"),
            func.max(SocSecurityEvent.threat_score).label("max_risk"),
            func.min(SocSecurityEvent.occurred_at).label("first_seen"),
            func.max(SocSecurityEvent.occurred_at).label("last_seen"),
        )
        .where(SocSecurityEvent.threat_actor_id.isnot(None))
        .group_by(SocSecurityEvent.threat_actor_id)
        .order_by(desc("last_seen"))
    )
    rows = (await db.execute(stmt)).all()

    actors = []
    for row in rows:
        actor_id = row.threat_actor_id
        # Fetch distinct IPs, countries, display name from events
        detail_stmt = (
            select(SocSecurityEvent)
            .where(SocSecurityEvent.threat_actor_id == actor_id)
            .order_by(SocSecurityEvent.occurred_at.desc())
            .limit(100)
        )
        events = (await db.execute(detail_stmt)).scalars().all()

        ips = sorted({e.source_ip for e in events if e.source_ip})
        countries = sorted({e.source_country for e in events if e.source_country})
        platforms = sorted({
            e.raw_payload.get("platform") or e.raw_payload.get("alert_category") or "unknown"
            for e in events if e.raw_payload and isinstance(e.raw_payload, dict)
        })

        # Use first event's display name or generate from actor_id
        display_name = None
        for e in events:
            if e.raw_payload and isinstance(e.raw_payload, dict):
                dn = e.raw_payload.get("actor_display_name")
                if dn:
                    display_name = dn
                    break
        if not display_name:
            display_name = f"ACTOR-{str(actor_id)[:8].upper()}"

        actors.append({
            "id": str(actor_id),
            "display_name": display_name,
            "threat_level": _threat_level(row.max_risk or 0),
            "max_risk_score": round(row.max_risk or 0, 1),
            "event_count": row.event_count,
            "known_ips": ips,
            "known_countries": countries,
            "platforms": platforms,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "is_tor": any(e.ip_is_tor for e in events),
            "is_vpn": any(e.ip_is_vpn for e in events),
            "uses_automation": len(events) >= 10,
        })

    return actors


@router.get("/{actor_id}")
async def get_actor(actor_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """Get detailed threat actor profile with full event timeline."""
    stmt = (
        select(SocSecurityEvent)
        .where(SocSecurityEvent.threat_actor_id == actor_id)
        .order_by(SocSecurityEvent.occurred_at.desc())
        .limit(200)
    )
    events = (await db.execute(stmt)).scalars().all()

    if not events:
        raise HTTPException(status_code=404, detail="Actor not found")

    ips = sorted({e.source_ip for e in events if e.source_ip})
    countries = sorted({e.source_country for e in events if e.source_country})
    platforms = sorted({
        e.raw_payload.get("platform") or e.raw_payload.get("alert_category") or "unknown"
        for e in events if e.raw_payload and isinstance(e.raw_payload, dict)
    })
    max_risk = max((e.threat_score or 0) for e in events)

    display_name = None
    for e in events:
        if e.raw_payload and isinstance(e.raw_payload, dict):
            dn = e.raw_payload.get("actor_display_name")
            if dn:
                display_name = dn
                break
    if not display_name:
        display_name = f"ACTOR-{str(actor_id)[:8].upper()}"

    timeline = []
    for e in events:
        timeline.append({
            "id": str(e.id),
            "event_type": e.event_type.value if e.event_type else "unknown",
            "severity": e.severity.value if e.severity else "medium",
            "threat_score": round(e.threat_score or 0, 1),
            "source_ip": e.source_ip,
            "source_country": e.source_country,
            "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
            "status": e.status.value if e.status else "new",
        })

    return {
        "id": str(actor_id),
        "display_name": display_name,
        "threat_level": _threat_level(max_risk),
        "max_risk_score": round(max_risk, 1),
        "event_count": len(events),
        "known_ips": ips,
        "known_countries": countries,
        "platforms": platforms,
        "first_seen": events[-1].occurred_at.isoformat() if events else None,
        "last_seen": events[0].occurred_at.isoformat() if events else None,
        "is_tor": any(e.ip_is_tor for e in events),
        "is_vpn": any(e.ip_is_vpn for e in events),
        "uses_automation": len(events) >= 10,
        "timeline": timeline,
    }
