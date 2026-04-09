import uuid
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from database import get_db
from models.event import SecurityEvent, EventSeverity

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("/")
async def list_events(
    account_id: uuid.UUID | None = None,
    severity: EventSeverity | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    q = select(SecurityEvent).order_by(desc(SecurityEvent.occurred_at)).limit(limit).offset(offset)
    if account_id:
        q = q.where(SecurityEvent.account_id == account_id)
    if severity:
        q = q.where(SecurityEvent.severity == severity)
    result = await db.execute(q)
    events = result.scalars().all()
    return [_serialize(e) for e in events]


@router.get("/{event_id}")
async def get_event(event_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    from fastapi import HTTPException
    result = await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return _serialize(event)


def _serialize(e: SecurityEvent) -> dict:
    return {
        "id": str(e.id),
        "account_id": str(e.account_id),
        "event_type": e.event_type.value,
        "severity": e.severity.value,
        "risk_score": e.risk_score,
        "source_ip": e.source_ip,
        "source_country": e.source_country,
        "source_device": e.source_device,
        "client_app": e.client_app,
        "description": e.description,
        "occurred_at": e.occurred_at.isoformat(),
        "ingested_at": e.ingested_at.isoformat(),
    }
