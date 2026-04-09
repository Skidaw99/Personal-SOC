import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from database import get_db
from models.alert import FraudAlert, AlertStatus, AlertCategory
from models.account import SocialAccount
from utils.logger import get_logger

router = APIRouter(prefix="/alerts", tags=["Alerts"])
logger = get_logger(__name__)


class AlertAcknowledge(BaseModel):
    notes: str | None = None


class AlertResolve(BaseModel):
    status: AlertStatus
    notes: str | None = None


@router.get("/")
async def list_alerts(
    status: AlertStatus | None = None,
    category: AlertCategory | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    q = select(FraudAlert).order_by(desc(FraudAlert.created_at)).limit(limit).offset(offset)
    if status:
        q = q.where(FraudAlert.status == status)
    if category:
        q = q.where(FraudAlert.category == category)
    result = await db.execute(q)
    alerts = result.scalars().all()
    return [_serialize(a) for a in alerts]


@router.get("/{alert_id}")
async def get_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    alert = await _get_or_404(db, alert_id)
    return _serialize(alert)


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: uuid.UUID, body: AlertAcknowledge, db: AsyncSession = Depends(get_db)):
    from datetime import datetime
    alert = await _get_or_404(db, alert_id)
    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = datetime.utcnow()
    if body.notes:
        alert.notes = body.notes
    await db.commit()
    return _serialize(alert)


@router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: uuid.UUID, body: AlertResolve, db: AsyncSession = Depends(get_db)):
    from datetime import datetime
    alert = await _get_or_404(db, alert_id)
    alert.status = body.status
    alert.resolved_at = datetime.utcnow()
    if body.notes:
        alert.notes = body.notes
    await db.commit()
    return _serialize(alert)


async def _get_or_404(db: AsyncSession, alert_id: uuid.UUID) -> FraudAlert:
    result = await db.execute(select(FraudAlert).where(FraudAlert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


def _serialize(a: FraudAlert) -> dict:
    return {
        "id": str(a.id),
        "account_id": str(a.account_id),
        "triggering_event_id": str(a.triggering_event_id) if a.triggering_event_id else None,
        "category": a.category.value,
        "status": a.status.value,
        "risk_score": a.risk_score,
        "title": a.title,
        "description": a.description,
        "recommended_action": a.recommended_action,
        "evidence": a.evidence,
        "email_sent": a.email_sent,
        "webhook_sent": a.webhook_sent,
        "created_at": a.created_at.isoformat(),
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
        "notes": a.notes,
    }
