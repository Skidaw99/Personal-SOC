from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from database import get_db
from models.alert import FraudAlert, AlertStatus, AlertCategory
from models.event import SecurityEvent, EventSeverity
from models.account import SocialAccount

router = APIRouter(prefix="/stats", tags=["Stats"])


@router.get("/dashboard")
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    """
    Returns all data needed to render the founder dashboard:
    - Total accounts monitored
    - Open / acknowledged / resolved alert counts
    - Risk breakdown by severity
    - Recent alerts (last 10)
    - Platform distribution
    - Events per day (last 7 days)
    """
    # Alert counts by status
    alert_counts = {}
    for status in AlertStatus:
        result = await db.execute(
            select(func.count()).where(FraudAlert.status == status)
        )
        alert_counts[status.value] = result.scalar() or 0

    # Alert counts by category
    category_counts = {}
    for cat in AlertCategory:
        result = await db.execute(
            select(func.count()).where(FraudAlert.category == cat)
        )
        category_counts[cat.value] = result.scalar() or 0

    # Total accounts
    accounts_result = await db.execute(select(func.count()).select_from(SocialAccount))
    total_accounts = accounts_result.scalar() or 0

    # Total events
    events_result = await db.execute(select(func.count()).select_from(SecurityEvent))
    total_events = events_result.scalar() or 0

    # Severity breakdown
    severity_counts = {}
    for sev in EventSeverity:
        result = await db.execute(
            select(func.count()).where(SecurityEvent.severity == sev)
        )
        severity_counts[sev.value] = result.scalar() or 0

    # Recent open alerts (last 10)
    recent_result = await db.execute(
        select(FraudAlert)
        .where(FraudAlert.status == AlertStatus.OPEN)
        .order_by(desc(FraudAlert.created_at))
        .limit(10)
    )
    recent_alerts = recent_result.scalars().all()

    # Platform distribution of alerts
    platform_dist_result = await db.execute(
        select(SocialAccount.platform, func.count(FraudAlert.id))
        .join(FraudAlert, FraudAlert.account_id == SocialAccount.id)
        .group_by(SocialAccount.platform)
    )
    platform_distribution = {row[0].value: row[1] for row in platform_dist_result.all()}

    # Average risk score of open alerts
    avg_risk_result = await db.execute(
        select(func.avg(FraudAlert.risk_score)).where(FraudAlert.status == AlertStatus.OPEN)
    )
    avg_risk = round(avg_risk_result.scalar() or 0.0, 1)

    return {
        "summary": {
            "total_accounts": total_accounts,
            "total_events": total_events,
            "open_alerts": alert_counts.get("open", 0),
            "acknowledged_alerts": alert_counts.get("acknowledged", 0),
            "resolved_alerts": alert_counts.get("resolved", 0),
            "avg_open_risk_score": avg_risk,
        },
        "alert_by_category": category_counts,
        "event_by_severity": severity_counts,
        "platform_distribution": platform_distribution,
        "recent_open_alerts": [
            {
                "id": str(a.id),
                "title": a.title,
                "category": a.category.value,
                "risk_score": a.risk_score,
                "created_at": a.created_at.isoformat(),
            }
            for a in recent_alerts
        ],
    }
