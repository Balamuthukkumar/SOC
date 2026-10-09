from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from app.deps import DB, CurrentUser, require_role
from app.models import Alert, RemediationAction
from app.services import remediation
from app.services.alert_checker import run_check
from app.services.epss import fetch_epss
from app.schemas.alert import AlertList, AlertOut, AlertPatch, AlertStats, AlertStatus, Severity
from app.schemas.common import pages

router = APIRouter()


async def _owned(db, user, alert_id: int) -> Alert:
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id, Alert.user_id == user.id))).scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@router.get("/stats/overview", response_model=AlertStats)
async def stats(user: CurrentUser, db: DB):
    """Real alerts only — a vulnerability match against a real asset, from a real feed run. Demo/test data is
    always excluded here regardless of role, since this backs the dashboard summary tiles."""
    real = (Alert.user_id == user.id, Alert.is_synthetic.is_(False))
    sev = dict((await db.execute(select(Alert.severity, func.count()).where(*real)
                                 .group_by(Alert.severity))).all())
    st = dict((await db.execute(select(Alert.status, func.count()).where(*real)
                                .group_by(Alert.status))).all())
    return AlertStats(
        total_alerts=sum(sev.values()), critical_alerts=sev.get("critical", 0), high_alerts=sev.get("high", 0),
        medium_alerts=sev.get("medium", 0), low_alerts=sev.get("low", 0),
        pending_alerts=st.get("pending", 0), acknowledged_alerts=st.get("acknowledged", 0))


@router.get("/", response_model=AlertList)
async def list_alerts(user: CurrentUser, db: DB, page: int = Query(1, ge=1), size: int = Query(10, ge=1, le=100),
                      severity: Severity | None = None, status: AlertStatus | None = None,
                      asset_id: int | None = None, cve_id: str | None = None,
                      include_synthetic: bool = Query(False, description="Admin-only: also show demo/test alerts")):
    where = [Alert.user_id == user.id]
    if not (include_synthetic and user.role == "admin"):
        where.append(Alert.is_synthetic.is_(False))
    if severity: where.append(Alert.severity == severity.value)
    if status: where.append(Alert.status == status.value)
    if asset_id: where.append(Alert.asset_id == asset_id)
    if cve_id: where.append(Alert.cve_id == cve_id)
    total = (await db.execute(select(func.count(Alert.id)).where(*where))).scalar_one()
    rows = (await db.execute(select(Alert).where(*where).order_by(Alert.created_at.desc())
                             .offset((page - 1) * size).limit(size))).scalars().all()
    return AlertList(alerts=[AlertOut.build(a) for a in rows], total=total, page=page, size=size,
                     pages=pages(total, size))


@router.post("/scan", dependencies=[require_role("admin")])
async def scan_now(db: DB, hours_back: int = Query(6, ge=1, le=168)):
    """Run the vulnerability feed check immediately (admin only)."""
    return {"success": True, "data": await run_check(db, hours_back)}


@router.get("/{alert_id}/remediations")
async def remediations(alert_id: int, user: CurrentUser, db: DB):
    alert = await _owned(db, user, alert_id)
    rows = (await db.execute(select(RemediationAction).where(RemediationAction.alert_id == alert_id)
                             .order_by(RemediationAction.priority))).scalars().all()
    if not rows:
        rows = [RemediationAction(alert_id=alert_id, **step) for step in remediation.generate(alert, alert.asset)]
        db.add_all(rows)
        await db.commit()
    return {"success": True, "data": [{c.name: getattr(r, c.name) for c in RemediationAction.__table__.columns} for r in rows]}


@router.get("/{alert_id}/epss")
async def epss(alert_id: int, user: CurrentUser, db: DB):
    alert = await _owned(db, user, alert_id)
    if not alert.cve_id:
        raise HTTPException(400, "Alert has no CVE id")
    if alert.epss_score is None:
        try:
            score, pct = (await fetch_epss([alert.cve_id])).get(alert.cve_id, (None, None))
        except Exception:
            raise HTTPException(502, "EPSS service unavailable")
        alert.epss_score, alert.epss_percentile = score, pct
        await db.commit()
    return {"success": True, "data": {"cve_id": alert.cve_id, "epss": alert.epss_score, "percentile": alert.epss_percentile}}


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: int, user: CurrentUser, db: DB):
    return AlertOut.build(await _owned(db, user, alert_id))


@router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(alert_id: int, body: AlertPatch, user: CurrentUser, db: DB):
    alert = await _owned(db, user, alert_id)
    alert.status = body.status.value
    if body.status == AlertStatus.acknowledged:
        alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    return AlertOut.build(alert)


@router.post("/{alert_id}/acknowledge")
async def acknowledge(alert_id: int, user: CurrentUser, db: DB):
    alert = await _owned(db, user, alert_id)
    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": "Alert acknowledged successfully"}
