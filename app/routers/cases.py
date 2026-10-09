from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from app.deps import DB, CurrentUser
from app.models import AgentRun, Alert, Case, CaseAlert, CaseEvent, SecurityEvent
from app.services.agents.orchestrator import run_pipeline
from app.services.agents.triage import TriageAgent
from app.services.similarity import blast_radius, search_cases, similar_cases
from app.schemas.alert import AlertOut
from app.schemas.case import CaseDetail, CaseList, CaseOut, CasePatch
from app.schemas.event import EventOut

router = APIRouter()


async def _counts(db, case_id: int) -> tuple[int, int]:
    a = (await db.execute(select(func.count(CaseAlert.id)).where(CaseAlert.case_id == case_id))).scalar_one()
    e = (await db.execute(select(func.count(CaseEvent.id)).where(CaseEvent.case_id == case_id))).scalar_one()
    return a, e


async def _owned(db, user, case_id: int) -> Case:
    case = (await db.execute(select(Case).where(Case.id == case_id, Case.user_id == user.id))).scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.get("/", response_model=CaseList)
async def list_cases(user: CurrentUser, db: DB, page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100),
                     severity: str | None = None, status: str | None = None,
                     include_synthetic: bool = Query(False, description="Admin-only: also show demo/test cases")):
    where = [Case.user_id == user.id]
    if not (include_synthetic and user.role == "admin"):
        where.append(Case.is_synthetic.is_(False))
    if severity: where.append(Case.severity == severity)
    if status: where.append(Case.status == status)
    total = (await db.execute(select(func.count(Case.id)).where(*where))).scalar_one()
    rows = (await db.execute(select(Case).where(*where).order_by(Case.created_at.desc())
                             .offset((page - 1) * size).limit(size))).scalars().all()
    out = []
    for c in rows:
        item = CaseOut.model_validate(c)
        item.alert_count, item.event_count = await _counts(db, c.id)
        out.append(item)
    return CaseList(cases=out, total=total, page=page, size=size)


@router.get("/search")
async def search(user: CurrentUser, db: DB, q: str = Query(..., min_length=2), max_results: int = Query(10, ge=1, le=50),
                 include_synthetic: bool = Query(False, description="Admin-only: also search demo/test cases")):
    inc = include_synthetic and user.role == "admin"
    return {"success": True, "data": await search_cases(db, user.id, q, max_results, include_synthetic=inc), "query": q}


@router.get("/agents/runs")
async def agent_runs(user: CurrentUser, db: DB):
    rows = (await db.execute(select(AgentRun).where(AgentRun.user_id == user.id)
                             .order_by(AgentRun.started_at.desc()).limit(50))).scalars().all()
    return [{c.name: getattr(r, c.name) for c in AgentRun.__table__.columns if c.name != "error_message"} for r in rows]


@router.post("/pipeline")
async def pipeline(user: CurrentUser, db: DB, hours_back: int = Query(24, ge=1, le=168)):
    return {"success": True, "data": await run_pipeline(db, user.id, hours_back)}


@router.post("/auto-triage")
async def auto_triage(user: CurrentUser, db: DB, hours_back: int = Query(24, ge=1, le=168)):
    result = await TriageAgent(db, user.id).execute(hours_back=hours_back)
    return {"success": True, "data": {"cases_created": result["cases_created"], "summary": result["summary"]}}


@router.get("/{case_id}", response_model=CaseDetail)
async def get_case(case_id: int, user: CurrentUser, db: DB):
    case = await _owned(db, user, case_id)
    detail = CaseDetail.model_validate(case)
    detail.alert_count, detail.event_count = await _counts(db, case_id)
    return detail


@router.patch("/{case_id}", response_model=CaseOut)
async def update_case(case_id: int, body: CasePatch, user: CurrentUser, db: DB):
    case = await _owned(db, user, case_id)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(case, k, v)
    await db.commit()
    return CaseOut.model_validate(case)


@router.get("/{case_id}/similar")
async def similar(case_id: int, user: CurrentUser, db: DB, max_results: int = Query(5, ge=1, le=20),
                  include_synthetic: bool = Query(False, description="Admin-only: also compare against demo/test cases")):
    inc = include_synthetic and user.role == "admin"
    result = await similar_cases(db, user.id, case_id, max_results, include_synthetic=inc)
    if result is None:
        raise HTTPException(404, "Case not found")
    return {"success": True, "data": result}


@router.get("/{case_id}/blast-radius")
async def blast(case_id: int, user: CurrentUser, db: DB):
    result = await blast_radius(db, user.id, case_id)
    if result is None:
        raise HTTPException(404, "Case not found")
    return {"success": True, "data": result}


@router.get("/{case_id}/alerts", response_model=list[AlertOut])
async def case_alerts(case_id: int, user: CurrentUser, db: DB):
    await _owned(db, user, case_id)
    q = select(Alert).join(CaseAlert, CaseAlert.alert_id == Alert.id).where(CaseAlert.case_id == case_id)
    return [AlertOut.build(a) for a in (await db.execute(q)).scalars().all()]


@router.get("/{case_id}/events", response_model=list[EventOut])
async def case_events(case_id: int, user: CurrentUser, db: DB):
    await _owned(db, user, case_id)
    q = (select(SecurityEvent).join(CaseEvent, CaseEvent.event_id == SecurityEvent.id)
         .where(CaseEvent.case_id == case_id).order_by(SecurityEvent.timestamp))
    return (await db.execute(q)).scalars().all()
