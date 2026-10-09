from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select

from app.deps import DB, CurrentUser
from app.models import ValidationRun, ValidationStep
from app.services.agents.purple import ATOMIC_TESTS, PurpleAgent

router = APIRouter()


class RunIn(BaseModel):
    name: str
    description: str | None = None
    mode: str = "dry_run"
    scope: dict | None = None
    mitre_techniques: list[str] = []


def run_dict(r: ValidationRun, steps: bool = False) -> dict:
    d = {c.name: getattr(r, c.name) for c in ValidationRun.__table__.columns}
    if steps:
        d["steps"] = [{c.name: getattr(s, c.name) for c in ValidationStep.__table__.columns} for s in r.steps]
    return d


async def _owned(db, user, run_id: int) -> ValidationRun:
    r = (await db.execute(select(ValidationRun).where(ValidationRun.id == run_id, ValidationRun.user_id == user.id))).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Validation run not found")
    return r


@router.get("/techniques")
async def techniques():
    return [{"id": k, "name": v[0], "tests": [t[0] for t in v[1]]} for k, v in ATOMIC_TESTS.items()]


@router.get("/runs")
async def list_runs(user: CurrentUser, db: DB, page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100),
                    status: str | None = None):
    where = [ValidationRun.user_id == user.id] + ([ValidationRun.status == status] if status else [])
    total = (await db.execute(select(func.count(ValidationRun.id)).where(*where))).scalar_one()
    rows = (await db.execute(select(ValidationRun).where(*where).order_by(ValidationRun.created_at.desc())
                             .offset((page - 1) * size).limit(size))).scalars().all()
    return {"success": True, "data": [run_dict(r) for r in rows], "total": total, "page": page, "size": size}


@router.post("/runs", status_code=201)
async def create_run(body: RunIn, user: CurrentUser, db: DB):
    if body.mode != "dry_run":
        raise HTTPException(403, "Only 'dry_run' mode is available; live execution is not implemented")
    unknown = [t for t in body.mitre_techniques if t not in ATOMIC_TESTS]
    if unknown:
        raise HTTPException(422, f"No atomic tests for: {', '.join(unknown)}")
    run = ValidationRun(user_id=user.id, **body.model_dump())
    db.add(run)
    await db.commit()
    return {"success": True, "data": run_dict(run)}


@router.get("/runs/{run_id}")
async def get_run(run_id: int, user: CurrentUser, db: DB):
    return {"success": True, "data": run_dict(await _owned(db, user, run_id), steps=True)}


@router.post("/runs/{run_id}/execute")
async def execute_run(run_id: int, user: CurrentUser, db: DB):
    run = await _owned(db, user, run_id)
    if run.status not in ("pending", "failed"):
        raise HTTPException(400, f"Run status is '{run.status}', cannot execute")
    result = await PurpleAgent(db, user.id).execute(run_id=run_id)
    return {"success": True, "data": {"run_id": run_id, "status": "completed", "results": result["results"],
                                      "summary": result["summary"]}}


@router.get("/coverage")
async def coverage(user: CurrentUser, db: DB):
    detected = func.sum(case((ValidationStep.result == "detected", 1), else_=0))
    rows = (await db.execute(
        select(ValidationStep.technique_id, ValidationStep.technique_name, func.count(ValidationStep.id), detected)
        .join(ValidationRun, ValidationRun.id == ValidationStep.run_id)
        .where(ValidationRun.user_id == user.id)
        .group_by(ValidationStep.technique_id, ValidationStep.technique_name))).all()
    return {"success": True, "data": [
        {"technique_id": t, "technique_name": n, "total_tests": total, "detections": int(d or 0),
         "detection_rate": round((d or 0) / total * 100, 1)} for t, n, total, d in rows]}
