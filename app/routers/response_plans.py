from fastapi import APIRouter, Body, HTTPException, Query
from sqlalchemy import func, select

from app.deps import DB, CurrentUser
from app.models import ApprovalRequest, ResponsePlan
from app.models.base import utcnow
from app.services.agents.response import ResponseAgent
from app.services.executor import execute_plan
from app.services.policy import AUTONOMY_LEVELS

router = APIRouter()


def plan_dict(p: ResponsePlan) -> dict:
    return {c.name: getattr(p, c.name) for c in ResponsePlan.__table__.columns}


async def _owned(db, user, plan_id: int) -> ResponsePlan:
    plan = (await db.execute(select(ResponsePlan).where(ResponsePlan.id == plan_id, ResponsePlan.user_id == user.id))).scalar_one_or_none()
    if not plan:
        raise HTTPException(404, "Response plan not found")
    return plan


async def _resolve(db, plan_id: int, status: str, reviewer: int, reason: str | None = None) -> int:
    pending = (await db.execute(select(ApprovalRequest).where(
        ApprovalRequest.plan_id == plan_id, ApprovalRequest.status == "pending"))).scalars().all()
    for a in pending:
        a.status, a.reviewed_by, a.reviewed_at = status, reviewer, utcnow()
        if reason:
            a.reason = reason
    return len(pending)


@router.get("/autonomy-levels")
async def autonomy_levels():
    return [{"level": k, "name": v["name"], "auto_approve": v["auto_approve"]} for k, v in AUTONOMY_LEVELS.items()]


@router.post("/generate")
async def generate(user: CurrentUser, db: DB, case_id: int = Query(...), autonomy_level: str = Query("L1")):
    if autonomy_level not in AUTONOMY_LEVELS:
        raise HTTPException(422, f"autonomy_level must be one of {list(AUTONOMY_LEVELS)}")
    try:
        result = await ResponseAgent(db, user.id).execute(case_id=case_id, autonomy_level=autonomy_level)
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    return {"success": True, "data": result}


@router.get("/")
async def list_plans(user: CurrentUser, db: DB, page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100),
                     status: str | None = None, case_id: int | None = None):
    where = [ResponsePlan.user_id == user.id]
    if status: where.append(ResponsePlan.status == status)
    if case_id: where.append(ResponsePlan.case_id == case_id)
    total = (await db.execute(select(func.count(ResponsePlan.id)).where(*where))).scalar_one()
    rows = (await db.execute(select(ResponsePlan).where(*where).order_by(ResponsePlan.created_at.desc())
                             .offset((page - 1) * size).limit(size))).scalars().all()
    return {"success": True, "data": [plan_dict(p) for p in rows], "total": total, "page": page, "size": size}


@router.get("/pending-approvals")
async def pending(user: CurrentUser, db: DB):
    rows = (await db.execute(select(ApprovalRequest, ResponsePlan).join(ResponsePlan, ApprovalRequest.plan_id == ResponsePlan.id)
                             .where(ResponsePlan.user_id == user.id, ApprovalRequest.status == "pending")
                             .order_by(ApprovalRequest.created_at.desc()))).all()
    data = [{"id": a.id, "plan_id": p.id, "case_id": p.case_id, "status": a.status, "reason": a.reason,
             "requested_by": a.requested_by, "actions": p.actions, "autonomy_level": p.autonomy_level,
             "created_at": a.created_at} for a, p in rows]
    return {"success": True, "data": data, "total": len(data)}


@router.get("/{plan_id}")
async def get_plan(plan_id: int, user: CurrentUser, db: DB):
    return plan_dict(await _owned(db, user, plan_id))


@router.post("/{plan_id}/approve")
async def approve(plan_id: int, user: CurrentUser, db: DB):
    plan = await _owned(db, user, plan_id)
    if plan.status not in ("pending_approval", "draft"):
        raise HTTPException(400, f"Plan status is '{plan.status}', cannot approve")
    plan.status, plan.approved_by, plan.approved_at = "approved", user.id, utcnow()
    n = await _resolve(db, plan_id, "approved", user.id)
    await db.commit()
    return {"success": True, "message": f"Plan {plan_id} approved", "plan_status": plan.status, "approvals_resolved": n}


@router.post("/{plan_id}/reject")
async def reject(plan_id: int, user: CurrentUser, db: DB, reason: str = Body("", embed=True)):
    plan = await _owned(db, user, plan_id)
    if plan.status not in ("pending_approval", "draft"):
        raise HTTPException(400, f"Plan status is '{plan.status}', cannot reject")
    plan.status = "rejected"
    await _resolve(db, plan_id, "rejected", user.id, reason)
    await db.commit()
    return {"success": True, "message": f"Plan {plan_id} rejected", "plan_status": plan.status}


@router.post("/{plan_id}/execute")
async def execute(plan_id: int, user: CurrentUser, db: DB):
    plan = await _owned(db, user, plan_id)
    if plan.status != "approved":
        raise HTTPException(400, f"Plan must be approved before execution (current: '{plan.status}')")
    return {"success": True, "data": await execute_plan(db, plan)}
