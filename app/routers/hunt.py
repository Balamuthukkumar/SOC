from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.deps import DB, CurrentUser
from app.models import DetectionRule, HuntSession
from app.models.base import utcnow
from app.schemas.common import ORM
from app.services.agents.hunt import HuntAgent

router = APIRouter()


class HuntRequest(BaseModel):
    hypothesis: str


class RuleIn(BaseModel):
    name: str
    rule_type: str
    rule_content: str
    description: str | None = None
    mitre_techniques: list | None = None
    confidence: str = "medium"


class RuleOut(RuleIn, ORM):
    id: int
    enabled: bool
    created_by: str


@router.post("/")
async def start_hunt(body: HuntRequest, user: CurrentUser, db: DB):
    if not body.hypothesis.strip():
        raise HTTPException(422, "hypothesis must not be empty")
    session = HuntSession(user_id=user.id, hypothesis=body.hypothesis)
    db.add(session)
    await db.flush()
    result = await HuntAgent(db, user.id).execute(hypothesis=body.hypothesis)
    runs = result["query_results"]
    session.status, session.completed_at = "completed", utcnow()
    session.queries_run = len(runs)
    session.findings_count = sum(r["row_count"] for r in runs)
    session.result_data, session.sigma_rule = runs, result.get("sigma_rule")
    await db.commit()
    return {"success": True, "data": {**result, "session_id": session.id}}


@router.get("/")
async def list_hunts(user: CurrentUser, db: DB):
    rows = (await db.execute(select(HuntSession).where(HuntSession.user_id == user.id)
                             .order_by(HuntSession.created_at.desc()).limit(50))).scalars().all()
    return [{c.name: getattr(r, c.name) for c in HuntSession.__table__.columns if c.name != "result_data"} for r in rows]


@router.post("/detections", response_model=RuleOut, status_code=201)
async def create_rule(body: RuleIn, user: CurrentUser, db: DB):
    rule = DetectionRule(user_id=user.id, **body.model_dump())
    db.add(rule)
    await db.commit()
    return rule


@router.get("/detections", response_model=list[RuleOut])
async def list_rules(user: CurrentUser, db: DB):
    return (await db.execute(select(DetectionRule).where(DetectionRule.user_id == user.id)
                             .order_by(DetectionRule.created_at.desc()))).scalars().all()


@router.get("/{session_id}")
async def get_hunt(session_id: int, user: CurrentUser, db: DB):
    s = (await db.execute(select(HuntSession).where(HuntSession.id == session_id, HuntSession.user_id == user.id))).scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Hunt session not found")
    return {"success": True, "data": {c.name: getattr(s, c.name) for c in HuntSession.__table__.columns}}
