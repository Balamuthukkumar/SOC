from fastapi import APIRouter
from sqlalchemy import select

from app.deps import DB, CurrentUser
from app.models import Case
from app.services.mitre import TACTICS, TECHNIQUES, compute_coverage, search_techniques

router = APIRouter()


@router.get("/tactics")
async def tactics():
    return [{"id": k, **v} for k, v in TACTICS.items()]


@router.get("/techniques")
async def techniques(search: str | None = None, tactic: str | None = None):
    if search:
        return search_techniques(search)
    return [{"id": k, **v} for k, v in TECHNIQUES.items() if not tactic or tactic in v["tactics"]]


@router.get("/coverage")
async def coverage(user: CurrentUser, db: DB):
    """Coverage reflects real, confirmed cases only — a demo/test case must never inflate detection coverage."""
    rows = (await db.execute(select(Case.mitre_techniques).where(
        Case.user_id == user.id, Case.mitre_techniques.isnot(None), Case.is_synthetic.is_(False)))).scalars().all()
    detected = {t["id"] if isinstance(t, dict) else t for lst in rows if isinstance(lst, list) for t in lst}
    return {"success": True, "data": compute_coverage(detected)}
