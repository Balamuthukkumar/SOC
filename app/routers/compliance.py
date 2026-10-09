from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select

from app.deps import DB, CurrentUser
from app.models import ComplianceAssessment, ComplianceControl, ComplianceFramework
from app.schemas.common import ORM
from app.services.compliance import run_assessment

router = APIRouter()
STATUSES = {"compliant", "non_compliant", "partial", "not_applicable", "not_assessed"}


class FrameworkOut(ORM):
    id: int
    name: str
    version: str
    description: str | None = None


class ControlOut(ORM):
    id: int
    framework_id: int
    control_id: str
    title: str
    description: str | None = None
    category: str | None = None


class AssessmentOut(ORM):
    id: int
    control_id: int
    status: str
    evidence_type: str | None = None
    evidence_detail: str | None = None
    assessed_by: str


class AssessmentIn(BaseModel):
    status: str
    evidence_type: str | None = "manual"
    evidence_detail: str | None = None


def _check_status(status: str) -> None:
    if status not in STATUSES:
        raise HTTPException(422, f"status must be one of {sorted(STATUSES)}")


@router.get("/frameworks", response_model=list[FrameworkOut])
async def frameworks(user: CurrentUser, db: DB):
    return (await db.execute(select(ComplianceFramework))).scalars().all()


@router.get("/frameworks/{framework_id}/controls", response_model=list[ControlOut])
async def controls(framework_id: int, user: CurrentUser, db: DB):
    return (await db.execute(select(ComplianceControl).where(ComplianceControl.framework_id == framework_id))).scalars().all()


@router.get("/summary")
async def summary(user: CurrentUser, db: DB):
    out = []
    for fw in (await db.execute(select(ComplianceFramework))).scalars():
        total = (await db.execute(select(func.count(ComplianceControl.id)).where(ComplianceControl.framework_id == fw.id))).scalar_one()
        counts = dict((await db.execute(
            select(ComplianceAssessment.status, func.count()).join(ComplianceControl, ComplianceControl.id == ComplianceAssessment.control_id)
            .where(ComplianceAssessment.user_id == user.id, ComplianceControl.framework_id == fw.id)
            .group_by(ComplianceAssessment.status))).all())
        assessed = sum(counts.values())
        applicable = total - counts.get("not_applicable", 0)
        compliant = counts.get("compliant", 0)
        out.append({"framework_id": fw.id, "framework_name": fw.name, "total_controls": total,
                    "compliant": compliant, "non_compliant": counts.get("non_compliant", 0), "partial": counts.get("partial", 0),
                    "not_assessed": total - assessed + counts.get("not_assessed", 0),
                    "compliance_percentage": round(compliant / applicable * 100, 1) if applicable else 0.0})
    return out


@router.post("/assess")
async def assess(user: CurrentUser, db: DB):
    results = await run_assessment(db, user.id)
    return {"success": True, "data": {"assessed": len(results), "results": results}}


@router.get("/assessments", response_model=list[AssessmentOut])
async def assessments(user: CurrentUser, db: DB):
    return (await db.execute(select(ComplianceAssessment).where(ComplianceAssessment.user_id == user.id))).scalars().all()


@router.patch("/assessments/{assessment_id}", response_model=AssessmentOut)
async def update_assessment(assessment_id: int, body: AssessmentIn, user: CurrentUser, db: DB):
    _check_status(body.status)
    a = (await db.execute(select(ComplianceAssessment).where(
        ComplianceAssessment.id == assessment_id, ComplianceAssessment.user_id == user.id))).scalar_one_or_none()
    if not a:
        raise HTTPException(404, "Assessment not found")
    a.status, a.evidence_type, a.evidence_detail, a.assessed_by = body.status, body.evidence_type, body.evidence_detail, user.email
    await db.commit()
    return a


@router.put("/controls/{control_pk}/assessment", response_model=AssessmentOut)
async def assess_control(control_pk: int, body: AssessmentIn, user: CurrentUser, db: DB):
    _check_status(body.status)
    if not (await db.execute(select(ComplianceControl.id).where(ComplianceControl.id == control_pk))).first():
        raise HTTPException(404, "Control not found")
    a = (await db.execute(select(ComplianceAssessment).where(
        ComplianceAssessment.user_id == user.id, ComplianceAssessment.control_id == control_pk))).scalar_one_or_none()
    a = a or ComplianceAssessment(user_id=user.id, control_id=control_pk)
    a.status, a.evidence_type, a.evidence_detail, a.assessed_by = body.status, body.evidence_type, body.evidence_detail, user.email
    db.add(a)
    await db.commit()
    return a
