import re
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import func, select

from app.deps import DB, CurrentUser
from app.models import Organization, Subscription, User
from app.schemas.common import ORM
from app.schemas.user import UserOut
from app.services.plans import PLANS

router = APIRouter()
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,48}[a-z0-9])$")


class OrgCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    slug: str

    @field_validator("slug")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not SLUG_RE.match(v):
            raise ValueError("slug must be 3-50 chars: lowercase letters, digits, hyphens")
        return v


class OrgPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None


class OrgOut(ORM):
    id: int
    name: str
    slug: str
    plan: str
    max_assets: int
    max_users: int
    created_at: datetime


async def my_org(db, user: User) -> Organization:
    org = await db.get(Organization, user.org_id) if user.org_id else None
    if not org:
        raise HTTPException(404, "User does not belong to an organization")
    return org


def require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(403, "Only organization admins can do this")


def apply_plan(org: Organization, plan: str) -> None:
    org.plan, org.max_assets, org.max_users = plan, PLANS[plan]["max_assets"], PLANS[plan]["max_users"]


@router.post("/", response_model=OrgOut, status_code=201)
async def create_org(body: OrgCreate, user: CurrentUser, db: DB):
    if user.org_id:
        raise HTTPException(400, "User already belongs to an organization")
    if (await db.execute(select(Organization.id).where(Organization.slug == body.slug))).first():
        raise HTTPException(409, "Organization slug already taken")
    org = Organization(name=body.name, slug=body.slug)
    apply_plan(org, "free")
    db.add(org)
    await db.flush()
    db.add(Subscription(org_id=org.id, plan="free"))
    user.org_id, user.role = org.id, "admin"
    await db.commit()
    return org


@router.get("/me", response_model=OrgOut)
async def get_org(user: CurrentUser, db: DB):
    return await my_org(db, user)


@router.patch("/me", response_model=OrgOut)
async def update_org(body: OrgPatch, user: CurrentUser, db: DB):
    org = await my_org(db, user)
    require_admin(user)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(org, k, v)
    await db.commit()
    return org


@router.post("/me/invite")
async def invite(email: str, user: CurrentUser, db: DB):
    org = await my_org(db, user)
    require_admin(user)
    members = (await db.execute(select(func.count(User.id)).where(User.org_id == org.id))).scalar_one()
    if members >= org.max_users:
        raise HTTPException(400, f"Organization has reached its user limit ({org.max_users})")
    invitee = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not invitee:
        raise HTTPException(404, "User not found")
    if invitee.org_id:
        raise HTTPException(400, "User already belongs to an organization")
    invitee.org_id = org.id
    await db.commit()
    return {"success": True, "data": {"message": f"{email} added to {org.name}"}}


@router.get("/me/members", response_model=list[UserOut])
async def members(user: CurrentUser, db: DB):
    org = await my_org(db, user)
    return (await db.execute(select(User).where(User.org_id == org.id))).scalars().all()
