from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.deps import DB, CurrentUser
from app.models import Asset, Sbom, SbomComponent
from app.schemas.common import ORM
from app.services.sbom import cross_reference, parse

router = APIRouter()
MAX_COMPONENTS = 20_000


class SbomUpload(BaseModel):
    asset_id: int
    sbom_data: dict
    source: str = "upload"


class SbomOut(ORM):
    id: int
    asset_id: int
    format: str
    version: str | None = None
    source: str
    component_count: int
    vulnerability_count: int
    created_at: datetime


class ComponentOut(ORM):
    id: int
    sbom_id: int
    name: str
    version: str | None = None
    supplier: str | None = None
    purl: str | None = None
    cpe: str | None = None
    license: str | None = None
    vulnerabilities: list[str] | None = None


async def _owned(db, user, sbom_id: int) -> Sbom:
    s = (await db.execute(select(Sbom).where(Sbom.id == sbom_id, Sbom.user_id == user.id))).scalar_one_or_none()
    if not s:
        raise HTTPException(404, "SBOM not found")
    return s


@router.post("/upload", response_model=SbomOut, status_code=201)
async def upload(body: SbomUpload, user: CurrentUser, db: DB):
    if not (await db.execute(select(Asset.id).where(Asset.id == body.asset_id, Asset.user_id == user.id))).first():
        raise HTTPException(404, "Asset not found")
    try:
        fmt, version, components = parse(body.sbom_data)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if len(components) > MAX_COMPONENTS:
        raise HTTPException(413, f"SBOM exceeds {MAX_COMPONENTS} components")
    await cross_reference(db, user.id, components)
    sbom = Sbom(asset_id=body.asset_id, user_id=user.id, format=fmt, version=version, source=body.source,
                component_count=len(components),
                vulnerability_count=len({v for c in components for v in c["vulnerabilities"]}))
    sbom.components = [SbomComponent(**{k: v for k, v in c.items() if k != "ref"}) for c in components]
    db.add(sbom)
    await db.commit()
    return sbom


@router.get("/", response_model=list[SbomOut])
async def list_sboms(user: CurrentUser, db: DB):
    return (await db.execute(select(Sbom).where(Sbom.user_id == user.id).order_by(Sbom.created_at.desc()))).scalars().all()


@router.get("/{sbom_id}", response_model=SbomOut)
async def get_sbom(sbom_id: int, user: CurrentUser, db: DB):
    return await _owned(db, user, sbom_id)


@router.get("/{sbom_id}/components", response_model=list[ComponentOut])
async def components(sbom_id: int, user: CurrentUser, db: DB, vulnerable_only: bool = False):
    sbom = await _owned(db, user, sbom_id)
    rows = (await db.execute(select(SbomComponent).where(SbomComponent.sbom_id == sbom.id).order_by(SbomComponent.name))).scalars().all()
    return [c for c in rows if c.vulnerabilities] if vulnerable_only else rows


@router.delete("/{sbom_id}", status_code=204)
async def delete_sbom(sbom_id: int, user: CurrentUser, db: DB):
    await db.delete(await _owned(db, user, sbom_id))
    await db.commit()
