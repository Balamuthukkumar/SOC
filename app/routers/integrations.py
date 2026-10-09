from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.deps import DB, CurrentUser
from app.models import IntegrationConfig
from app.services import integrations as svc
from app.services.crypto import decrypt_json, encrypt_json

router = APIRouter()
VALID = {t["type"] for t in svc.TYPES}


class IntegrationIn(BaseModel):
    integration_type: str
    name: str
    config: dict


class IntegrationPatch(BaseModel):
    name: str | None = None
    config: dict | None = None
    is_active: bool | None = None


def view(c: IntegrationConfig) -> dict:
    return {"id": c.id, "integration_type": c.integration_type, "name": c.name, "is_active": c.is_active,
            "config": svc.mask(decrypt_json(c.config_encrypted)), "created_at": c.created_at}


async def _safe(kind: str, config: dict) -> None:
    field = svc.URL_FIELDS.get(kind)
    if field and config.get(field):
        try:
            await svc.validate_outbound_url(config[field])
        except ValueError as exc:
            raise HTTPException(400, f"Integration endpoint rejected: {exc}")


async def _owned(db, user, integration_id: int) -> IntegrationConfig:
    c = (await db.execute(select(IntegrationConfig).where(
        IntegrationConfig.id == integration_id, IntegrationConfig.user_id == user.id))).scalar_one_or_none()
    if not c:
        raise HTTPException(404, "Integration not found")
    return c


@router.get("/types")
async def types(user: CurrentUser):
    return {"success": True, "data": svc.TYPES}


@router.get("/")
async def list_integrations(user: CurrentUser, db: DB):
    rows = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.user_id == user.id))).scalars().all()
    return {"success": True, "data": [view(c) for c in rows]}


@router.post("/", status_code=201)
async def create(body: IntegrationIn, user: CurrentUser, db: DB):
    if body.integration_type not in VALID:
        raise HTTPException(400, f"Invalid integration type. Must be one of: {sorted(VALID)}")
    await _safe(body.integration_type, body.config)
    c = IntegrationConfig(user_id=user.id, integration_type=body.integration_type, name=body.name,
                          config_encrypted=encrypt_json(body.config))
    db.add(c)
    await db.commit()
    return {"success": True, "data": view(c)}


@router.patch("/{integration_id}")
async def update(integration_id: int, body: IntegrationPatch, user: CurrentUser, db: DB):
    c = await _owned(db, user, integration_id)
    if body.config is not None:
        merged = svc.merge_masked(decrypt_json(c.config_encrypted), body.config)
        await _safe(c.integration_type, merged)
        c.config_encrypted = encrypt_json(merged)
    if body.name is not None: c.name = body.name
    if body.is_active is not None: c.is_active = body.is_active
    await db.commit()
    return {"success": True, "data": view(c)}


@router.delete("/{integration_id}")
async def delete(integration_id: int, user: CurrentUser, db: DB):
    await db.delete(await _owned(db, user, integration_id))
    await db.commit()
    return {"success": True, "data": None, "message": "Integration deleted"}


@router.post("/{integration_id}/test")
async def test(integration_id: int, user: CurrentUser, db: DB):
    c = await _owned(db, user, integration_id)
    return {"success": True, "data": await svc.test_connection(c.integration_type, decrypt_json(c.config_encrypted))}
