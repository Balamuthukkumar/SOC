from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from app.deps import DB, CurrentUser
from app.models import Asset, Organization, User
from app.schemas.asset import AssetIn, AssetList, AssetOut, AssetPatch

router = APIRouter()

ASSET_TYPES = ["hardware", "software", "firmware", "operating_system", "plc", "hmi", "rtu", "ied",
               "scada_server", "historian", "engineering_workstation", "industrial_network", "other_ot"]


async def _owned(db, user, asset_id: int) -> Asset:
    asset = (await db.execute(select(Asset).where(Asset.id == asset_id, Asset.user_id == user.id))).scalar_one_or_none()
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset


@router.get("/types/", response_model=list[str])
async def asset_types():
    return ASSET_TYPES


@router.get("/", response_model=AssetList)
async def list_assets(user: CurrentUser, db: DB, page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=200),
                      asset_type: str | None = None, is_ot_asset: bool | None = None,
                      criticality: str | None = None, search: str | None = None):
    where = [Asset.user_id == user.id]
    if asset_type: where.append(Asset.asset_type == asset_type)
    if is_ot_asset is not None: where.append(Asset.is_ot_asset == is_ot_asset)
    if criticality: where.append(Asset.criticality == criticality)
    if search: where.append(Asset.name.ilike(f"%{search}%"))
    total = (await db.execute(select(func.count(Asset.id)).where(*where))).scalar_one()
    rows = (await db.execute(select(Asset).where(*where).order_by(Asset.created_at.desc())
                             .offset((page - 1) * size).limit(size))).scalars().all()
    return AssetList(assets=rows, total=total, page=page, size=size)


@router.post("/", response_model=AssetOut, status_code=201)
async def create_asset(body: AssetIn, user: CurrentUser, db: DB):
    if user.org_id:
        org = await db.get(Organization, user.org_id)
        used = (await db.execute(select(func.count(Asset.id)).where(
            Asset.user_id.in_(select(User.id).where(User.org_id == org.id))))).scalar_one()
        if used >= org.max_assets:
            raise HTTPException(402, f"Asset limit reached for the {org.plan} plan ({org.max_assets})")
    asset = Asset(user_id=user.id, **body.model_dump())
    db.add(asset)
    await db.commit()
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: int, user: CurrentUser, db: DB):
    return await _owned(db, user, asset_id)


@router.put("/{asset_id}", response_model=AssetOut)
async def update_asset(asset_id: int, body: AssetPatch, user: CurrentUser, db: DB):
    asset = await _owned(db, user, asset_id)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(asset, k, v)
    await db.commit()
    return asset


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: int, user: CurrentUser, db: DB):
    await db.delete(await _owned(db, user, asset_id))
    await db.commit()
