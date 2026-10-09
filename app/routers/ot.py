import hashlib
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.deps import DB, CurrentUser
from app.models import Asset, DiscoveredDevice, NetworkSensor
from app.models.base import utcnow
from app.schemas.common import ORM
from app.services.ot_risk import score_device

router = APIRouter()


# ---- schemas ---------------------------------------------------------------------------------
class SensorIn(BaseModel):
    name: str
    sensor_type: str
    endpoint_url: str | None = None
    location: str | None = None
    network_segment: str | None = None
    enabled: bool = True
    configuration: dict | None = None
    api_token: str | None = Field(default=None, exclude=True)


class SensorPatch(BaseModel):
    name: str | None = None
    endpoint_url: str | None = None
    location: str | None = None
    network_segment: str | None = None
    enabled: bool | None = None
    configuration: dict | None = None


class SensorOut(ORM):
    id: int
    name: str
    sensor_type: str
    endpoint_url: str | None = None
    location: str | None = None
    network_segment: str | None = None
    enabled: bool
    last_heartbeat: datetime | None = None
    last_discovery_count: int
    configuration: dict | None = None
    created_at: datetime


class DeviceIn(BaseModel):
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    device_class: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    ports_open: list[int] | None = None
    services_detected: list[str] | None = None
    protocols: list[str] | None = None
    industrial_protocols: list[str] | None = None
    is_ot_device: bool = False
    ot_device_type: str | None = None
    confidence: str = "medium"
    discovery_method: str = "manual_import"
    sensor_id: int | None = None
    description: str | None = None
    notes: str | None = None
    tags: list[str] | None = None


class DevicePatch(BaseModel):
    hostname: str | None = None
    device_class: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    ot_device_type: str | None = None
    is_ot_device: bool | None = None
    confidence: str | None = None
    notes: str | None = None
    tags: list[str] | None = None


class DeviceOut(DeviceIn, ORM):
    id: int
    asset_id: int | None = None
    risk_score: float
    risk_factors: list[str] | None = None
    is_correlated: bool
    correlation_score: float | None = None
    first_seen: datetime
    last_seen: datetime


class IngestBatch(BaseModel):
    sensor_id: int
    discovery_method: str = "sensor_report"
    devices: list[DeviceIn]


# ---- helpers ---------------------------------------------------------------------------------
async def _sensor(db, user, sensor_id: int) -> NetworkSensor:
    s = (await db.execute(select(NetworkSensor).where(NetworkSensor.id == sensor_id, NetworkSensor.user_id == user.id))).scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Sensor not found")
    return s


async def _device(db, user, device_id: int) -> DiscoveredDevice:
    d = (await db.execute(select(DiscoveredDevice).where(DiscoveredDevice.id == device_id, DiscoveredDevice.user_id == user.id))).scalar_one_or_none()
    if not d:
        raise HTTPException(404, "Device not found")
    return d


def rescore(d: DiscoveredDevice) -> None:
    d.risk_score, d.risk_factors = score_device(d)


async def upsert_device(db, user_id: int, data: DeviceIn, sensor_id: int | None, method: str) -> tuple[DiscoveredDevice, bool]:
    existing = (await db.execute(select(DiscoveredDevice).where(
        DiscoveredDevice.user_id == user_id, DiscoveredDevice.ip_address == data.ip_address))).scalar_one_or_none()
    fields = data.model_dump(exclude={"sensor_id", "discovery_method"}, exclude_unset=True)
    if existing:
        for k, v in fields.items():
            if v is not None:
                setattr(existing, k, v)
        existing.last_seen = utcnow()
        device, created = existing, False
    else:
        device = DiscoveredDevice(user_id=user_id, sensor_id=sensor_id, discovery_method=method, **fields)
        db.add(device)
        created = True
    rescore(device)
    return device, created


# ---- sensors ---------------------------------------------------------------------------------
@router.post("/sensors", response_model=SensorOut, status_code=201)
async def create_sensor(body: SensorIn, user: CurrentUser, db: DB):
    token = body.api_token
    sensor = NetworkSensor(user_id=user.id, api_token_hash=hashlib.sha256(token.encode()).hexdigest() if token else None,
                           **body.model_dump(exclude={"api_token"}))
    db.add(sensor)
    await db.commit()
    return sensor


@router.get("/sensors", response_model=list[SensorOut])
async def list_sensors(user: CurrentUser, db: DB):
    return (await db.execute(select(NetworkSensor).where(NetworkSensor.user_id == user.id))).scalars().all()


@router.get("/sensors/{sensor_id}", response_model=SensorOut)
async def get_sensor(sensor_id: int, user: CurrentUser, db: DB):
    return await _sensor(db, user, sensor_id)


@router.patch("/sensors/{sensor_id}", response_model=SensorOut)
async def patch_sensor(sensor_id: int, body: SensorPatch, user: CurrentUser, db: DB):
    s = await _sensor(db, user, sensor_id)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(s, k, v)
    await db.commit()
    return s


@router.delete("/sensors/{sensor_id}", status_code=204)
async def delete_sensor(sensor_id: int, user: CurrentUser, db: DB):
    await db.delete(await _sensor(db, user, sensor_id))
    await db.commit()


@router.post("/ingest/batch")
async def ingest_batch(body: IngestBatch, user: CurrentUser, db: DB):
    if not body.devices:
        raise HTTPException(400, "No devices provided")
    sensor = await _sensor(db, user, body.sensor_id)
    created = updated = 0
    high_risk = []
    for item in body.devices:
        device, is_new = await upsert_device(db, user.id, item, sensor.id, body.discovery_method)
        created += is_new
        updated += not is_new
        if is_new and device.risk_score > 70:
            high_risk.append({"ip_address": device.ip_address, "risk_score": device.risk_score})
    sensor.last_heartbeat, sensor.last_discovery_count = utcnow(), len(body.devices)
    await db.commit()
    return {"status": "success", "summary": {"processed": len(body.devices), "created": created, "updated": updated},
            "high_risk_devices": high_risk}


@router.post("/ingest/single", status_code=201)
async def ingest_single(body: DeviceIn, user: CurrentUser, db: DB):
    device, created = await upsert_device(db, user.id, body, body.sensor_id, body.discovery_method)
    await db.commit()
    return {"status": "created" if created else "updated", "id": device.id, "risk_score": device.risk_score}


# ---- discovered devices ----------------------------------------------------------------------
@router.post("/discovered-devices", response_model=DeviceOut, status_code=201)
async def create_device(body: DeviceIn, user: CurrentUser, db: DB):
    device, _ = await upsert_device(db, user.id, body, body.sensor_id, body.discovery_method)
    await db.commit()
    return device


@router.get("/discovered-devices")
async def list_devices(user: CurrentUser, db: DB, page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=200),
                       is_ot_device: bool | None = None, min_risk: float | None = None, correlated: bool | None = None):
    where = [DiscoveredDevice.user_id == user.id]
    if is_ot_device is not None: where.append(DiscoveredDevice.is_ot_device == is_ot_device)
    if min_risk is not None: where.append(DiscoveredDevice.risk_score >= min_risk)
    if correlated is not None: where.append(DiscoveredDevice.is_correlated == correlated)
    total = (await db.execute(select(func.count(DiscoveredDevice.id)).where(*where))).scalar_one()
    rows = (await db.execute(select(DiscoveredDevice).where(*where).order_by(DiscoveredDevice.risk_score.desc(), DiscoveredDevice.id)
                             .offset((page - 1) * size).limit(size))).scalars().all()
    return {"devices": [DeviceOut.model_validate(r) for r in rows], "total": total, "page": page, "size": size}


@router.get("/discovered-devices/{device_id}", response_model=DeviceOut)
async def get_device(device_id: int, user: CurrentUser, db: DB):
    return await _device(db, user, device_id)


@router.patch("/discovered-devices/{device_id}", response_model=DeviceOut)
async def patch_device(device_id: int, body: DevicePatch, user: CurrentUser, db: DB):
    d = await _device(db, user, device_id)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(d, k, v)
    rescore(d)
    await db.commit()
    return d


@router.post("/discovered-devices/{device_id}/correlate/{asset_id}", response_model=DeviceOut)
async def correlate(device_id: int, asset_id: int, user: CurrentUser, db: DB,
                    correlation_score: float | None = Query(None, ge=0, le=100)):
    d = await _device(db, user, device_id)
    if not (await db.execute(select(Asset.id).where(Asset.id == asset_id, Asset.user_id == user.id))).first():
        raise HTTPException(404, "Asset not found")
    d.asset_id, d.is_correlated, d.correlation_score = asset_id, True, correlation_score
    rescore(d)
    await db.commit()
    return d


@router.post("/discovered-devices/{device_id}/promote-to-asset")
async def promote(device_id: int, user: CurrentUser, db: DB):
    d = await _device(db, user, device_id)
    if d.asset_id:
        raise HTTPException(409, "Device is already linked to an asset")
    asset = Asset(user_id=user.id, name=d.hostname or " ".join(filter(None, [d.manufacturer, d.model])) or d.ip_address,
                  asset_type=(d.ot_device_type or "other_ot") if d.is_ot_device else "hardware", vendor=d.manufacturer,
                  product=d.model, version=d.firmware_version, is_ot_asset=d.is_ot_device,
                  primary_protocol=(d.protocols or [None])[0], last_known_ip=d.ip_address,
                  description=f"Promoted from discovered device at {d.ip_address}", discovery_method=d.discovery_method)
    db.add(asset)
    await db.flush()
    d.asset_id, d.is_correlated, d.correlation_score = asset.id, True, 100.0
    rescore(d)
    await db.commit()
    return {"success": True, "asset_id": asset.id, "device_id": d.id}


# ---- dashboard aggregates --------------------------------------------------------------------
@router.get("/summary")
async def summary(user: CurrentUser, db: DB):
    D = DiscoveredDevice

    async def count(table_id, *where):
        return (await db.execute(select(func.count(table_id)).where(*where))).scalar_one()

    managed = await count(Asset.id, Asset.user_id == user.id, Asset.is_ot_asset.is_(True))
    discovered = await count(D.id, D.user_id == user.id, D.is_ot_device.is_(True))
    unmanaged_ot = await count(D.id, D.user_id == user.id, D.is_ot_device.is_(True), D.is_correlated.is_(False))
    return {"managed_ot_assets": managed, "discovered_ot_devices": discovered,
            "high_risk_devices": await count(D.id, D.user_id == user.id, D.risk_score >= 70),
            "uncorrelated_devices": await count(D.id, D.user_id == user.id, D.is_correlated.is_(False)),
            "discovery_gap": unmanaged_ot}


@router.get("/devices-by-zone")
async def by_zone(user: CurrentUser, db: DB):
    rows = (await db.execute(select(Asset.network_zone, func.count(Asset.id)).where(
        Asset.user_id == user.id, Asset.is_ot_asset.is_(True)).group_by(Asset.network_zone))).all()
    return {"zones": [{"zone": z or "unknown", "count": n} for z, n in rows]}


@router.get("/devices-by-protocol")
async def by_protocol(user: CurrentUser, db: DB):
    rows = (await db.execute(select(Asset.primary_protocol, func.count(Asset.id)).where(
        Asset.user_id == user.id, Asset.is_ot_asset.is_(True), Asset.primary_protocol.isnot(None))
        .group_by(Asset.primary_protocol))).all()
    return {"protocols": [{"protocol": p, "count": n} for p, n in rows]}
