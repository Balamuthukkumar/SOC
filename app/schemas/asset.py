from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import ORM


class AssetIn(BaseModel):
    name: str
    asset_type: str
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    description: str | None = None
    cpe_string: str | None = None
    is_ot_asset: bool = False
    network_zone: str = "unknown"
    primary_protocol: str | None = None
    last_known_ip: str | None = None
    criticality: str = "medium"
    discovery_method: str | None = None


class AssetPatch(BaseModel):
    name: str | None = None
    asset_type: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    description: str | None = None
    cpe_string: str | None = None
    is_ot_asset: bool | None = None
    network_zone: str | None = None
    primary_protocol: str | None = None
    last_known_ip: str | None = None
    criticality: str | None = None


class AssetOut(AssetIn, ORM):
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime | None = None


class AssetList(BaseModel):
    assets: list[AssetOut]
    total: int
    page: int
    size: int
