from datetime import datetime
from enum import Enum

from pydantic import BaseModel

from app.schemas.common import ORM


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, Enum):
    pending = "pending"
    acknowledged = "acknowledged"
    resolved = "resolved"
    dismissed = "dismissed"


class AlertOut(ORM):
    id: int
    asset_id: int
    cve_id: str | None = None
    title: str
    description: str | None = None
    severity: str
    cvss_score: float | None = None
    remediation: str | None = None
    status: str
    source_url: str | None = None
    known_exploited: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    created_at: datetime
    acknowledged_at: datetime | None = None
    asset_name: str | None = None
    asset_vendor: str | None = None
    asset_product: str | None = None
    is_synthetic: bool = False
    # Always present, for requirement "clearly label each alert with source / detection rule / evidence":
    source_label: str = ""       # where this alert came from
    detection_rule: str = ""     # what criteria flagged it

    @classmethod
    def build(cls, a) -> "AlertOut":
        out = cls.model_validate(a)
        out.asset_name, out.asset_vendor, out.asset_product = a.asset.name, a.asset.vendor, a.asset.product
        if a.is_synthetic:
            out.source_label = "Demo / test data (not a real finding)"
        elif a.known_exploited:
            out.source_label = "CISA Known Exploited Vulnerabilities catalogue"
        else:
            out.source_label = "NVD vulnerability feed"
        out.detection_rule = f"CVE match: {a.cve_id}" if a.cve_id else "Vendor advisory match"
        return out


class AlertList(BaseModel):
    alerts: list[AlertOut]
    total: int
    page: int
    size: int
    pages: int


class AlertPatch(BaseModel):
    status: AlertStatus


class AlertStats(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    pending_alerts: int
    acknowledged_alerts: int
