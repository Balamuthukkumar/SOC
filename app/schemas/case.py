from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.schemas.common import ORM


class TimelineOut(ORM):
    id: int
    timestamp: datetime
    entry_type: str
    content: str
    source: str
    metadata_json: dict | None = None


class CaseOut(ORM):
    id: int
    title: str
    summary: str | None = None
    severity: str
    status: str
    confidence_score: float | None = None
    mitre_tactics: list[Any] | None = None
    mitre_techniques: list[Any] | None = None
    attack_narrative: str | None = None
    created_by: str
    created_at: datetime
    updated_at: datetime | None = None
    alert_count: int = 0
    event_count: int = 0
    is_synthetic: bool = False


class CaseDetail(CaseOut):
    timeline: list[TimelineOut] = []


class CaseList(BaseModel):
    cases: list[CaseOut]
    total: int
    page: int
    size: int


class CasePatch(BaseModel):
    status: str | None = None
    severity: str | None = None
