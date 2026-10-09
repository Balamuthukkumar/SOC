from datetime import datetime

from pydantic import BaseModel

from app.schemas.common import ORM


class EventOut(ORM):
    id: int
    timestamp: datetime
    event_type: str
    severity: str
    signature: str | None = None
    signature_id: str | None = None
    category: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    action: str | None = None
    hostname: str | None = None
    username: str | None = None
    domain: str | None = None
    url: str | None = None
    source_type: str | None = None
    processed: str
    is_synthetic: bool = False
    created_at: datetime


class EventList(BaseModel):
    events: list[EventOut]
    total: int
    page: int
    size: int


class EventBatch(BaseModel):
    source_type: str = "webhook"
    source_name: str | None = None
    events: list[dict]
    # Opt-in only. Marks every event in this batch as test/demo data so it never counts toward production
    # alerts, cases or dashboard totals. Real sensors must never set this to true.
    synthetic: bool = False


class SourceOut(ORM):
    id: int
    name: str
    source_type: str
    status: str
    event_count: int
    last_event_at: datetime | None = None
    created_at: datetime
