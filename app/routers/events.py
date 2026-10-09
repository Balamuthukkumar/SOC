import json

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from sqlalchemy import func, select

from app.deps import DB, CurrentUser
from app.models import EventSource, SecurityEvent
from app.schemas.event import EventBatch, EventList, SourceOut
from app.services.ingestion import ingest_events

router = APIRouter()

MAX_UPLOAD = 10 * 1024 * 1024
MAX_BATCH = 10_000
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _parse_upload(text: str) -> list[dict]:
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        events = []
        for line in text.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events


@router.post("/ingest", status_code=201)
async def ingest(batch: EventBatch, user: CurrentUser, db: DB):
    if not batch.events:
        raise HTTPException(400, "No events provided")
    if len(batch.events) > MAX_BATCH:
        raise HTTPException(400, f"Batch size limit is {MAX_BATCH} events")
    return {"success": True, "data": await ingest_events(db, user.id, batch.events, batch.source_type, batch.source_name,
                                                          synthetic=batch.synthetic)}


@router.post("/upload", status_code=201)
async def upload(user: CurrentUser, db: DB, file: UploadFile = File(...), source_type: str = "suricata",
                 synthetic: bool = False):
    content = await file.read(MAX_UPLOAD + 1)
    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, "Uploaded file is too large")
    events = [e for e in _parse_upload(content.decode("utf-8", errors="replace")) if isinstance(e, dict)]
    if not events:
        raise HTTPException(400, "No valid JSON events found in file")
    return {"success": True, "data": await ingest_events(db, user.id, events, source_type, file.filename, synthetic=synthetic)}


@router.get("/", response_model=EventList)
async def list_events(user: CurrentUser, db: DB, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
                      severity: str | None = None, event_type: str | None = None, source_ip: str | None = None,
                      dest_ip: str | None = None, source_type: str | None = None,
                      include_synthetic: bool = Query(False, description="Admin-only: also show test/demo events")):
    where = [SecurityEvent.user_id == user.id]
    if not (include_synthetic and user.role == "admin"):
        where.append(SecurityEvent.is_synthetic.is_(False))
    for col, val in ((SecurityEvent.severity, severity), (SecurityEvent.event_type, event_type),
                     (SecurityEvent.source_ip, source_ip), (SecurityEvent.dest_ip, dest_ip),
                     (SecurityEvent.source_type, source_type)):
        if val:
            where.append(col == val)
    total = (await db.execute(select(func.count(SecurityEvent.id)).where(*where))).scalar_one()
    rows = (await db.execute(select(SecurityEvent).where(*where).order_by(SecurityEvent.timestamp.desc())
                             .offset((page - 1) * size).limit(size))).scalars().all()
    return EventList(events=rows, total=total, page=page, size=size)


@router.get("/sources", response_model=list[SourceOut])
async def sources(user: CurrentUser, db: DB):
    """Sources that have produced at least one real (non-synthetic) event. A source used only for demo/test
    data never shows up here, so the UI can't be mistaken for a live feed."""
    real_count = (select(func.count(SecurityEvent.id)).where(SecurityEvent.source_id == EventSource.id,
                  SecurityEvent.is_synthetic.is_(False)).correlate(EventSource).scalar_subquery())
    rows = (await db.execute(select(EventSource).where(EventSource.user_id == user.id, real_count > 0)
                             .order_by(EventSource.last_event_at.desc().nullslast()))).scalars().all()
    return rows


@router.get("/stats")
async def stats(user: CurrentUser, db: DB):
    uid = (SecurityEvent.user_id == user.id, SecurityEvent.is_synthetic.is_(False))
    by_sev = dict((await db.execute(select(SecurityEvent.severity, func.count()).where(*uid)
                                    .group_by(SecurityEvent.severity))).all())
    by_type = dict((await db.execute(select(SecurityEvent.event_type, func.count()).where(*uid)
                                     .group_by(SecurityEvent.event_type))).all())
    real_sources = (await db.execute(select(func.count(func.distinct(SecurityEvent.source_id))).where(*uid))).scalar_one()
    return {"success": True, "data": {
        "total_events": sum(by_sev.values()),
        "by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
        "by_type": by_type, "source_count": real_sources}}
