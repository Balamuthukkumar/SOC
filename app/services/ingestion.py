"""Normalize raw telemetry (Suricata EVE, Zeek, generic JSON) into SecurityEvent rows."""
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import EventSource, SecurityEvent
from app.models.base import utcnow

SURICATA_SEVERITY = {1: "high", 2: "medium", 3: "low"}


def _ts(value) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return utcnow()


def parse_suricata(raw: dict) -> dict:
    alert = raw.get("alert") or {}
    return dict(
        timestamp=_ts(raw.get("timestamp")), event_type=raw.get("event_type", "alert"),
        severity=SURICATA_SEVERITY.get(alert.get("severity"), "info") if alert else "info",
        signature=alert.get("signature"), signature_id=str(alert["signature_id"]) if "signature_id" in alert else None,
        category=alert.get("category"), source_ip=raw.get("src_ip"), source_port=raw.get("src_port"),
        dest_ip=raw.get("dest_ip"), dest_port=raw.get("dest_port"), protocol=(raw.get("proto") or "").lower() or None,
        action=alert.get("action"), hostname=(raw.get("http") or {}).get("hostname"),
        url=(raw.get("http") or {}).get("url"), user_agent=(raw.get("http") or {}).get("http_user_agent"),
    )


def parse_zeek(raw: dict) -> dict:
    return dict(
        timestamp=_ts(raw.get("ts")), event_type=raw.get("_path", "conn"),
        severity="info" if "note" not in raw else "medium", signature=raw.get("note"),
        source_ip=raw.get("id.orig_h"), source_port=raw.get("id.orig_p"),
        dest_ip=raw.get("id.resp_h"), dest_port=raw.get("id.resp_p"), protocol=raw.get("proto"),
        bytes_out=raw.get("orig_bytes"), bytes_in=raw.get("resp_bytes"), domain=raw.get("query"),
    )


# Columns a raw payload may never set directly. Provenance (is_synthetic) and identity columns are always
# assigned by ingest_events() itself — never trusted from client-supplied JSON, even under parse_generic's
# "copy any matching column name" behavior.
_NON_COPYABLE = {"id", "user_id", "source_id", "raw_data", "created_at", "is_synthetic"}


def parse_generic(raw: dict) -> dict:
    fields = {c for c in SecurityEvent.__table__.columns.keys()} - _NON_COPYABLE
    data = {k: v for k, v in raw.items() if k in fields}
    data["timestamp"] = _ts(raw.get("timestamp"))
    data.setdefault("event_type", "event")
    return data


PARSERS = {"suricata": parse_suricata, "zeek": parse_zeek}


async def ingest_events(db: AsyncSession, user_id: int, raw_events: list[dict],
                        source_type: str, source_name: str | None, *, synthetic: bool = False) -> dict:
    """Normalize and store events.

    `synthetic=True` must only ever be set by test/demo tooling that explicitly opts in (e.g. a `synthetic: true`
    field on the request). Real sensor submissions through the public ingest/upload endpoints always get False.
    """
    name = source_name or source_type
    source = (await db.execute(select(EventSource).where(
        EventSource.user_id == user_id, EventSource.name == name,
        EventSource.source_type == source_type))).scalar_one_or_none()
    if not source:
        source = EventSource(user_id=user_id, name=name, source_type=source_type)
        db.add(source)
        await db.flush()

    parser = PARSERS.get(source_type, parse_generic)
    accepted = rejected = 0
    for raw in raw_events:
        try:
            fields = parser(raw)
        except Exception:
            rejected += 1
            continue
        db.add(SecurityEvent(user_id=user_id, source_id=source.id, source_type=source_type,
                             raw_data=raw, is_synthetic=synthetic, **fields))
        accepted += 1

    source.event_count += accepted
    source.last_event_at = utcnow()
    await db.commit()
    return {"accepted": accepted, "rejected": rejected, "source_id": source.id}
