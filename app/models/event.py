from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import created_col


class EventSource(Base):
    __tablename__ = "event_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String)
    source_type: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="active")
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_col()


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (Index("ix_events_user_ts", "user_id", "timestamp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    source_id: Mapped[int | None] = mapped_column(ForeignKey("event_sources.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_type: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String, default="info", index=True)
    signature: Mapped[str | None] = mapped_column(String)
    signature_id: Mapped[str | None] = mapped_column(String)
    category: Mapped[str | None] = mapped_column(String)
    source_ip: Mapped[str | None] = mapped_column(String, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    dest_ip: Mapped[str | None] = mapped_column(String, index=True)
    dest_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String)
    action: Mapped[str | None] = mapped_column(String)
    hostname: Mapped[str | None] = mapped_column(String)
    username: Mapped[str | None] = mapped_column(String)
    domain: Mapped[str | None] = mapped_column(String)
    url: Mapped[str | None] = mapped_column(String)
    user_agent: Mapped[str | None] = mapped_column(String)
    bytes_in: Mapped[int | None] = mapped_column(Integer)
    bytes_out: Mapped[int | None] = mapped_column(Integer)
    raw_data: Mapped[dict | None] = mapped_column(JSON)
    source_type: Mapped[str | None] = mapped_column(String)
    processed: Mapped[str] = mapped_column(String, default="pending")
    # True only for demo/test data (seed.py, or ingest explicitly marked synthetic=true). Real sensor
    # submissions through /events/ingest and /events/upload always get False.
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = created_col()
