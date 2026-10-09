from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.base import created_col, updated_col, utcnow


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String)
    summary: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String, default="medium")
    status: Mapped[str] = mapped_column(String, default="open", index=True)
    confidence_score: Mapped[float | None] = mapped_column(Float)
    mitre_tactics: Mapped[list | None] = mapped_column(JSON)
    mitre_techniques: Mapped[list | None] = mapped_column(JSON)
    attack_narrative: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String, default="system")
    # True when every alert/event behind this case is synthetic (seed demo data, or a case built
    # entirely from events ingested with synthetic=true). Excluded from dashboard/list/MITRE coverage.
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = created_col()
    updated_at: Mapped[datetime] = updated_col()

    timeline: Mapped[list["CaseTimeline"]] = relationship(
        cascade="all, delete-orphan", order_by="CaseTimeline.timestamp", lazy="selectin"
    )
    alert_links: Mapped[list["CaseAlert"]] = relationship(cascade="all, delete-orphan")
    event_links: Mapped[list["CaseEvent"]] = relationship(cascade="all, delete-orphan")


class CaseAlert(Base):
    __tablename__ = "case_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"))


class CaseEvent(Base):
    __tablename__ = "case_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("security_events.id"))


class CaseTimeline(Base):
    __tablename__ = "case_timeline"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    entry_type: Mapped[str] = mapped_column(String)  # event | alert | action | note | ai_analysis
    content: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String, default="system")
    metadata_json: Mapped[dict | None] = mapped_column(JSON)
