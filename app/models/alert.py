from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.asset import Asset
from app.models.base import created_col, updated_col


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    cve_id: Mapped[str | None] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    remediation: Mapped[str | None] = mapped_column(Text)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    # True only for demo/test data (seed.py, synthetic ingest). Never set for real feed/sensor data.
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String, default="pending", index=True)
    source_url: Mapped[str | None] = mapped_column(String)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_col()
    updated_at: Mapped[datetime] = updated_col()

    asset: Mapped[Asset] = relationship(lazy="joined")


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    action_type: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    estimated_downtime_minutes: Mapped[int | None] = mapped_column(Integer)
    requires_maintenance_window: Mapped[bool] = mapped_column(Boolean, default=False)
    priority: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String, default="proposed")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = created_col()
