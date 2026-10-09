from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import created_col


class HuntSession(Base):
    __tablename__ = "hunt_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    hypothesis: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="running")
    queries_run: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    result_data: Mapped[list | None] = mapped_column(JSON)
    sigma_rule: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_col()
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(Text)
    rule_type: Mapped[str] = mapped_column(String)  # sigma | suricata | yara | sql
    rule_content: Mapped[str] = mapped_column(Text)
    mitre_techniques: Mapped[list | None] = mapped_column(JSON)
    confidence: Mapped[str] = mapped_column(String, default="medium")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String, default="human")
    created_at: Mapped[datetime] = created_col()
