from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.base import created_col


class ValidationRun(Base):
    __tablename__ = "validation_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending | running | completed | failed
    mode: Mapped[str] = mapped_column(String, default="dry_run")
    scope: Mapped[dict | None] = mapped_column(JSON)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    results_summary: Mapped[dict | None] = mapped_column(JSON)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_col()

    steps: Mapped[list["ValidationStep"]] = relationship(
        cascade="all, delete-orphan", order_by="ValidationStep.step_number", lazy="selectin")


class ValidationStep(Base):
    __tablename__ = "validation_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("validation_runs.id", ondelete="CASCADE"), index=True)
    step_number: Mapped[int] = mapped_column(Integer)
    technique_id: Mapped[str] = mapped_column(String, index=True)
    technique_name: Mapped[str] = mapped_column(String)
    test_name: Mapped[str] = mapped_column(String)
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    command: Mapped[str | None] = mapped_column(Text)
    expected_detection: Mapped[str | None] = mapped_column(Text)
    result: Mapped[str | None] = mapped_column(String)  # detected | missed
    evidence: Mapped[dict | None] = mapped_column(JSON)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
