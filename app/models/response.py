from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import created_col


class ResponsePlan(Base):
    __tablename__ = "response_plans"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    actions: Mapped[list] = mapped_column(JSON)
    # draft | pending_approval | approved | executing | completed | partial | rejected
    status: Mapped[str] = mapped_column(String, default="draft", index=True)
    autonomy_level: Mapped[str] = mapped_column(String, default="L1")
    rationale: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String, default="agent")
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_col()


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("response_plans.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[str] = mapped_column(String, default="response_agent")
    status: Mapped[str] = mapped_column(String, default="pending")  # pending | approved | rejected
    reason: Mapped[str | None] = mapped_column(Text)
    reviewed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_col()
