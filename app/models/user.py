from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.base import created_col, utcnow


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String)
    slug: Mapped[str] = mapped_column(String, unique=True, index=True)
    plan: Mapped[str] = mapped_column(String, default="free")
    max_assets: Mapped[int] = mapped_column(Integer, default=10)
    max_users: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = created_col()

    users: Mapped[list["User"]] = relationship(back_populates="organization")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str | None] = mapped_column(String)
    full_name: Mapped[str | None] = mapped_column(String)
    company: Mapped[str | None] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="viewer")  # admin | analyst | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    github_id: Mapped[str | None] = mapped_column(String, unique=True, index=True)
    auth_provider: Mapped[str] = mapped_column(String, default="email")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String)
    slack_webhook_url: Mapped[str | None] = mapped_column(String)
    webhook_url: Mapped[str | None] = mapped_column(String)
    org_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"))
    created_at: Mapped[datetime] = created_col()

    organization: Mapped[Organization | None] = relationship(back_populates="users")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String)
    resource: Mapped[str | None] = mapped_column(String)
    detail: Mapped[dict | None] = mapped_column(JSON)
    ip_address: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
