"""Compliance, SBOM, integrations, billing."""
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.base import created_col, updated_col


class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String)
    version: Mapped[str] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(Text)


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id: Mapped[int] = mapped_column(primary_key=True)
    framework_id: Mapped[int] = mapped_column(ForeignKey("compliance_frameworks.id"), index=True)
    control_id: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(String)


class ComplianceAssessment(Base):
    __tablename__ = "compliance_assessments"
    __table_args__ = (UniqueConstraint("user_id", "control_id", name="uq_assessment_user_control"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    control_id: Mapped[int] = mapped_column(ForeignKey("compliance_controls.id"))
    # compliant | non_compliant | partial | not_applicable | not_assessed
    status: Mapped[str] = mapped_column(String, default="not_assessed")
    evidence_type: Mapped[str | None] = mapped_column(String)
    evidence_detail: Mapped[str | None] = mapped_column(Text)
    assessed_at: Mapped[datetime] = updated_col()
    assessed_by: Mapped[str] = mapped_column(String, default="system")


class Sbom(Base):
    __tablename__ = "sboms"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    format: Mapped[str] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String)
    source: Mapped[str] = mapped_column(String, default="upload")
    component_count: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = created_col()

    components: Mapped[list["SbomComponent"]] = relationship(cascade="all, delete-orphan")


class SbomComponent(Base):
    __tablename__ = "sbom_components"

    id: Mapped[int] = mapped_column(primary_key=True)
    sbom_id: Mapped[int] = mapped_column(ForeignKey("sboms.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String)
    supplier: Mapped[str | None] = mapped_column(String)
    purl: Mapped[str | None] = mapped_column(String)
    cpe: Mapped[str | None] = mapped_column(String)
    license: Mapped[str | None] = mapped_column(String)
    hash_sha256: Mapped[str | None] = mapped_column(String)
    vulnerabilities: Mapped[list | None] = mapped_column(JSON)  # CVE ids affecting this component


class IntegrationConfig(Base):
    __tablename__ = "integration_configs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    integration_type: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    config_encrypted: Mapped[str] = mapped_column(Text)  # Fernet token of the JSON config
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = created_col()
    updated_at: Mapped[datetime] = updated_col()


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), unique=True)
    stripe_customer_id: Mapped[str | None] = mapped_column(String, index=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String, index=True)
    plan: Mapped[str] = mapped_column(String, default="free")
    status: Mapped[str] = mapped_column(String, default="active")  # active | past_due | canceled | trialing
    current_period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = created_col()
    updated_at: Mapped[datetime] = updated_col()
