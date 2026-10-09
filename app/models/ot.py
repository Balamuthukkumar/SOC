from datetime import datetime

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import created_col, updated_col, utcnow


class NetworkSensor(Base):
    __tablename__ = "network_sensors"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String)
    sensor_type: Mapped[str] = mapped_column(String)
    endpoint_url: Mapped[str | None] = mapped_column(String)
    api_token_hash: Mapped[str | None] = mapped_column(String)
    location: Mapped[str | None] = mapped_column(String)
    network_segment: Mapped[str | None] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_discovery_count: Mapped[int] = mapped_column(Integer, default=0)
    configuration: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = created_col()
    updated_at: Mapped[datetime] = updated_col()


class DiscoveredDevice(Base):
    __tablename__ = "discovered_devices"
    __table_args__ = (UniqueConstraint("user_id", "ip_address", name="uq_device_user_ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("network_sensors.id", ondelete="SET NULL"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    ip_address: Mapped[str] = mapped_column(String, index=True)
    mac_address: Mapped[str | None] = mapped_column(String)
    hostname: Mapped[str | None] = mapped_column(String)
    device_class: Mapped[str | None] = mapped_column(String)
    manufacturer: Mapped[str | None] = mapped_column(String)
    model: Mapped[str | None] = mapped_column(String)
    firmware_version: Mapped[str | None] = mapped_column(String)
    serial_number: Mapped[str | None] = mapped_column(String)
    ports_open: Mapped[list | None] = mapped_column(JSON)
    services_detected: Mapped[list | None] = mapped_column(JSON)
    protocols: Mapped[list | None] = mapped_column(JSON)
    industrial_protocols: Mapped[list | None] = mapped_column(JSON)
    is_ot_device: Mapped[bool] = mapped_column(Boolean, default=False)
    ot_device_type: Mapped[str | None] = mapped_column(String)
    confidence: Mapped[str] = mapped_column(String, default="medium")
    discovery_method: Mapped[str] = mapped_column(String, default="sensor_report")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_factors: Mapped[list | None] = mapped_column(JSON)
    is_correlated: Mapped[bool] = mapped_column(Boolean, default=False)
    correlation_score: Mapped[float | None] = mapped_column(Float)
    description: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list | None] = mapped_column(JSON)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = created_col()
    updated_at: Mapped[datetime] = updated_col()


class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    source_ip: Mapped[str] = mapped_column(String)
    target_ip: Mapped[str] = mapped_column(String)
    protocol: Mapped[str] = mapped_column(String)
    port: Mapped[int | None] = mapped_column(Integer)
    direction: Mapped[str] = mapped_column(String, default="bidirectional")
    is_encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    bytes_transferred: Mapped[int] = mapped_column(BigInteger, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
