from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.base import created_col, updated_col


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String)
    asset_type: Mapped[str] = mapped_column(String)
    vendor: Mapped[str | None] = mapped_column(String)
    product: Mapped[str | None] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(Text)
    cpe_string: Mapped[str | None] = mapped_column(String)
    is_ot_asset: Mapped[bool] = mapped_column(Boolean, default=False)
    network_zone: Mapped[str] = mapped_column(String, default="unknown")
    primary_protocol: Mapped[str | None] = mapped_column(String)
    last_known_ip: Mapped[str | None] = mapped_column(String)
    criticality: Mapped[str] = mapped_column(String, default="medium")
    discovery_method: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = created_col()
    updated_at: Mapped[datetime] = updated_col()
