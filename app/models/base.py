from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.orm import mapped_column

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def created_col():
    return mapped_column(DateTime(timezone=True), default=utcnow)

def updated_col():
    return mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
