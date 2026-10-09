from datetime import datetime

from pydantic import BaseModel, EmailStr, field_validator

from app.schemas.common import ORM
from app.security import validate_password


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None
    company: str | None = None

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        return validate_password(v)


class UserOut(ORM):
    id: int
    email: EmailStr
    full_name: str | None = None
    company: str | None = None
    role: str
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    org_id: int | None = None
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class IntegrationsUpdate(BaseModel):
    slack_webhook_url: str | None = None
    webhook_url: str | None = None


class MFAVerify(BaseModel):
    code: str
