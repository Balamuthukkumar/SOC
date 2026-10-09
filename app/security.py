from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.config import settings

ALGORITHM = "HS256"
MAX_PASSWORD_BYTES = 72


def validate_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if len(password.encode()) > MAX_PASSWORD_BYTES:
        raise ValueError("Password must not exceed 72 bytes")
    return password


def hash_password(password: str) -> str:
    return bcrypt.hashpw(validate_password(password).encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str | None) -> bool:
    if not hashed or len(password.encode()) > MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def create_token(subject: str, minutes: int | None = None) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=minutes or settings.access_token_minutes)
    return jwt.encode({"sub": subject, "exp": exp}, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str) -> str | None:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM]).get("sub")
    except jwt.PyJWTError:
        return None
