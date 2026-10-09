"""Encrypt small secrets (integration credentials) at rest, keyed from SECRET_KEY."""
import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def _fernet() -> Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(("fernet:" + settings.secret_key).encode()).digest()))


def encrypt_json(data: dict) -> str:
    return _fernet().encrypt(json.dumps(data).encode()).decode()


def decrypt_json(token: str) -> dict:
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except InvalidToken as exc:
        raise ValueError("Stored credentials cannot be decrypted (SECRET_KEY changed?)") from exc
