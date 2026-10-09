from fastapi import Request

from app.models import AuditLog


def audit(db, user_id: int | None, action: str, request: Request | None = None, **detail) -> None:
    db.add(AuditLog(
        user_id=user_id, action=action, detail=detail or None,
        ip_address=request.client.host if request and request.client else None,
    ))
