import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select

from app.deps import DB, CurrentUser
from app.limiter import limiter
from app.models import AuditLog, User
from app.schemas.user import IntegrationsUpdate, MFAVerify, Token, UserCreate, UserOut
from app.security import create_token, hash_password, verify_password
from app.config import settings
from app.services import github_auth
from app.services.audit import audit

router = APIRouter()


@router.post("/register", response_model=UserOut, status_code=201)
@limiter.limit("3/minute")
async def register(request: Request, body: UserCreate, db: DB):
    if (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none():
        raise HTTPException(400, "Email already registered")
    user = User(email=body.email, hashed_password=hash_password(body.password),
                full_name=body.full_name, company=body.company)
    db.add(user)
    await db.commit()
    return user


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
async def login(request: Request, response: Response, db: DB,
                form: OAuth2PasswordRequestForm = Depends()):
    user = (await db.execute(select(User).where(User.email == form.username))).scalar_one_or_none()
    if not user or not verify_password(form.password, user.hashed_password):
        audit(db, user.id if user else None, "login_failed", request, email=form.username)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    if user.mfa_enabled:
        otp = request.headers.get("x-mfa-code", "")
        if not pyotp.TOTP(user.mfa_secret).verify(otp):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "MFA code required or invalid")
    token = create_token(user.email)
    response.set_cookie("access_token", token, httponly=True, samesite="lax")
    audit(db, user.id, "login", request)
    await db.commit()
    return Token(access_token=token)


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out"}


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser):
    return user


@router.post("/verify-token")
async def verify_token_endpoint(user: CurrentUser):
    return {"valid": True, "email": user.email}


@router.patch("/me/integrations", response_model=UserOut)
async def update_integrations(body: IntegrationsUpdate, user: CurrentUser, db: DB):
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(user, k, v)
    await db.commit()
    return user


@router.post("/me/mfa/setup")
async def mfa_setup(user: CurrentUser, db: DB):
    user.mfa_secret = pyotp.random_base32()
    await db.commit()
    uri = pyotp.TOTP(user.mfa_secret).provisioning_uri(name=user.email, issuer_name="SOC Platform")
    return {"secret": user.mfa_secret, "provisioning_uri": uri}


@router.post("/me/mfa/verify", response_model=bool)
async def mfa_verify(body: MFAVerify, user: CurrentUser, db: DB):
    if not user.mfa_secret:
        raise HTTPException(400, "MFA setup not started")
    ok = pyotp.TOTP(user.mfa_secret).verify(body.code)
    if ok and not user.mfa_enabled:
        user.mfa_enabled = True
        await db.commit()
    return ok


@router.get("/audit-logs")
async def audit_logs(user: CurrentUser, db: DB, limit: int = 100):
    q = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if user.role != "admin":
        q = q.where(AuditLog.user_id == user.id)
    rows = (await db.execute(q)).scalars().all()
    return [{"id": r.id, "user_id": r.user_id, "action": r.action, "resource": r.resource,
             "detail": r.detail, "ip_address": r.ip_address, "created_at": r.created_at} for r in rows]


@router.get("/github/login")
async def github_login():
    if not settings.github_client_id:
        raise HTTPException(503, "GitHub login is not configured")
    return RedirectResponse(github_auth.authorize_url(github_auth.new_state()))


@router.get("/github/callback")
async def github_callback(request: Request, db: DB, code: str, state: str | None = None):
    if not settings.github_client_id:
        raise HTTPException(503, "GitHub login is not configured")
    if not github_auth.consume_state(state):
        raise HTTPException(400, "Invalid or expired OAuth state")
    try:
        gh = await github_auth.exchange_code(code)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    user = (await db.execute(select(User).where(User.github_id == gh["id"]))).scalar_one_or_none()
    if not user:
        by_email = (await db.execute(select(User).where(User.email == gh["email"]))).scalar_one_or_none()
        if by_email and not by_email.is_verified:
            raise HTTPException(409, "An unverified account already uses this email; sign in with your password")
        user = by_email or User(email=gh["email"], full_name=gh["name"], auth_provider="github", is_verified=True)
        user.github_id = gh["id"]
        db.add(user)
    audit(db, user.id, "login_github", request)
    await db.commit()
    response = RedirectResponse(settings.frontend_url)
    response.set_cookie("access_token", create_token(user.email), httponly=True, samesite="lax")
    return response
