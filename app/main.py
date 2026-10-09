import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text

from app import models  # noqa: F401  (register tables)
from app.config import settings
from app.db import Base, SessionLocal, engine
from app.deps import require_role
from app.limiter import limiter
from app.middleware import METRICS, RequestContextMiddleware
from app.routers import (alerts, assets, auth, billing, cases, compliance, events, hunt, integrations, mitre,
                         organizations, ot, response_plans, sbom, topology, validation)
from app import scheduler
from app.seed import seed_demo
from app.services.compliance import seed_frameworks

log = logging.getLogger("app")
logging.basicConfig(level=logging.INFO)

API = "/api/v1"
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.environment != "production":  # production schema is managed by `alembic upgrade head`
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as session:
        await seed_frameworks(session)
        if settings.seed_demo:
            await seed_demo(session)
    if settings.scheduler_enabled:
        scheduler.start()
    yield
    scheduler.stop()
    await engine.dispose()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, headers=exc.headers,
                        content={"detail": exc.detail,
                                 "error": {"code": f"HTTP_{exc.status_code}", "message": str(exc.detail)}})


for module, prefix, tag in (
    (auth, "auth", "Auth"), (assets, "assets", "Assets"), (alerts, "alerts", "Alerts"),
    (events, "events", "Events"), (cases, "cases", "Cases"), (mitre, "mitre", "MITRE ATT&CK"),
    (hunt, "hunt", "Threat Hunting"), (response_plans, "response-plans", "Response Plans"),
    (validation, "validation", "Validation"), (ot, "ot", "OT/ICS"), (topology, "topology", "Topology"),
    (compliance, "compliance", "Compliance"), (sbom, "sbom", "SBOM"), (organizations, "orgs", "Organizations"),
    (integrations, "integrations", "Integrations"), (billing, "billing", "Billing"),
):
    app.include_router(module.router, prefix=f"{API}/{prefix}", tags=[tag])


@app.get("/health")
async def health():
    return {"status": "healthy", "app": settings.app_name}


@app.get("/metrics", dependencies=[require_role("admin")])
async def metrics():
    total = METRICS["requests_total"] or 1
    return {"success": True, "data": {**METRICS, "avg_request_ms": round(METRICS["request_seconds_total"] / total * 1000, 2)}}


@app.get("/health/live")
async def live():
    return {"status": "ok"}


@app.get("/health/ready")
async def ready():
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return {"status": "ready"}


if FRONTEND_DIST.is_dir():
    app.mount("/app/assets", StaticFiles(directory=FRONTEND_DIST / "assets"))

    @app.get("/app/{path:path}")
    async def spa(path: str):
        return FileResponse(FRONTEND_DIST / "index.html")

    @app.get("/")
    async def root():
        return RedirectResponse("/app/")
