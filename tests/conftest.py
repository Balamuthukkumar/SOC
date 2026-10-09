import os

os.environ["TESTING"] = "1"
os.environ["SCHEDULER_ENABLED"] = "false"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test.db"

import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.seed import DEMO_EMAIL, DEMO_PASSWORD  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    from app.db import SessionLocal
    from app.seed import seed_demo
    from app.services.compliance import seed_frameworks
    async with SessionLocal() as s:
        await seed_frameworks(s)
        await seed_demo(s)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def auth(client):
    r = await client.post("/api/v1/auth/login", data={"username": DEMO_EMAIL, "password": DEMO_PASSWORD})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
