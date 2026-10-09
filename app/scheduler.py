import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import settings
from app.db import SessionLocal
from app.services.alert_checker import run_check

log = logging.getLogger(__name__)
scheduler = AsyncIOScheduler()


async def vulnerability_job() -> None:
    try:
        async with SessionLocal() as db:
            await run_check(db, hours_back=settings.feed_interval_hours + 1)
    except Exception:
        log.exception("scheduled vulnerability check failed")


def start() -> None:
    scheduler.add_job(vulnerability_job, "interval", hours=settings.feed_interval_hours,
                      id="vulnerability_feeds", max_instances=1, coalesce=True)
    scheduler.start()


def stop() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
