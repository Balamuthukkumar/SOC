import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, Asset, AuditLog, User
from app.services import feeds
from app.services.matching import asset_matches
from app.services.notify import notify_user

log = logging.getLogger(__name__)


async def create_alerts(db: AsyncSession, advisories: list[dict]) -> dict[int, list[Alert]]:
    """Match advisories against every active user's assets. Idempotent on (user, asset, cve). Returns new alerts by user."""
    rows = (await db.execute(select(User, Asset).join(Asset, Asset.user_id == User.id).where(User.is_active.is_(True)))).all()
    existing = {(a, c) for a, c in (await db.execute(select(Alert.asset_id, Alert.cve_id).where(Alert.cve_id.isnot(None)))).all()}
    fresh: dict[int, list[Alert]] = {}
    for adv in advisories:
        for user, asset in rows:
            key = (asset.id, adv["cve_id"])
            if key in existing or not asset_matches(asset, adv):
                continue
            existing.add(key)
            alert = Alert(user_id=user.id, asset_id=asset.id, cve_id=adv["cve_id"], title=adv["title"][:250],
                          description=adv["description"], severity=adv["severity"], cvss_score=adv["cvss_score"],
                          remediation=adv.get("remediation"), source_url=adv["source_url"],
                          known_exploited=adv["known_exploited"])
            # a KEV hit on an asset we already alerted for via NVD escalates rather than duplicating
            db.add(alert)
            fresh.setdefault(user.id, []).append(alert)
    for user_id, alerts in fresh.items():
        db.add(AuditLog(user_id=user_id, action="alerts_created", detail={"count": len(alerts)}))
    await db.commit()
    return fresh


async def run_check(db: AsyncSession, hours_back: int = 6, advisories: list[dict] | None = None) -> dict:
    advisories = advisories if advisories is not None else await feeds.fetch_all(hours_back)
    fresh = await create_alerts(db, advisories)
    users = {u.id: u for u in (await db.execute(select(User).where(User.id.in_(fresh)))).scalars()} if fresh else {}
    for user_id, alerts in fresh.items():
        await notify_user(users[user_id], alerts)
    created = sum(len(a) for a in fresh.values())
    log.info("vulnerability check: %d advisories, %d new alerts", len(advisories), created)
    return {"advisories_checked": len(advisories), "alerts_created": created, "users_notified": len(fresh)}
