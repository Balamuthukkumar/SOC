import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, select

from app.deps import DB, CurrentUser
from app.models import Asset, Organization, Subscription, User
from app.routers.organizations import apply_plan, my_org, require_admin
from app.services import stripe_client as stripe
from app.services.plans import PLANS, plan_info

log = logging.getLogger(__name__)
router = APIRouter()
PAID = ("starter", "pro", "enterprise")


class Checkout(BaseModel):
    plan: str
    success_url: str = "/app/settings?billing=success"
    cancel_url: str = "/app/settings?billing=canceled"


def ts(value) -> datetime | None:
    return datetime.fromtimestamp(value, tz=timezone.utc) if value else None


@router.get("/plans")
async def plans():
    return [plan_info(p) for p in PLANS]


async def _subscription(db, org: Organization) -> Subscription:
    sub = (await db.execute(select(Subscription).where(Subscription.org_id == org.id))).scalar_one_or_none()
    if not sub:
        sub = Subscription(org_id=org.id, plan=org.plan)
        db.add(sub)
        await db.flush()
    return sub


@router.get("/subscription")
async def subscription(user: CurrentUser, db: DB):
    sub = await _subscription(db, await my_org(db, user))
    await db.commit()
    return {"success": True, "data": {c.name: getattr(sub, c.name) for c in Subscription.__table__.columns
                                      if not c.name.startswith("stripe_customer")}}


@router.post("/checkout")
async def checkout(body: Checkout, user: CurrentUser, db: DB):
    org = await my_org(db, user)
    require_admin(user)
    if body.plan not in PAID:
        raise HTTPException(400, f"plan must be one of {list(PAID)}")
    if not stripe.secret_key() or not stripe.price_id(body.plan):
        raise HTTPException(503, "Billing is not configured (set STRIPE_SECRET_KEY and STRIPE_PRICE_<PLAN>)")
    sub = await _subscription(db, org)
    try:
        if not sub.stripe_customer_id:
            sub.stripe_customer_id = await stripe.create_customer(user.email, org.id)
        session = await stripe.create_checkout(sub.stripe_customer_id, body.plan, body.success_url, body.cancel_url, org.id)
    except Exception:
        log.exception("Stripe checkout failed")
        raise HTTPException(502, "Could not create checkout session")
    await db.commit()
    return {"success": True, "data": {"checkout_url": session["url"], "session_id": session["id"]}}


@router.post("/cancel")
async def cancel(user: CurrentUser, db: DB):
    org = await my_org(db, user)
    require_admin(user)
    sub = await _subscription(db, org)
    if sub.status == "canceled" or sub.plan == "free":
        raise HTTPException(400, "No active paid subscription to cancel")
    if sub.stripe_subscription_id and stripe.secret_key():
        try:
            await stripe._post(f"/subscriptions/{sub.stripe_subscription_id}", {"cancel_at_period_end": "true"})
        except Exception:
            log.exception("Stripe cancel failed")
            raise HTTPException(502, "Could not cancel with the billing provider")
    sub.cancel_at_period_end = True
    await db.commit()
    return {"success": True, "data": {"cancel_at_period_end": True,
                                      "message": "Subscription will be canceled at the end of the billing period"}}


@router.get("/usage")
async def usage(user: CurrentUser, db: DB):
    org = await my_org(db, user)
    assets = (await db.execute(select(func.count(Asset.id)).where(
        Asset.user_id.in_(select(User.id).where(User.org_id == org.id))))).scalar_one()
    users = (await db.execute(select(func.count(User.id)).where(User.org_id == org.id))).scalar_one()
    limits = PLANS.get(org.plan, PLANS["free"])
    return {"success": True, "data": {"plan": org.plan, "assets": {"current": assets, "limit": limits["max_assets"]},
                                      "users": {"current": users, "limit": limits["max_users"]}, "features": limits["features"]}}


async def _apply_event(db, event: dict) -> None:
    kind, obj = event["type"], event["data"]["object"]
    if kind.startswith("customer.subscription."):
        meta = obj.get("metadata") or {}
        sub = (await db.execute(select(Subscription).where(Subscription.stripe_subscription_id == obj["id"]))).scalar_one_or_none()
        if not sub and meta.get("org_id"):
            sub = (await db.execute(select(Subscription).where(Subscription.org_id == int(meta["org_id"])))).scalar_one_or_none()
        if not sub:
            log.warning("Stripe event for unknown subscription %s", obj.get("id"))
            return
        org = await db.get(Organization, sub.org_id)
        if kind.endswith("deleted"):
            sub.status, sub.plan, sub.cancel_at_period_end = "canceled", "free", False
            apply_plan(org, "free")
            return
        plan = meta.get("plan") if meta.get("plan") in PAID else sub.plan
        sub.stripe_subscription_id, sub.plan, sub.status = obj["id"], plan, obj.get("status", "active")
        sub.current_period_start, sub.current_period_end = ts(obj.get("current_period_start")), ts(obj.get("current_period_end"))
        sub.cancel_at_period_end = bool(obj.get("cancel_at_period_end"))
        apply_plan(org, plan)
    elif kind == "invoice.payment_failed":
        sub = (await db.execute(select(Subscription).where(Subscription.stripe_subscription_id == obj.get("subscription")))).scalar_one_or_none()
        if sub:
            sub.status = "past_due"


@router.post("/webhook")
async def webhook(request: Request, db: DB):
    secret = stripe.webhook_secret()
    if not secret:
        raise HTTPException(503, "Stripe webhook secret not configured")
    payload = await request.body()
    if not stripe.verify_signature(payload, request.headers.get("stripe-signature", ""), secret):
        raise HTTPException(400, "Invalid webhook signature")
    await _apply_event(db, json.loads(payload))
    await db.commit()
    return {"success": True, "data": {"received": True}}
