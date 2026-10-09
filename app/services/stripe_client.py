"""Minimal Stripe REST client (no SDK): checkout sessions + webhook signature verification."""
import hashlib
import hmac
import os
import time

import httpx

API = "https://api.stripe.com/v1"
TOLERANCE_SECONDS = 300


def secret_key() -> str:
    return os.getenv("STRIPE_SECRET_KEY", "")


def webhook_secret() -> str:
    return os.getenv("STRIPE_WEBHOOK_SECRET", "")


def price_id(plan: str) -> str:
    return os.getenv(f"STRIPE_PRICE_{plan.upper()}", "")


def verify_signature(payload: bytes, header: str, secret: str, now: float | None = None) -> bool:
    """Stripe-Signature: t=<ts>,v1=<hmac_sha256(secret, f"{ts}.{payload}")>[,v1=...]"""
    try:
        items = [p.split("=", 1) for p in header.split(",")]
        ts = next(v for k, v in items if k == "t")
        sigs = [v for k, v in items if k == "v1"]
    except (StopIteration, ValueError):
        return False
    if abs((now or time.time()) - int(ts)) > TOLERANCE_SECONDS:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)


async def _post(path: str, data: dict) -> dict:
    async with httpx.AsyncClient(timeout=15) as http:
        r = await http.post(f"{API}{path}", data=data, auth=(secret_key(), ""))
        r.raise_for_status()
        return r.json()


async def create_customer(email: str, org_id: int) -> str:
    return (await _post("/customers", {"email": email, "metadata[org_id]": str(org_id)}))["id"]


async def create_checkout(customer: str, plan: str, success_url: str, cancel_url: str, org_id: int) -> dict:
    return await _post("/checkout/sessions", {
        "customer": customer, "mode": "subscription", "line_items[0][price]": price_id(plan),
        "line_items[0][quantity]": "1", "success_url": success_url, "cancel_url": cancel_url,
        "subscription_data[metadata][org_id]": str(org_id), "subscription_data[metadata][plan]": plan})
