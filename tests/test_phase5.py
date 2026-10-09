import hashlib
import hmac
import json
import time

import pytest

from app.services import stripe_client
from app.services.integrations import merge_masked, sentinel_signature, validate_outbound_url
from app.services.sbom import parse


# ---------------- compliance ----------------
async def test_compliance_assess_and_summary(client, auth):
    fws = (await client.get("/api/v1/compliance/frameworks", headers=auth)).json()
    assert {f["name"] for f in fws} == {"IEC 62443", "NIST CSF"}
    res = (await client.post("/api/v1/compliance/assess", headers=auth)).json()["data"]
    by = {r["control_id"]: r for r in res["results"]}
    assert by["ID.AM-1"]["status"] == "compliant" and by["DE.CM-1"]["status"] == "compliant"
    assert by["RS.AN-1"]["status"] == "non_compliant"  # 0 of 6 alerts triaged
    summary = (await client.get("/api/v1/compliance/summary", headers=auth)).json()
    nist = next(s for s in summary if s["framework_name"] == "NIST CSF")
    assert nist["compliant"] >= 3 and nist["total_controls"] == 11
    assert nist["compliant"] + nist["non_compliant"] + nist["partial"] + nist["not_assessed"] == nist["total_controls"]


async def test_manual_assessment_survives_reassessment(client, auth):
    await client.post("/api/v1/compliance/assess", headers=auth)
    controls = (await client.get("/api/v1/compliance/frameworks/2/controls", headers=auth)).json()
    cid = next(c["id"] for c in controls if c["control_id"] == "ID.AM-1")
    r = await client.put(f"/api/v1/compliance/controls/{cid}/assessment", headers=auth,
                         json={"status": "partial", "evidence_detail": "auditor note"})
    assert r.json()["assessed_by"] == "admin@example.com"
    again = (await client.post("/api/v1/compliance/assess", headers=auth)).json()["data"]["results"]
    assert next(x for x in again if x["control_id"] == "ID.AM-1").get("skipped") == "manual"
    a = (await client.get("/api/v1/compliance/assessments", headers=auth)).json()
    assert next(x for x in a if x["control_id"] == cid)["status"] == "partial"
    bad = await client.put(f"/api/v1/compliance/controls/{cid}/assessment", headers=auth, json={"status": "bogus"})
    assert bad.status_code == 422


# ---------------- sbom ----------------
CYCLONE = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
    {"bom-ref": "a", "name": "openssl", "version": "1.1.1", "supplier": {"name": "OpenSSL"},
     "hashes": [{"alg": "SHA-256", "content": "ab"}], "licenses": [{"license": {"id": "Apache-2.0"}}]},
    {"bom-ref": "b", "name": "zlib", "version": "1.2"}],
    "vulnerabilities": [{"id": "CVE-2024-0001", "affects": [{"ref": "a"}]}]}


def test_parse_formats():
    fmt, ver, comps = parse(CYCLONE)
    assert (fmt, ver) == ("CycloneDX", "1.5") and comps[0]["vulnerabilities"] == ["CVE-2024-0001"] and comps[0]["license"] == "Apache-2.0"
    fmt, _, comps = parse({"spdxVersion": "SPDX-2.3", "packages": [{"name": "x", "supplier": "NOASSERTION", "versionInfo": "1"}]})
    assert fmt == "SPDX" and comps[0]["supplier"] is None
    with pytest.raises(ValueError):
        parse({"hello": "world"})


async def test_sbom_upload_crossrefs_alerts(client, auth):
    asset_id = (await client.get("/api/v1/assets/", headers=auth)).json()["assets"][0]["id"]
    doc = {**CYCLONE, "components": CYCLONE["components"] + [{"bom-ref": "c", "name": "WinCC", "version": "7"}]}
    r = await client.post("/api/v1/sbom/upload", headers=auth, json={"asset_id": asset_id, "sbom_data": doc})
    assert r.status_code == 201 and r.json()["component_count"] == 3
    assert r.json()["vulnerability_count"] == 2  # VEX CVE + seeded "Siemens WinCC - SQL Injection" alert
    comps = (await client.get(f"/api/v1/sbom/{r.json()['id']}/components", headers=auth, params={"vulnerable_only": True})).json()
    assert {c["name"] for c in comps} == {"openssl", "WinCC"}
    assert (await client.post("/api/v1/sbom/upload", headers=auth, json={"asset_id": asset_id, "sbom_data": {"x": 1}})).status_code == 400
    assert (await client.post("/api/v1/sbom/upload", headers=auth, json={"asset_id": 9999, "sbom_data": CYCLONE})).status_code == 404
    assert (await client.delete(f"/api/v1/sbom/{r.json()['id']}", headers=auth)).status_code == 204


# ---------------- organizations & plan limits ----------------
async def _new_user(client, email):
    await client.post("/api/v1/auth/register", json={"email": email, "password": "password-1234"})
    tok = (await client.post("/api/v1/auth/login", data={"username": email, "password": "password-1234"})).json()
    return {"Authorization": f"Bearer {tok['access_token']}"}


async def test_org_lifecycle_and_asset_limit(client):
    h = await _new_user(client, "owner@example.com")
    assert (await client.get("/api/v1/orgs/me", headers=h)).status_code == 404
    assert (await client.post("/api/v1/orgs/", headers=h, json={"name": "Acme", "slug": "Bad Slug"})).status_code == 422
    org = (await client.post("/api/v1/orgs/", headers=h, json={"name": "Acme", "slug": "acme"})).json()
    assert org["plan"] == "free" and org["max_assets"] == 10
    assert (await client.post("/api/v1/orgs/", headers=h, json={"name": "B", "slug": "acme2"})).status_code == 400
    assert (await client.get("/api/v1/auth/me", headers=h)).json()["role"] == "admin"
    for i in range(10):
        assert (await client.post("/api/v1/assets/", headers=h, json={"name": f"a{i}", "asset_type": "plc"})).status_code == 201
    assert (await client.post("/api/v1/assets/", headers=h, json={"name": "over", "asset_type": "plc"})).status_code == 402
    usage = (await client.get("/api/v1/billing/usage", headers=h)).json()["data"]
    assert usage["assets"] == {"current": 10, "limit": 10}
    # free plan allows one user: invite is refused
    await _new_user(client, "second@example.com")
    assert (await client.post("/api/v1/orgs/me/invite", headers=h, params={"email": "second@example.com"})).status_code == 400
    # duplicate slug
    other = await _new_user(client, "other@example.com")
    assert (await client.post("/api/v1/orgs/", headers=other, json={"name": "X", "slug": "acme"})).status_code == 409


async def test_only_admin_can_patch_org(client):
    h = await _new_user(client, "o2@example.com")
    await client.post("/api/v1/orgs/", headers=h, json={"name": "Org2", "slug": "org-two"})
    assert (await client.patch("/api/v1/orgs/me", headers=h, json={"name": "Renamed"})).json()["name"] == "Renamed"
    assert (await client.patch("/api/v1/orgs/me", headers=h, json={"plan": "enterprise"})).status_code == 422  # extra=forbid


# ---------------- integrations ----------------
async def test_validate_outbound_url_blocks_internal():
    for bad in ("http://example.com", "https://localhost/x", "https://127.0.0.1/", "https://10.0.0.1/",
                "https://169.254.169.254/latest", "https://user:pw@example.com/", "ftp://example.com"):
        with pytest.raises(ValueError):
            await validate_outbound_url(bad)


async def test_integration_secrets_masked_and_encrypted(client, auth):
    pd = {"integration_type": "pagerduty", "name": "pd", "config": {"routing_key": "super-secret"}}
    r = (await client.post("/api/v1/integrations/", headers=auth, json=pd)).json()["data"]
    assert r["config"]["routing_key"] == "********" and "super-secret" not in json.dumps(r)
    listed = (await client.get("/api/v1/integrations/", headers=auth)).json()["data"]
    assert "super-secret" not in json.dumps(listed)
    from sqlalchemy import select
    from app.db import SessionLocal
    from app.models import IntegrationConfig
    async with SessionLocal() as s:
        raw = (await s.execute(select(IntegrationConfig))).scalar_one().config_encrypted
    assert "super-secret" not in raw
    upd = await client.patch(f"/api/v1/integrations/{r['id']}", headers=auth, json={"config": {"routing_key": "********"}})
    assert upd.status_code == 200
    t = (await client.post(f"/api/v1/integrations/{r['id']}/test", headers=auth)).json()["data"]
    assert t["success"] is True  # secret retained through the masked PATCH


async def test_integration_rejects_ssrf_and_bad_type(client, auth):
    bad = {"integration_type": "splunk", "name": "x", "config": {"hec_url": "https://127.0.0.1:8088", "hec_token": "t"}}
    assert (await client.post("/api/v1/integrations/", headers=auth, json=bad)).status_code == 400
    assert (await client.post("/api/v1/integrations/", headers=auth, json={**bad, "integration_type": "nope"})).status_code == 400


def test_merge_masked_and_sentinel_signature():
    assert merge_masked({"password": "real", "u": "a"}, {"password": "********", "u": "b"}) == {"password": "real", "u": "b"}
    import base64
    key = base64.b64encode(b"k" * 32).decode()
    sig = sentinel_signature("ws-1", key, "Mon, 01 Jan 2024 00:00:00 GMT", 10)
    assert sig.startswith("SharedKey ws-1:") and sig == sentinel_signature("ws-1", key, "Mon, 01 Jan 2024 00:00:00 GMT", 10)


# ---------------- billing ----------------
def sign(payload: bytes, secret: str, ts: int | None = None) -> str:
    ts = ts or int(time.time())
    return f"t={ts},v1=" + hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()


def test_stripe_signature_verification():
    body = b'{"x":1}'
    assert stripe_client.verify_signature(body, sign(body, "s"), "s")
    assert not stripe_client.verify_signature(body, sign(body, "other"), "s")
    assert not stripe_client.verify_signature(b'{"x":2}', sign(body, "s"), "s")
    assert not stripe_client.verify_signature(body, sign(body, "s", ts=int(time.time()) - 3600), "s")  # replay
    assert not stripe_client.verify_signature(body, "garbage", "s")


async def test_billing_plans_and_checkout_unconfigured(client, auth, monkeypatch):
    plans = (await client.get("/api/v1/billing/plans")).json()
    assert [p["plan"] for p in plans] == ["free", "starter", "pro", "enterprise"]
    h = await _new_user(client, "b@example.com")
    await client.post("/api/v1/orgs/", headers=h, json={"name": "B", "slug": "bill-org"})
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    assert (await client.post("/api/v1/billing/checkout", headers=h, json={"plan": "pro"})).status_code == 503
    assert (await client.post("/api/v1/billing/checkout", headers=h, json={"plan": "free"})).status_code == 400
    assert (await client.post("/api/v1/billing/cancel", headers=h)).status_code == 400  # free plan


async def test_webhook_upgrades_and_downgrades(client, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec")
    h = await _new_user(client, "w@example.com")
    org = (await client.post("/api/v1/orgs/", headers=h, json={"name": "W", "slug": "web-hook"})).json()

    async def send(event, secret="whsec"):
        body = json.dumps(event).encode()
        return await client.post("/api/v1/billing/webhook", content=body, headers={"stripe-signature": sign(body, secret)})

    sub = {"id": "sub_1", "status": "active", "metadata": {"org_id": str(org["id"]), "plan": "pro"},
           "current_period_start": 1_700_000_000, "current_period_end": 1_702_000_000}
    assert (await send({"type": "customer.subscription.created", "data": {"object": sub}}, secret="wrong")).status_code == 400
    assert (await send({"type": "customer.subscription.created", "data": {"object": sub}})).status_code == 200
    me = (await client.get("/api/v1/orgs/me", headers=h)).json()
    assert me["plan"] == "pro" and me["max_assets"] == 500
    s = (await client.get("/api/v1/billing/subscription", headers=h)).json()["data"]
    assert s["plan"] == "pro" and s["stripe_subscription_id"] == "sub_1" and "stripe_customer_id" not in s
    await send({"type": "invoice.payment_failed", "data": {"object": {"subscription": "sub_1"}}})
    assert (await client.get("/api/v1/billing/subscription", headers=h)).json()["data"]["status"] == "past_due"
    await send({"type": "customer.subscription.deleted", "data": {"object": {"id": "sub_1", "metadata": {}}}})
    assert (await client.get("/api/v1/orgs/me", headers=h)).json()["plan"] == "free"
    # unknown plan in metadata can't escalate privileges
    sub["metadata"]["plan"] = "platinum"
    await send({"type": "customer.subscription.updated", "data": {"object": sub}})
    assert (await client.get("/api/v1/orgs/me", headers=h)).json()["plan"] == "free"


async def test_webhook_requires_configured_secret(client, monkeypatch):
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    assert (await client.post("/api/v1/billing/webhook", content=b"{}")).status_code == 503
