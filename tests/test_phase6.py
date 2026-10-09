from types import SimpleNamespace as NS

from app.services import feeds, remediation
from app.services.alert_checker import run_check
from app.services.matching import asset_matches, names_match, severity_from_cvss, version_in_range
from app.services.similarity import cosine, tokens, vectors

NVD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2099-0001", "descriptions": [{"lang": "es", "value": "hola"}, {"lang": "en", "value": "RCE in ControlLogix"}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:o:rockwellautomation:controllogix_5580_firmware:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "32.0", "versionEndExcluding": "33.11"},
        {"vulnerable": False, "criteria": "cpe:2.3:h:rockwellautomation:controllogix_5580:-:*:*:*:*:*:*:*"}]}]}]}}]}
KEV = {"vulnerabilities": [{"cveID": "CVE-2099-0002", "vendorProject": "Fortinet", "product": "FortiGate",
                            "vulnerabilityName": "SSL VPN OOB write", "shortDescription": "d", "requiredAction": "Apply updates.",
                            "dateAdded": "2024-01-01"}]}


def asset(**kw):
    return NS(**{"vendor": None, "product": None, "version": None, "cpe_string": None, **kw})


def test_parse_nvd():
    [adv] = feeds.parse_nvd(NVD)
    assert adv["cve_id"] == "CVE-2099-0001" and adv["severity"] == "critical" and adv["cvss_score"] == 9.8
    assert adv["description"] == "RCE in ControlLogix"
    assert len(adv["criteria"]) == 1 and adv["criteria"][0]["end_excl"] == "33.11"  # non-vulnerable cpe ignored


def test_parse_kev():
    [adv] = feeds.parse_kev(KEV)
    assert adv["known_exploited"] and adv["remediation"] == "Apply updates." and adv["criteria"][0]["product"] == "FortiGate"


def test_name_matching_is_strict():
    assert names_match("Rockwell Automation", "rockwellautomation", strip_corp=True)
    assert names_match("ControlLogix 5580", "controllogix_5580_firmware")
    assert not names_match("MS", "Microsoft")          # the old 'ms' alias false-positive is gone
    assert not names_match("FortiGate 200F", "FortiOS")  # different product names never match by vendor alone
    assert not names_match("abc", "xabcx")              # < 4 chars never matches by containment
    assert not names_match("", "x")


def test_version_ranges():
    r = {"start_incl": "32.0", "end_excl": "33.11"}
    assert version_in_range("32.0", r) and version_in_range("33.10.9", r) and version_in_range("33.2", r)
    assert not version_in_range("33.11", r) and not version_in_range("31.9", r) and not version_in_range("34", r)
    assert version_in_range(None, r)                    # unknown version -> cannot rule out
    assert version_in_range("1.2.3", {"version": "1.2.3"}) and not version_in_range("1.2.4", {"version": "1.2.3"})
    assert version_in_range("9.9", {"version": "*"})
    assert version_in_range("2.10", {"end_incl": "2.10"}) and not version_in_range("2.11", {"end_incl": "2.10"})


def test_asset_matching():
    [adv] = feeds.parse_nvd(NVD)
    assert asset_matches(asset(vendor="Rockwell Automation", product="ControlLogix 5580", version="33.2"), adv)
    assert not asset_matches(asset(vendor="Rockwell Automation", product="ControlLogix 5580", version="34.1"), adv)
    assert not asset_matches(asset(vendor="Siemens", product="S7-1500", version="33.2"), adv)
    assert not asset_matches(asset(), adv)
    assert asset_matches(asset(cpe_string="cpe:2.3:o:rockwellautomation:controllogix_5580_firmware:33.2:*:*:*:*:*:*:*"), adv)
    assert not asset_matches(asset(cpe_string="cpe:2.3:o:rockwellautomation:controllogix_5580_firmware:35.0:*:*:*:*:*:*:*"), adv)
    assert severity_from_cvss(9.0) == "critical" and severity_from_cvss(7.0) == "high" and severity_from_cvss(None, "high") == "high"


async def test_run_check_creates_idempotent_alerts(client, auth):
    from app.db import SessionLocal
    from app.models import Asset
    from sqlalchemy import select
    async with SessionLocal() as db:
        a = (await db.execute(select(Asset).where(Asset.name.like("Allen-Bradley%")))).scalar_one()
        a.vendor, a.product, a.version = "Rockwell Automation", "ControlLogix 5580", "33.2"
        await db.commit()
        advisories = feeds.parse_nvd(NVD) + feeds.parse_kev(KEV)
        first = await run_check(db, advisories=advisories)
        second = await run_check(db, advisories=advisories)
    assert first["alerts_created"] == 2 and first["users_notified"] == 1  # ControlLogix (NVD) + FortiGate (KEV)
    assert second["alerts_created"] == 0
    alerts = (await client.get("/api/v1/alerts/", headers=auth, params={"cve_id": "CVE-2099-0002"})).json()["alerts"]
    assert alerts[0]["known_exploited"] is True and alerts[0]["asset_name"].startswith("Fortinet")


async def test_admin_scan_endpoint_and_non_admin_forbidden(client, auth, monkeypatch):
    async def fake_fetch(hours_back=6):
        return []
    monkeypatch.setattr(feeds, "fetch_all", fake_fetch)
    r = await client.post("/api/v1/alerts/scan", headers=auth)
    assert r.json()["data"]["alerts_created"] == 0
    await client.post("/api/v1/auth/register", json={"email": "v@example.com", "password": "password-v-123"})
    tok = (await client.post("/api/v1/auth/login", data={"username": "v@example.com", "password": "password-v-123"})).json()
    assert (await client.post("/api/v1/alerts/scan", headers={"Authorization": f"Bearer {tok['access_token']}"})).status_code == 403


def test_remediation_rules():
    alert = NS(known_exploited=True, severity="critical", remediation="Upgrade to 33.11")
    ot = NS(network_zone="control", primary_protocol="modbus", is_ot_asset=True)
    kinds = [s["action_type"] for s in remediation.generate(alert, ot)]
    assert kinds[0] == "urgent_containment" and kinds.index("compensating_control") < kinds.index("patch")
    assert "network_segmentation" in kinds and kinds[-1] == "accept_risk"
    it = NS(network_zone="it", primary_protocol="https", is_ot_asset=False)
    kinds = [s["action_type"] for s in remediation.generate(NS(known_exploited=False, severity="medium", remediation="x"), it)]
    assert kinds == ["patch", "accept_risk"]
    assert remediation.generate(NS(known_exploited=False, severity="low", remediation=None), None)[0]["action_type"] == "monitor"


async def test_remediation_and_epss_endpoints(client, auth, monkeypatch):
    aid = (await client.get("/api/v1/alerts/", headers=auth,
                            params={"severity": "critical", "include_synthetic": "true"})).json()["alerts"][0]["id"]
    first = (await client.get(f"/api/v1/alerts/{aid}/remediations", headers=auth)).json()["data"]
    again = (await client.get(f"/api/v1/alerts/{aid}/remediations", headers=auth)).json()["data"]
    assert [r["id"] for r in first] == [r["id"] for r in again] and first[-1]["action_type"] == "accept_risk"
    from app.routers import alerts as alerts_router

    async def fake_epss(ids):
        return {ids[0]: (0.42, 0.97)}
    monkeypatch.setattr(alerts_router, "fetch_epss", fake_epss)
    e = (await client.get(f"/api/v1/alerts/{aid}/epss", headers=auth)).json()["data"]
    assert e["epss"] == 0.42 and e["percentile"] == 0.97


def test_tfidf_cosine():
    docs = [tokens("modbus scan plc exploit"), tokens("modbus plc write attack"), tokens("invoice payment email phishing")]
    v = vectors(docs)
    assert cosine(v[0], v[1]) > cosine(v[0], v[2]) and cosine(v[0], v[0]) > 0.99 and cosine({}, v[0]) == 0


async def test_case_search_similar_blast_radius(client, auth):
    cid = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()["cases"][0]["id"]
    # Default search never surfaces the synthetic case, even for a query that matches it exactly.
    assert (await client.get("/api/v1/cases/search", headers=auth, params={"q": "VPN lateral movement PLC"})).json()["data"] == []
    hit = (await client.get("/api/v1/cases/search", headers=auth,
                            params={"q": "VPN lateral movement PLC", "include_synthetic": "true"})).json()["data"]
    assert hit and hit[0]["case_id"] == cid
    assert (await client.get("/api/v1/cases/search", headers=auth, params={"q": "zzzzqq", "include_synthetic": "true"})).json()["data"] == []
    assert (await client.get(f"/api/v1/cases/{cid}/similar", headers=auth)).json()["data"] == []  # only one case
    assert (await client.get("/api/v1/cases/999/similar", headers=auth)).status_code == 404
    br = (await client.get(f"/api/v1/cases/{cid}/blast-radius", headers=auth)).json()["data"]
    types = {n["type"] for n in br["nodes"]}
    assert {"case", "asset", "ip", "mitre"} <= types
    assert br["summary"]["assets_affected"] >= 2 and br["summary"]["techniques_used"] == 7
    ids = {n["id"] for n in br["nodes"]}
    assert all(e["from"] in ids and e["to"] in ids for e in br["edges"])
    assert (await client.get("/api/v1/cases/999/blast-radius", headers=auth)).status_code == 404


async def test_request_id_and_metrics(client):
    r = await client.get("/health", headers={"x-request-id": "abc123"})
    assert r.headers["x-request-id"] == "abc123" and r.headers["x-content-type-options"] == "nosniff"
    assert (await client.get("/health")).headers["x-request-id"]
    assert (await client.get("/metrics")).status_code == 401  # admin only
    tok = (await client.post("/api/v1/auth/login", data={"username": "admin@example.com", "password": "password123"})).json()
    m = (await client.get("/metrics", headers={"Authorization": f"Bearer {tok['access_token']}"})).json()["data"]
    assert m["requests_total"] >= 3


async def test_github_oauth_state_and_config(client, monkeypatch):
    from app.config import settings
    from app.services import github_auth
    assert (await client.get("/api/v1/auth/github/login")).status_code == 503
    monkeypatch.setattr(settings, "github_client_id", "cid")
    r = await client.get("/api/v1/auth/github/login", follow_redirects=False)
    assert r.status_code == 307 and "github.com/login/oauth/authorize" in r.headers["location"] and "state=" in r.headers["location"]
    assert (await client.get("/api/v1/auth/github/callback", params={"code": "x", "state": "forged"})).status_code == 400
    state = github_auth.new_state()
    assert github_auth.consume_state(state) and not github_auth.consume_state(state)  # single use

    async def fake_exchange(code):
        return {"id": "42", "login": "octo", "name": "Octo", "email": "octo@example.com", "avatar_url": None}
    monkeypatch.setattr(github_auth, "exchange_code", fake_exchange)
    cb = await client.get("/api/v1/auth/github/callback", params={"code": "c", "state": github_auth.new_state()}, follow_redirects=False)
    assert cb.status_code == 307 and "access_token=" in cb.headers["set-cookie"] and "HttpOnly" in cb.headers["set-cookie"]
    me = await client.get("/api/v1/auth/me")  # cookie auth
    assert me.json()["email"] == "octo@example.com"
    # unverified password account with same email cannot be taken over via GitHub
    await client.post("/api/v1/auth/register", json={"email": "victim@example.com", "password": "password-1234"})

    async def evil(code):
        return {"id": "666", "login": "evil", "name": None, "email": "victim@example.com", "avatar_url": None}
    monkeypatch.setattr(github_auth, "exchange_code", evil)
    r = await client.get("/api/v1/auth/github/callback", params={"code": "c", "state": github_auth.new_state()})
    assert r.status_code == 409
