import json


async def test_login_rejects_bad_password(client):
    r = await client.post("/api/v1/auth/login", data={"username": "admin@example.com", "password": "wrong-pass"})
    assert r.status_code == 401


async def test_requires_auth(client):
    assert (await client.get("/api/v1/assets/")).status_code == 401


async def test_register_and_isolation(client, auth):
    r = await client.post("/api/v1/auth/register", json={"email": "bob@example.com", "password": "hunter2hunter2"})
    assert r.status_code == 201
    tok = (await client.post("/api/v1/auth/login", data={"username": "bob@example.com", "password": "hunter2hunter2"})).json()
    bob = {"Authorization": f"Bearer {tok['access_token']}"}
    assert (await client.get("/api/v1/assets/", headers=bob)).json()["total"] == 0
    assert (await client.get("/api/v1/assets/", headers=auth)).json()["total"] == 11


async def test_asset_crud(client, auth):
    r = await client.post("/api/v1/assets/", headers=auth, json={"name": "PLC-X", "asset_type": "plc"})
    aid = r.json()["id"]
    assert (await client.put(f"/api/v1/assets/{aid}", headers=auth, json={"criticality": "high"})).json()["criticality"] == "high"
    assert (await client.delete(f"/api/v1/assets/{aid}", headers=auth)).status_code == 204
    assert (await client.get(f"/api/v1/assets/{aid}", headers=auth)).status_code == 404


async def test_alerts_stats_and_ack(client, auth):
    # Seed alerts are synthetic (demo/test data) — invisible on the default view by design. See
    # test_synthetic_filtering.py for that behavior; here we exercise alert CRUD as an admin who opts in.
    assert (await client.get("/api/v1/alerts/stats/overview", headers=auth)).json()["total_alerts"] == 0
    params = {"include_synthetic": "true"}
    listed = (await client.get("/api/v1/alerts/", headers=auth, params=params)).json()
    assert listed["total"] == 6
    first = (await client.get("/api/v1/alerts/", headers=auth, params={**params, "severity": "critical"})).json()["alerts"][0]
    assert first["asset_name"] and first["is_synthetic"] is True and first["source_label"] and first["detection_rule"]
    assert (await client.post(f"/api/v1/alerts/{first['id']}/acknowledge", headers=auth)).status_code == 200
    acked = (await client.get("/api/v1/alerts/", headers=auth, params=params)).json()["alerts"]
    assert sum(a["status"] == "acknowledged" for a in acked) == 1


async def test_event_ingest_suricata(client, auth):
    raw = {"timestamp": "2026-01-01T00:00:00Z", "event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
           "proto": "TCP", "alert": {"signature": "TEST", "signature_id": 1, "severity": 1}}
    r = await client.post("/api/v1/events/ingest", headers=auth, json={"source_type": "suricata", "events": [raw]})
    assert r.status_code == 201 and r.json()["data"]["accepted"] == 1
    hit = (await client.get("/api/v1/events/", headers=auth, params={"source_ip": "1.1.1.1"})).json()
    assert hit["events"][0]["severity"] == "high"


async def test_event_upload_ndjson(client, auth):
    body = "\n".join(json.dumps({"timestamp": 1700000000, "event_type": "conn"}) for _ in range(3))
    r = await client.post("/api/v1/events/upload", headers=auth, params={"source_type": "generic"},
                          files={"file": ("e.json", body)})
    assert r.json()["data"]["accepted"] == 3


async def test_cases(client, auth):
    # The seed case is synthetic — invisible by default; include_synthetic=true (admin) opts in to exercise it.
    assert (await client.get("/api/v1/cases/", headers=auth)).json()["total"] == 0
    cases = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()
    assert cases["total"] == 1 and cases["cases"][0]["alert_count"] == 2 and cases["cases"][0]["is_synthetic"] is True
    cid = cases["cases"][0]["id"]
    detail = (await client.get(f"/api/v1/cases/{cid}", headers=auth)).json()
    assert detail["timeline"]
    assert (await client.patch(f"/api/v1/cases/{cid}", headers=auth, json={"status": "resolved"})).json()["status"] == "resolved"
    assert len((await client.get(f"/api/v1/cases/{cid}/events", headers=auth)).json()) > 0


async def test_seed_data_is_consistent(client, auth):
    from app.routers.assets import ASSET_TYPES
    assets = (await client.get("/api/v1/assets/", headers=auth, params={"size": 200})).json()["assets"]
    assert {a["asset_type"] for a in assets} <= set(ASSET_TYPES)
