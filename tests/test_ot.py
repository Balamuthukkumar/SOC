from types import SimpleNamespace as NS

from app.services.ot_risk import clamp, score_asset, score_device, vulnerability_score


def dev(**kw):
    base = dict(is_ot_device=True, services_detected=[], industrial_protocols=[], ot_device_type=None, is_correlated=False)
    return NS(**{**base, **kw})


def test_risky_device_scores_higher_and_lists_factors():
    safe = score_device(dev(is_ot_device=False, is_correlated=True))
    risky, factors = score_device(dev(services_detected=["telnet"], industrial_protocols=["modbus"], ot_device_type="plc"))
    assert risky > safe[0] and risky <= 100
    assert "cleartext_service:telnet" in factors and "unauthenticated_protocol:modbus" in factors


def test_asset_score_bounds_and_non_ot():
    ot = NS(is_ot_asset=True, network_zone="control", primary_protocol="modbus", asset_type="plc", criticality="critical")
    alerts = [NS(severity="critical", cvss_score=9.8, created_at=None)] * 5
    score, parts = score_asset(ot, alerts)
    assert 0 < score <= 100 and set(parts) == {"vulnerability", "exposure", "criticality"}
    it = NS(is_ot_asset=False, network_zone="it", primary_protocol=None, asset_type="hardware", criticality="low")
    assert score_asset(it, [])[0] == 0
    assert vulnerability_score([]) == 0 and clamp(500) == 100


async def test_ot_summary_and_aggregates(client, auth):
    s = (await client.get("/api/v1/ot/summary", headers=auth)).json()
    assert s["managed_ot_assets"] == 8 and s["discovered_ot_devices"] == 3
    assert s["discovery_gap"] == 2  # two OT devices not correlated to an asset
    zones = {z["zone"]: z["count"] for z in (await client.get("/api/v1/ot/devices-by-zone", headers=auth)).json()["zones"]}
    assert zones["control"] == 3
    assert (await client.get("/api/v1/ot/devices-by-protocol", headers=auth)).json()["protocols"]


async def test_device_list_sorted_by_risk(client, auth):
    devs = (await client.get("/api/v1/ot/discovered-devices", headers=auth)).json()["devices"]
    risks = [d["risk_score"] for d in devs]
    assert risks == sorted(risks, reverse=True) and {d["ip_address"] for d in devs[:2]} == {"10.2.1.40", "10.2.1.99"}


async def test_promote_and_correlate(client, auth):
    devs = (await client.get("/api/v1/ot/discovered-devices", headers=auth, params={"correlated": False, "is_ot_device": True})).json()["devices"]
    did = devs[0]["id"]
    r = await client.post(f"/api/v1/ot/discovered-devices/{did}/promote-to-asset", headers=auth)
    assert r.status_code == 200
    assert (await client.post(f"/api/v1/ot/discovered-devices/{did}/promote-to-asset", headers=auth)).status_code == 409
    assert (await client.get("/api/v1/ot/summary", headers=auth)).json()["discovery_gap"] == 1
    assert (await client.get("/api/v1/assets/", headers=auth)).json()["total"] == 12
    assert (await client.post(f"/api/v1/ot/discovered-devices/{devs[1]['id']}/correlate/9999", headers=auth)).status_code == 404


async def test_sensor_ingest_batch_upserts(client, auth):
    sid = (await client.post("/api/v1/ot/sensors", headers=auth, json={"name": "s", "sensor_type": "zeek", "api_token": "sekret"})).json()
    assert "api_token" not in sid and "sekret" not in str(sid)
    batch = {"sensor_id": sid["id"], "devices": [
        {"ip_address": "10.9.9.9", "is_ot_device": True, "ot_device_type": "plc", "services_detected": ["telnet"], "industrial_protocols": ["modbus"]}]}
    first = (await client.post("/api/v1/ot/ingest/batch", headers=auth, json=batch)).json()
    assert first["summary"]["created"] == 1
    second = (await client.post("/api/v1/ot/ingest/batch", headers=auth, json=batch)).json()
    assert second["summary"] == {"processed": 1, "created": 0, "updated": 1}
    assert (await client.post("/api/v1/ot/ingest/batch", headers=auth, json={"sensor_id": 999, "devices": batch["devices"]})).status_code == 404


async def test_ot_isolation_between_users(client, auth):
    await client.post("/api/v1/auth/register", json={"email": "eve@example.com", "password": "password-eve-1"})
    tok = (await client.post("/api/v1/auth/login", data={"username": "eve@example.com", "password": "password-eve-1"})).json()
    eve = {"Authorization": f"Bearer {tok['access_token']}"}
    assert (await client.get("/api/v1/ot/discovered-devices", headers=eve)).json()["total"] == 0
    did = (await client.get("/api/v1/ot/discovered-devices", headers=auth)).json()["devices"][0]["id"]
    assert (await client.get(f"/api/v1/ot/discovered-devices/{did}", headers=eve)).status_code == 404
    assert (await client.get("/api/v1/topology/graph", headers=eve)).json() == {"nodes": [], "edges": []}


async def test_topology_graph_and_stats(client, auth):
    g = (await client.get("/api/v1/topology/graph", headers=auth)).json()
    assert len(g["edges"]) == 10 and any(n["type"] == "ot_device" for n in g["nodes"])
    risky = [e for e in g["edges"] if e["risky"]]
    assert {e["protocol"] for e in risky} <= {"modbus", "ethernet_ip", "profibus", "dnp3", "telnet", "ftp", "http"} and risky
    st = (await client.get("/api/v1/topology/stats", headers=auth)).json()
    assert st["unencrypted_ot_connections"] == len(risky)
    r = await client.post("/api/v1/topology/connections", headers=auth,
                          json={"source_ip": "1.1.1.1", "target_ip": "2.2.2.2", "protocol": "dnp3", "port": 20000})
    assert r.status_code == 201
