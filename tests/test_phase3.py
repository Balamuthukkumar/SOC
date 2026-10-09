import pytest

from app.services.agents.hunt import build_query, fallback_queries
from app.services.policy import check_action


async def test_hunt_finds_modbus_events(client, auth):
    r = await client.post("/api/v1/hunt/", headers=auth, json={"hypothesis": "unauthorized modbus writes to PLCs"})
    data = r.json()["data"]
    assert any(q["row_count"] for q in data["query_results"])
    sessions = (await client.get("/api/v1/hunt/", headers=auth)).json()
    assert sessions[0]["findings_count"] > 0
    assert (await client.get(f"/api/v1/hunt/{data['session_id']}", headers=auth)).status_code == 200


async def test_hunt_ip_query(client, auth):
    r = await client.post("/api/v1/hunt/", headers=auth, json={"hypothesis": "what did 203.0.113.42 do"})
    rows = [row for q in r.json()["data"]["query_results"] for row in q["rows"]]
    assert rows and all("203.0.113.42" in (row["source_ip"], row["dest_ip"]) for row in rows)


def test_hunt_rejects_non_whitelisted_filters():
    with pytest.raises(ValueError):
        build_query(1, {"filters": [{"field": "user_id", "op": "eq", "value": 2}]})
    with pytest.raises(ValueError):
        build_query(1, {"filters": [{"field": "severity", "op": "; DROP TABLE users", "value": 1}]})
    with pytest.raises(ValueError):
        build_query(1, {"filters": [{"field": "source_ip", "op": "like", "value": "%"}]})
    assert fallback_queries("")["queries"]


async def test_detection_rules(client, auth):
    r = await client.post("/api/v1/hunt/detections", headers=auth,
                          json={"name": "r", "rule_type": "sigma", "rule_content": "title: x"})
    assert r.status_code == 201
    assert len((await client.get("/api/v1/hunt/detections", headers=auth)).json()) == 1


def test_policy_ot_zone_forces_human():
    assert check_action("block_ip", "L4", "control", True)["requires_human"]
    assert not check_action("block_ip", "L4", "it", False)["requires_human"]
    assert check_action("isolate_host", "L4")["requires_human"]
    assert not check_action("notify", "L1")["requires_human"]


async def test_response_plan_lifecycle(client, auth):
    case_id = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()["cases"][0]["id"]
    gen = (await client.post("/api/v1/response-plans/generate", headers=auth, params={"case_id": case_id})).json()["data"]
    pid = gen["plan_id"]
    assert gen["status"] == "pending_approval"  # block_ip not auto-approved at L1
    assert (await client.post(f"/api/v1/response-plans/{pid}/execute", headers=auth)).status_code == 400
    pend = (await client.get("/api/v1/response-plans/pending-approvals", headers=auth)).json()
    assert pend["total"] == 1
    assert (await client.post(f"/api/v1/response-plans/{pid}/approve", headers=auth)).status_code == 200
    ex = (await client.post(f"/api/v1/response-plans/{pid}/execute", headers=auth)).json()["data"]
    assert ex["status"] == "completed" and ex["succeeded"] == ex["total_actions"]
    assert (await client.post(f"/api/v1/response-plans/{pid}/approve", headers=auth)).status_code == 400


async def test_response_plan_reject_and_404(client, auth):
    assert (await client.post("/api/v1/response-plans/generate", headers=auth, params={"case_id": 999})).status_code == 404
    case_id = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()["cases"][0]["id"]
    pid = (await client.post("/api/v1/response-plans/generate", headers=auth, params={"case_id": case_id})).json()["data"]["plan_id"]
    r = await client.post(f"/api/v1/response-plans/{pid}/reject", headers=auth, json={"reason": "no"})
    assert r.json()["plan_status"] == "rejected"


async def test_validation_uses_real_telemetry(client, auth):
    body = {"name": "coverage", "mitre_techniques": ["T1046", "T0855", "T1486"]}
    run = (await client.post("/api/v1/validation/runs", headers=auth, json=body)).json()["data"]
    out = (await client.post(f"/api/v1/validation/runs/{run['id']}/execute", headers=auth)).json()["data"]
    steps = {s["technique_id"]: s["result"] for s in
             (await client.get(f"/api/v1/validation/runs/{run['id']}", headers=auth)).json()["data"]["steps"]}
    assert steps == {"T1046": "detected", "T0855": "detected", "T1486": "missed"}
    assert out["results"]["detection_rate"] == pytest.approx(66.7)
    cov = (await client.get("/api/v1/validation/coverage", headers=auth)).json()["data"]
    assert {c["technique_id"] for c in cov} == set(steps)
    assert (await client.post(f"/api/v1/validation/runs/{run['id']}/execute", headers=auth)).status_code == 400


async def test_validation_guards(client, auth):
    assert (await client.post("/api/v1/validation/runs", headers=auth, json={"name": "x", "mode": "production"})).status_code == 403
    assert (await client.post("/api/v1/validation/runs", headers=auth, json={"name": "x", "mitre_techniques": ["T9999"]})).status_code == 422
