from app.services.agents.triage import correlate, rule_fallback
from app.services.ai import parse_json


async def test_pipeline_without_ai_creates_cases(client, auth):
    # seed case already links the first two alerts and the non-info events; new ingest forms a new cluster
    ev = {"timestamp": "2026-01-01T00:00:00Z", "event_type": "alert", "src_ip": "9.9.9.9", "dest_ip": "10.2.1.30",
          "dest_port": 502, "alert": {"signature": "Modbus brute force scan", "severity": 1}}
    await client.post("/api/v1/events/ingest", headers=auth, json={"source_type": "suricata", "events": [ev]})
    r = await client.post("/api/v1/cases/pipeline", headers=auth, params={"hours_back": 168})
    data = r.json()["data"]
    assert data["pipeline_status"] == "completed" and "error" not in data["detect"]
    assert data["triage"]["cases_created"] >= 1
    runs = (await client.get("/api/v1/cases/agents/runs", headers=auth)).json()
    assert {x["agent_type"] for x in runs} == {"detect", "triage"}


async def test_auto_triage_is_idempotent(client, auth):
    await client.post("/api/v1/cases/auto-triage", headers=auth, params={"hours_back": 168})
    second = await client.post("/api/v1/cases/auto-triage", headers=auth, params={"hours_back": 168})
    assert second.json()["data"]["cases_created"] == 0


async def test_mitre_endpoints(client, auth):
    # Coverage reflects only real, confirmed cases — never the synthetic seeded one — and there is no admin
    # override for that (unlike the list endpoints). Build a real case to prove coverage lights up for it.
    from datetime import datetime, timezone
    assert (await client.get("/api/v1/mitre/coverage", headers=auth)).json()["data"]["covered_techniques"] == 0
    now = datetime.now(timezone.utc).isoformat()
    ev = {"timestamp": now, "event_type": "alert", "src_ip": "9.9.9.9", "dest_ip": "10.2.1.30",
          "dest_port": 502, "alert": {"signature": "Modbus brute force scan", "category": "modbus", "severity": 1}}
    await client.post("/api/v1/events/ingest", headers=auth, json={"source_type": "suricata", "events": [ev]})
    await client.post("/api/v1/cases/auto-triage", headers=auth, params={"hours_back": 168})
    cov = (await client.get("/api/v1/mitre/coverage", headers=auth)).json()["data"]
    assert cov["covered_techniques"] >= 1
    assert (await client.get("/api/v1/mitre/techniques", params={"search": "modbus"}, headers=auth)).json()


def test_parse_json_handles_fences():
    assert parse_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json('noise {"a": 2} trailing') == {"a": 2}


def test_correlate_merges_shared_ips():
    class E:
        def __init__(self, s, d): self.source_ip, self.dest_ip, self.severity = s, d, "high"
    groups = correlate([], [E("1.1.1.1", "2.2.2.2"), E("3.3.3.3", "4.4.4.4"), E("2.2.2.2", "3.3.3.3")])
    assert len(groups) == 1 and len(groups[0]["events"]) == 3


def test_blank_signature_maps_to_nothing():
    from app.services.mitre import map_signature_to_techniques, search_techniques
    assert map_signature_to_techniques("   ") == [] and search_techniques(" ") == []


async def test_pipeline_does_not_duplicate_seeded_case(client, auth):
    # The seed case and its events are synthetic, so running the pipeline over them must never surface
    # anything on the *default* (production) view — that's the whole point of the is_synthetic flag.
    before_real = (await client.get("/api/v1/cases/", headers=auth)).json()["total"]
    before_all = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()["total"]
    r = await client.post("/api/v1/cases/pipeline", headers=auth, params={"hours_back": 168})
    created = r.json()["data"]["triage"]["cases_created"]
    after_real = (await client.get("/api/v1/cases/", headers=auth)).json()["total"]
    after_all = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()["total"]
    assert after_real == before_real == 0           # still nothing on the real/default dashboard view
    assert after_all == before_all + created         # but the pipeline did run, visible to an admin who asks
    # the seeded case's high-severity events must not be pulled into a second case
    ev = (await client.get("/api/v1/cases/1/events", headers=auth)).json()
    assert ev and all(e["processed"] == "in_case" for e in ev)


def test_rule_fallback_title_and_technique_ranking():
    from datetime import datetime, timezone
    from types import SimpleNamespace as NS
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def ev(sig, sev, src="1.1.1.1", dst="2.2.2.2"):
        return NS(signature=sig, category=None, severity=sev, source_ip=src, dest_ip=dst, event_type="alert", timestamp=t)
    events = [ev("ET SCAN Nmap Port Scan", "medium"), ev("ET SCAN Nmap Port Scan again", "medium"),
              ev("ET EXPLOIT Modbus TCP Unauthorized Write", "critical", dst="3.3.3.3"), ev("ET POLICY Outbound Transfer exfil", "high")]
    out = rule_fallback([], events)
    assert out["title"].startswith("ET EXPLOIT Modbus TCP Unauthorized Write") and "+3 related events across 3 hosts" in out["title"]
    ids = [x["id"] for x in out["mitre_techniques"]]
    assert ids[0] == "T1046" and len(ids) <= 8                       # two supporting events beat one
    conf = {x["id"]: x["confidence"] for x in out["mitre_techniques"]}
    assert conf["T1046"] > conf["T0855"] and all(c <= 0.9 for c in conf.values())
    assert out["severity"] == "critical"
