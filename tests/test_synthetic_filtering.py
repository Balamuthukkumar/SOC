"""Verifies the core requirement: seeded/synthetic data never appears as a real alert, case, or event by
default — only real sensor/feed data does — and that provenance is clearly labeled when it is shown."""
from datetime import datetime, timezone

from app.services.ingestion import _NON_COPYABLE, parse_generic

REAL_EVENT = {"timestamp": None, "event_type": "alert", "src_ip": "203.0.113.9", "dest_ip": "10.2.1.30",
             "dest_port": 502, "alert": {"signature": "Real Modbus write attempt", "category": "modbus", "severity": 1}}


def _now_event(overrides: dict | None = None) -> dict:
    ev = {**REAL_EVENT, "timestamp": datetime.now(timezone.utc).isoformat()}
    ev.update(overrides or {})
    return ev


# ---------------- dashboard-facing endpoints exclude synthetic by default ----------------
async def test_alerts_empty_by_default_despite_seed_data(client, auth):
    assert (await client.get("/api/v1/alerts/", headers=auth)).json() == {"alerts": [], "total": 0, "page": 1, "size": 10, "pages": 1}
    stats = (await client.get("/api/v1/alerts/stats/overview", headers=auth)).json()
    assert all(v == 0 for v in stats.values())


async def test_events_empty_by_default_despite_seed_data(client, auth):
    assert (await client.get("/api/v1/events/", headers=auth)).json()["total"] == 0
    assert (await client.get("/api/v1/events/stats", headers=auth)).json()["data"]["total_events"] == 0
    # the seeded sensors produced only synthetic events, so they must not appear as live sources either
    assert (await client.get("/api/v1/events/sources", headers=auth)).json() == []


async def test_cases_and_mitre_coverage_empty_by_default_despite_seed_data(client, auth):
    assert (await client.get("/api/v1/cases/", headers=auth)).json()["total"] == 0
    assert (await client.get("/api/v1/mitre/coverage", headers=auth)).json()["data"]["covered_techniques"] == 0
    assert (await client.get("/api/v1/cases/search", headers=auth, params={"q": "PLC"})).json()["data"] == []


# ---------------- real ingested data appears immediately, labeled real ----------------
async def test_real_ingested_event_appears_by_default(client, auth):
    r = await client.post("/api/v1/events/ingest", headers=auth, json={"source_type": "suricata", "events": [_now_event()]})
    assert r.json()["data"]["accepted"] == 1
    listed = (await client.get("/api/v1/events/", headers=auth)).json()
    assert listed["total"] == 1 and listed["events"][0]["is_synthetic"] is False
    assert (await client.get("/api/v1/events/stats", headers=auth)).json()["data"]["total_events"] == 1
    sources = (await client.get("/api/v1/events/sources", headers=auth)).json()
    assert len(sources) == 1 and sources[0]["name"] == "suricata"


async def test_client_cannot_self_mark_real_event_as_synthetic_via_payload(client, auth):
    """A raw event body that smuggles is_synthetic:false (or any value) must never override the batch-level
    synthetic flag — provenance is controlled only by the server, from the authenticated request."""
    sneaky = _now_event({"is_synthetic": False, "source_ip": "198.51.100.5"})
    r = await client.post("/api/v1/events/ingest", headers=auth,
                          json={"source_type": "generic", "events": [sneaky], "synthetic": True})
    assert r.json()["data"]["accepted"] == 1
    # the batch said synthetic:true — that must win regardless of what the raw payload claimed
    params = {"source_ip": "198.51.100.5"}
    assert (await client.get("/api/v1/events/", headers=auth, params=params)).json()["total"] == 0
    admin_view = (await client.get("/api/v1/events/", headers=auth, params={**params, "include_synthetic": "true"})).json()
    assert admin_view["total"] == 1 and admin_view["events"][0]["is_synthetic"] is True


def test_parse_generic_never_copies_provenance_or_identity_fields():
    raw = {"is_synthetic": False, "user_id": 999, "id": 1, "source_id": 1, "signature": "x", "event_type": "alert"}
    out = parse_generic(raw)
    assert not (_NON_COPYABLE & out.keys())
    assert out["signature"] == "x"  # legitimate fields still copy through


# ---------------- non-admin can never see synthetic data even if they ask ----------------
async def test_non_admin_include_synthetic_is_ignored(client, auth):
    await client.post("/api/v1/auth/register", json={"email": "viewer@example.com", "password": "password-1234"})
    tok = (await client.post("/api/v1/auth/login", data={"username": "viewer@example.com", "password": "password-1234"})).json()
    viewer = {"Authorization": f"Bearer {tok['access_token']}"}
    # viewer has no seed data at all (isolated per user), but the parameter itself must be a no-op for non-admins
    assert (await client.get("/api/v1/alerts/", headers=viewer, params={"include_synthetic": "true"})).json()["total"] == 0
    assert (await client.get("/api/v1/events/", headers=viewer, params={"include_synthetic": "true"})).json()["total"] == 0
    assert (await client.get("/api/v1/cases/", headers=viewer, params={"include_synthetic": "true"})).json()["total"] == 0


async def test_admin_include_synthetic_reveals_seed_data_clearly_labeled(client, auth):
    alerts = (await client.get("/api/v1/alerts/", headers=auth, params={"include_synthetic": "true"})).json()
    assert alerts["total"] == 6
    for a in alerts["alerts"]:
        assert a["is_synthetic"] is True and a["source_label"] == "Demo / test data (not a real finding)"
        assert a["detection_rule"]  # requirement: every alert names its detection rule
    events = (await client.get("/api/v1/events/", headers=auth, params={"include_synthetic": "true", "size": 50})).json()
    assert events["total"] == 12 and all(e["is_synthetic"] for e in events["events"])
    cases = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()
    assert cases["total"] == 1 and cases["cases"][0]["is_synthetic"] is True


# ---------------- a case built from a mix of real + synthetic evidence counts as real ----------------
async def test_case_with_any_real_evidence_is_never_hidden(client, auth):
    """Attach a real alert's asset to a burst of real events sharing an IP with nothing synthetic — the
    resulting case must be real (visible by default), proving the pipeline never needs an admin flag to
    produce a genuine alert when genuine evidence exists."""
    events = [_now_event({"src_ip": "203.0.113.50", "dest_ip": "10.2.1.30",
                          "alert": {"signature": f"Real Modbus probe {i}", "category": "modbus", "severity": 1}})
              for i in range(3)]
    await client.post("/api/v1/events/ingest", headers=auth, json={"source_type": "suricata", "events": events})
    r = await client.post("/api/v1/cases/auto-triage", headers=auth, params={"hours_back": 1})
    assert r.json()["data"]["cases_created"] >= 1
    real_cases = (await client.get("/api/v1/cases/", headers=auth)).json()
    assert real_cases["total"] >= 1
    assert any(c["event_count"] >= 1 for c in real_cases["cases"])


# ---------------- hunt labels provenance per row instead of silently filtering ----------------
async def test_hunt_labels_synthetic_rows_instead_of_hiding_them(client, auth):
    await client.post("/api/v1/events/ingest", headers=auth, json={"source_type": "suricata", "events": [_now_event()]})
    d = (await client.post("/api/v1/hunt/", headers=auth, json={"hypothesis": "modbus writes to PLCs"})).json()["data"]
    rows = [row for q in d["query_results"] for row in q["rows"]]
    assert rows, "hunt should find both the real event just ingested and the synthetic seed events"
    assert any(r["is_synthetic"] is False for r in rows)
    assert any(r["is_synthetic"] is True for r in rows)   # the synthetic seed Modbus event is still visible, just labeled


# ---------------- purge script retroactively tags/removes already-seeded rows ----------------
async def test_purge_script_tags_seed_rows(client, auth):
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import Alert, Case, SecurityEvent
    from scripts.purge_demo_data import main as purge_main

    async with SessionLocal() as db:
        # simulate "seeded before the is_synthetic column/flagging existed"
        for model in (Alert, SecurityEvent, Case):
            for row in (await db.execute(select(model))).scalars():
                row.is_synthetic = False
        await db.commit()

    assert (await client.get("/api/v1/alerts/", headers=auth)).json()["total"] == 6  # now wrongly "real"

    import sys
    old_argv = sys.argv
    sys.argv = ["purge_demo_data.py"]  # default mode: tag, don't delete
    try:
        assert await purge_main() == 0
    finally:
        sys.argv = old_argv

    assert (await client.get("/api/v1/alerts/", headers=auth)).json()["total"] == 0
    assert (await client.get("/api/v1/events/", headers=auth)).json()["total"] == 0
    assert (await client.get("/api/v1/cases/", headers=auth)).json()["total"] == 0


async def test_purge_script_delete_mode_removes_rows_entirely(client, auth):
    import sys

    from scripts.purge_demo_data import main as purge_main
    old_argv = sys.argv
    sys.argv = ["purge_demo_data.py", "--delete"]
    try:
        assert await purge_main() == 0
    finally:
        sys.argv = old_argv
    admin_view = (await client.get("/api/v1/alerts/", headers=auth, params={"include_synthetic": "true"})).json()
    assert admin_view["total"] == 0  # gone even from the admin view — not just hidden
    assert (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()["total"] == 0


async def test_purge_script_sweeps_leftover_simulator_runs(client, auth):
    """Before synthetic-tagging was added, scripts/simulate_attack.py left real-looking rows behind (identified
    by EventSource name, not content). The purge script must find and remove those too, including any case
    built entirely from them, without touching the unrelated seed case."""
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import EventSource, SecurityEvent
    from app.seed import DEMO_EMAIL
    from app.services.agents.triage import TriageAgent
    from scripts.purge_demo_data import main as purge_main
    from scripts.simulate_attack import SENSOR_NAME

    async with SessionLocal() as db:
        from app.models import User
        user = (await db.execute(select(User).where(User.email == DEMO_EMAIL))).scalar_one()
        src = EventSource(user_id=user.id, name=SENSOR_NAME, source_type="suricata")
        db.add(src)
        await db.flush()
        db.add(SecurityEvent(user_id=user.id, source_id=src.id, source_type="suricata",
                             timestamp=datetime.now(timezone.utc), event_type="alert", severity="high",
                             signature="ET EXPLOIT Modbus TCP Unauthorized Write Single Register",
                             source_ip="10.3.1.6", dest_ip="10.2.1.30", dest_port=502, is_synthetic=False))
        await db.commit()
        result = await TriageAgent(db, user.id).execute(hours_back=1)
        assert result["cases_created"] >= 1

    # leftover data is currently indistinguishable from real — shows up by default, exactly the bug being fixed
    assert (await client.get("/api/v1/events/", headers=auth)).json()["total"] >= 1
    assert (await client.get("/api/v1/cases/", headers=auth)).json()["total"] >= 1

    import sys
    old_argv = sys.argv
    sys.argv = ["purge_demo_data.py", "--delete"]
    try:
        assert await purge_main() == 0
    finally:
        sys.argv = old_argv

    assert (await client.get("/api/v1/events/", headers=auth)).json()["total"] == 0
    assert (await client.get("/api/v1/cases/", headers=auth)).json()["total"] == 0
    assert (await client.get("/api/v1/events/sources", headers=auth)).json() == []


async def test_purge_script_never_touches_real_data(client, auth):
    """Seed a real alert alongside the demo data and confirm the purge script leaves it untouched."""
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import Alert, Asset, User
    from app.seed import DEMO_EMAIL
    from scripts.purge_demo_data import main as purge_main

    async with SessionLocal() as db:
        user = (await db.execute(select(User).where(User.email == DEMO_EMAIL))).scalar_one()
        asset = (await db.execute(select(Asset).where(Asset.user_id == user.id))).scalars().first()
        db.add(Alert(user_id=user.id, asset_id=asset.id, cve_id="CVE-9999-0001", severity="high", title="A real alert",
                     description="not seed data", is_synthetic=False))
        await db.commit()

    import sys
    old_argv = sys.argv
    sys.argv = ["purge_demo_data.py", "--delete"]
    try:
        assert await purge_main() == 0
    finally:
        sys.argv = old_argv

    remaining = (await client.get("/api/v1/alerts/", headers=auth)).json()
    assert remaining["total"] == 1 and remaining["alerts"][0]["cve_id"] == "CVE-9999-0001"
