#!/usr/bin/env python3
"""Inject a SIMULATED multi-stage attack into a running SOC Platform and show what it detects.

Nothing is sent to any real network: this only POSTs synthetic Suricata-style telemetry to *your own* SOC
Platform API, tagged `synthetic: true`. That tag means:
  - the events, and any case built only from them, are stored with is_synthetic=True
  - they are EXCLUDED from /alerts/, /events/, /cases/, the dashboard and MITRE coverage by default — the
    same rule real production data follows
  - this script reads them back with include_synthetic=true (admin-only) specifically so you can see what
    the pipeline produced, which is not how the normal UI behaves

This is a detection-pipeline test tool, not a monitoring feed. A real deployment's alerts come only from
real sensors posting to /api/v1/events/ingest without the synthetic flag — see scripts/suricata_shipper.py
and the README's "Connecting a real sensor" section.

    python scripts/simulate_attack.py                      # http://localhost:8000, demo login
    python scripts/simulate_attack.py --url http://localhost:8010 --email you@x.com --password '...'
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone

import httpx

SENSOR_NAME = "Attack Simulation Sensor"   # referenced by scripts/purge_demo_data.py — keep names in sync

ATTACKER = "198.51.100.77"        # TEST-NET-2 (reserved for documentation, never routable)
PIVOT = "10.5.0.88"               # compromised corporate workstation
TARGET_PLC = "10.2.1.30"          # Modbus PLC (exists in the demo data)
S7_PLC = "10.2.1.20"

# minutes_ago, severity(1=high,2=med,3=low), signature, category, src, dst, dport, proto, action
STAGES = [
    ("1 Initial access", [
        (46, 2, "ET SCAN Possible RDP Brute Force Attempt", "Attempted Information Leak", ATTACKER, PIVOT, 3389, "tcp", "allowed"),
        (44, 1, "ET POLICY RDP Successful Login After Multiple Failures", "Attempted Administrator Privilege Gain", ATTACKER, PIVOT, 3389, "tcp", "allowed"),
    ]),
    ("2 Discovery", [
        (38, 2, "ET SCAN Nmap Port Scan of OT Subnet", "Attempted Information Leak", PIVOT, "10.2.1.0", 0, "tcp", "allowed"),
        (37, 2, "ET SCAN Modbus Device Identification Scan", "Attempted Information Leak", PIVOT, TARGET_PLC, 502, "tcp", "allowed"),
    ]),
    ("3 Lateral movement", [
        (30, 1, "ET POLICY SMB Admin Share Access From Workstation", "Potentially Bad Traffic", PIVOT, "10.3.1.6", 445, "tcp", "allowed"),
        (28, 1, "ET EXPLOIT Remote Desktop Lateral Movement To SCADA Server", "Attempted Administrator Privilege Gain", PIVOT, "10.3.1.6", 3389, "tcp", "allowed"),
    ]),
    ("4 Command and control", [
        (22, 1, "ET TROJAN DNS Tunneling Beacon to Suspected C2 Domain", "A Network Trojan was detected", "10.3.1.6", "8.8.8.8", 53, "udp", "allowed"),
    ]),
    ("5 Impact on the process (PLC)", [
        (14, 1, "ET EXPLOIT S7comm CPU STOP Command From Non-Engineering Host", "Attempted Denial of Service", "10.3.1.6", S7_PLC, 102, "tcp", "blocked"),
        (13, 1, "ET EXPLOIT Modbus TCP Unauthorized Write Single Register", "Attempted Administrator Privilege Gain", "10.3.1.6", TARGET_PLC, 502, "tcp", "blocked"),
        (12, 1, "ET EXPLOIT Modbus TCP Force Listen Only Mode", "Attempted Denial of Service", "10.3.1.6", TARGET_PLC, 502, "tcp", "allowed"),
    ]),
    ("6 Exfiltration", [
        (6, 1, "ET POLICY Large Outbound Transfer Possible Data Exfiltration", "Potential Corporate Privacy Violation", "10.3.1.6", ATTACKER, 443, "tcp", "allowed"),
    ]),
]

# a rogue device an attacker plugged in: cleartext services on the OT network
ROGUE_DEVICE = {"ip_address": "10.2.1.77", "hostname": "unknown-laptop", "manufacturer": "Unknown", "is_ot_device": True,
                "ot_device_type": "plc", "services_detected": ["telnet", "http"], "industrial_protocols": ["modbus"],
                "protocols": ["modbus", "http"], "discovery_method": "sensor_report"}


def eve(minutes_ago, sev, sig, cat, src, dst, dport, proto, action, now):
    return {"timestamp": (now - timedelta(minutes=minutes_ago)).isoformat(), "event_type": "alert", "src_ip": src,
            "dest_ip": dst, "dest_port": dport, "proto": proto.upper(),
            "alert": {"signature": sig, "signature_id": 9000000 + abs(hash(sig)) % 99999, "severity": sev, "category": cat, "action": action}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--email", default="admin@example.com")
    ap.add_argument("--password", default="password123")
    a = ap.parse_args()
    now = datetime.now(timezone.utc)

    with httpx.Client(base_url=a.url + "/api/v1", timeout=60) as http:
        try:
            r = http.post("/auth/login", data={"username": a.email, "password": a.password})
        except httpx.ConnectError:
            print(f"Cannot reach {a.url}. Start the server first:  .venv/bin/python -m uvicorn app.main:app"); return 1
        if r.status_code != 200:
            print(f"Login failed ({r.status_code}). Is the server running at {a.url}?"); return 1
        http.headers["Authorization"] = "Bearer " + r.json()["access_token"]

        def cases():
            # include_synthetic=true: this script's own events/cases are tagged synthetic and would otherwise
            # be invisible here too, same as on the dashboard.
            return http.get("/cases/", params={"size": 100, "include_synthetic": "true"}).json()
        before = {"events": http.get("/events/stats").json()["data"]["total_events"], "cases": cases()["total"],
                  "devices": http.get("/ot/discovered-devices").json()["total"]}

        print(f"\n=== Simulating attack from {ATTACKER} against the OT network (synthetic telemetry, tagged accordingly) ===")
        total = 0
        for name, rows in STAGES:
            batch = [eve(*row, now) for row in rows]
            res = http.post("/events/ingest", json={"source_type": "suricata", "source_name": SENSOR_NAME,
                                                     "events": batch, "synthetic": True})
            ok = res.json()["data"]["accepted"]; total += ok
            print(f"  stage {name:32s} -> sent {len(batch)} events, accepted {ok}")
        http.post("/ot/ingest/single", json=ROGUE_DEVICE)
        print(f"  rogue device appears on the OT network: {ROGUE_DEVICE['ip_address']} (telnet + modbus)")

        print("\n=== Running the detection pipeline (detect -> triage) ===")
        d = http.post("/cases/pipeline", params={"hours_back": 2}).json()["data"]
        print(f"  detect : {d['detect'].get('summary', d['detect'])}")
        for f in d["detect"].get("findings", []):
            print(f"           [{f['severity']:8s}] {f['title']}")
        print(f"  triage : {d['triage'].get('summary', d['triage'])}")

        new = [c for c in cases()["cases"] if c["created_by"] == "agent"][:d["triage"].get("cases_created", 0)]
        for c in new:
            detail = http.get(f"/cases/{c['id']}").json()
            tech = ", ".join(f"{t['id']} {t['name']}" for t in (detail["mitre_techniques"] or [])) or "none mapped"
            print(f"\n  CASE #{c['id']} [{c['severity']}] {c['title'][:90]}")
            print(f"     events={c['event_count']} confidence={c['confidence_score']} MITRE: {tech}")

        dev = next(x for x in http.get("/ot/discovered-devices").json()["devices"] if x["ip_address"] == ROGUE_DEVICE["ip_address"])
        print(f"\n  rogue device risk score {dev['risk_score']}/100 -> {', '.join(dev['risk_factors'])}")

        print("\n=== Did the platform see each stage? (event search by attack IPs, include_synthetic=true) ===")
        for label, ip in (("attacker", ATTACKER), ("pivot host", PIVOT)):
            n = http.get("/events/", params={"source_ip": ip, "size": 1, "include_synthetic": "true"}).json()["total"]
            print(f"  events from {label} {ip}: {n}")
        hunt = http.post("/hunt/", json={"hypothesis": "unauthorized modbus writes or s7 stop commands to PLCs"}).json()["data"]
        print(f"  hunt 'unauthorized modbus/S7 to PLCs': {[q['row_count'] for q in hunt['query_results']]} rows per query")

        run = http.post("/validation/runs", json={"name": "Post-attack coverage", "mitre_techniques": ["T1046", "T1021", "T1110", "T0855", "T1071"]}).json()["data"]
        out = http.post(f"/validation/runs/{run['id']}/execute").json()["data"]
        print(f"  detection coverage after attack: {out['summary']}")

        after = {"events": http.get("/events/stats").json()["data"]["total_events"], "cases": cases()["total"],
                 "devices": http.get("/ot/discovered-devices").json()["total"]}
        print(f"\nBEFORE -> AFTER   events {before['events']} -> {after['events']}   cases {before['cases']} -> {after['cases']}   devices {before['devices']} -> {after['devices']}")
        print(f"\nSee it in the UI:  {a.url}/app/cases   {a.url}/app/events   {a.url}/app/ot   {a.url}/app/mitre")
    return 0


if __name__ == "__main__":
    sys.exit(main())
