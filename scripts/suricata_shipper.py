#!/usr/bin/env python3
"""Tail a real Suricata eve.json log and ship new lines to the SOC Platform's ingest endpoint.

This is the standard way to connect a real IDS sensor: point Suricata at traffic you're authorized to monitor,
let it write eve.json as usual, and run this alongside it. Events posted here are never marked synthetic, so
they appear as real alerts/cases/dashboard data as soon as the detection pipeline runs.

    python scripts/suricata_shipper.py /var/log/suricata/eve.json \\
        --url http://localhost:8000 --email you@example.com --password '...'

By default it only ships new lines appended after it starts (like `tail -f`). Use --from-start to also ship
what's already in the file (e.g. on first run).
"""
import argparse
import sys
import time
from pathlib import Path

import httpx

BATCH_SIZE = 200
BATCH_INTERVAL_SECONDS = 5
POLL_SECONDS = 1


def read_new_lines(fh, buffer: list[str]):
    import json
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert":  # eve.json also logs flow/dns/tls noise we don't need here
            buffer.append(event)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile", type=Path, help="Path to Suricata's eve.json")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--email", default="admin@example.com")
    ap.add_argument("--password", required=True)
    ap.add_argument("--sensor-name", default=None, help="Defaults to the hostname of this machine")
    ap.add_argument("--from-start", action="store_true", help="Also ship lines already in the file")
    a = ap.parse_args()

    if not a.logfile.exists():
        print(f"{a.logfile} does not exist. Is Suricata configured to write eve.json there?"); return 1

    sensor_name = a.sensor_name or f"suricata@{Path('/etc/hostname').read_text().strip() if Path('/etc/hostname').exists() else 'sensor'}"

    with httpx.Client(base_url=a.url + "/api/v1", timeout=30) as http:
        try:
            r = http.post("/auth/login", data={"username": a.email, "password": a.password})
        except httpx.ConnectError:
            print(f"Cannot reach {a.url}."); return 1
        if r.status_code != 200:
            print(f"Login failed ({r.status_code})."); return 1
        http.headers["Authorization"] = "Bearer " + r.json()["access_token"]

        print(f"Shipping real alert events from {a.logfile} to {a.url} as sensor '{sensor_name}' "
              f"({'from start' if a.from_start else 'tailing new lines only'}). Ctrl-C to stop.")

        with a.logfile.open("r") as fh:
            if not a.from_start:
                fh.seek(0, 2)  # end of file — only new lines count

            buffer: list[dict] = []
            last_flush = time.monotonic()
            total = 0
            try:
                while True:
                    read_new_lines(fh, buffer)
                    due = buffer and (len(buffer) >= BATCH_SIZE or time.monotonic() - last_flush >= BATCH_INTERVAL_SECONDS)
                    if due:
                        # synthetic is never set here — real sensor data is always real.
                        res = http.post("/events/ingest", json={"source_type": "suricata", "source_name": sensor_name,
                                                                "events": buffer})
                        if res.status_code == 201:
                            n = res.json()["data"]["accepted"]; total += n
                            print(f"  shipped {n} events (total {total})")
                        else:
                            print(f"  ingest failed: {res.status_code} {res.text[:200]}")
                        buffer, last_flush = [], time.monotonic()
                    time.sleep(POLL_SECONDS)
            except KeyboardInterrupt:
                print(f"\nStopped. Shipped {total} events this run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
