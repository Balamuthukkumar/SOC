#!/usr/bin/env python3
"""Live network sensor: watches this machine's interface with tcpdump and reports REAL attacks to the SOC Platform.

No Suricata needed. Detects, per source IP (never flagged synthetic, so it shows on the dashboard):
  - port scan        (nmap etc.: SYNs to many distinct ports)
  - SYN flood        (hping3 --flood -S etc.)
  - brute force      (many connection attempts to one auth service: ssh/rdp/ftp/telnet/smb/vnc/mysql)
  - ICMP flood / ping sweep
  - connection attempts to ICS ports (modbus 502, s7 102, dnp3 20000, enip 44818)

Run only on networks you are authorized to monitor. tcpdump needs root:

    sudo .venv/bin/python scripts/live_sensor.py --iface en0 --password 'yourpass'
"""
import argparse
import re
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import httpx

AUTH_PORTS = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet", 445: "SMB", 5900: "VNC", 3306: "MySQL", 5432: "Postgres"}
ICS_PORTS = {502: "Modbus", 102: "S7comm", 20000: "DNP3", 44818: "EtherNet/IP", 47808: "BACnet"}
WINDOW = 10            # seconds
SCAN_PORTS = 15        # distinct ports in window
FLOOD_SYNS = 150       # SYNs in window
BRUTE_SYNS = 8         # attempts to one auth port in window
ICMP_FLOOD = 100
COOLDOWN = 60          # re-alert same (src, kind) at most once per minute

# 12:00:00.123 IP 1.2.3.4.5555 > 5.6.7.8.22: Flags [S], ...    |   ... IP a > b: ICMP echo request
LINE = re.compile(r"IP (\d+\.\d+\.\d+\.\d+)(?:\.(\d+))? > (\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?: (.*)")


def event(kind, sig, sev, src, dst, dport, proto, cat, detail):
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "alert", "src_ip": src, "dest_ip": dst,
            "dest_port": dport, "proto": proto.upper(),
            "alert": {"signature": sig, "signature_id": 8000000 + abs(hash(kind)) % 99999, "severity": sev,
                      "category": cat, "action": "allowed"},
            "detail": detail}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="en0")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--email", default="admin@example.com")
    ap.add_argument("--password", required=True)
    ap.add_argument("--sensor-name", default="Live Network Sensor")
    ap.add_argument("--ignore", nargs="*", default=[], help="IPs never to alert on (e.g. your gateway)")
    a = ap.parse_args()

    http = httpx.Client(base_url=a.url + "/api/v1", timeout=30)
    r = http.post("/auth/login", data={"username": a.email, "password": a.password})
    if r.status_code != 200:
        print(f"Login failed ({r.status_code}). Is the server running at {a.url}?"); return 1
    http.headers["Authorization"] = "Bearer " + r.json()["access_token"]

    local = subprocess.run(["ipconfig", "getifaddr", a.iface], capture_output=True, text=True).stdout.strip()
    flt = f"dst host {local} and (tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn or icmp)" if local else \
          "(tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn) or icmp"
    print(f"Watching {a.iface} ({local or 'all hosts'}) — attacks against this machine will appear in the dashboard. Ctrl-C to stop.")
    p = subprocess.Popen(["tcpdump", "-l", "-n", "-i", a.iface, flt], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    syns = defaultdict(deque)      # src -> deque[(t, dst, dport)]
    icmps = defaultdict(deque)
    last_alert: dict = {}
    pending: list = []

    def fire(src, kind, ev):
        if src in a.ignore or time.time() - last_alert.get((src, kind), 0) < COOLDOWN:
            return
        last_alert[(src, kind)] = time.time()
        pending.append(ev)
        print(f"[ALERT] {ev['alert']['signature']}  {src} -> {ev['dest_ip']}:{ev['dest_port']}")

    def flush():
        if not pending:
            return
        res = http.post("/events/ingest", json={"source_type": "suricata", "source_name": a.sensor_name, "events": pending})
        if res.status_code == 201:
            http.post("/cases/pipeline", params={"hours_back": 1})
            pending.clear()
        else:
            print("ingest failed", res.status_code, res.text[:200])

    last_flush = time.time()
    try:
        for line in p.stdout:
            now = time.time()
            m = LINE.search(line)
            if m:
                src, _, dst, dport, rest = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
                dport = int(dport) if dport else 0
                if "ICMP" in rest:
                    q = icmps[src]; q.append(now)
                    while q and now - q[0] > WINDOW: q.popleft()
                    if len(q) >= ICMP_FLOOD:
                        fire(src, "icmp", event("icmp", "LIVE DoS ICMP Flood Detected", 1, src, dst, 0, "icmp",
                                                "Attempted Denial of Service", f"{len(q)} ICMP packets in {WINDOW}s"))
                    elif len(q) == 20:
                        fire(src, "ping", event("ping", "LIVE SCAN ICMP Ping Sweep / Host Discovery", 2, src, dst, 0, "icmp",
                                                "Attempted Information Leak", "ICMP echo burst"))
                    continue
                q = syns[src]; q.append((now, dst, dport))
                while q and now - q[0][0] > WINDOW: q.popleft()
                ports = {x[2] for x in q}
                if dport in ICS_PORTS:
                    fire(src, f"ics{dport}", event("ics", f"LIVE ICS {ICS_PORTS[dport]} Connection Attempt From Unauthorized Host",
                                                   1, src, dst, dport, "tcp", "Attempted Administrator Privilege Gain", "ICS port touched"))
                if len(q) >= FLOOD_SYNS:
                    fire(src, "flood", event("flood", "LIVE DoS TCP SYN Flood Detected", 1, src, dst, dport, "tcp",
                                             "Attempted Denial of Service", f"{len(q)} SYNs in {WINDOW}s"))
                elif len(ports) >= SCAN_PORTS:
                    fire(src, "scan", event("scan", "LIVE SCAN Nmap Port Scan Detected", 2, src, dst, dport, "tcp",
                                            "Attempted Information Leak", f"{len(ports)} distinct ports in {WINDOW}s"))
                elif dport in AUTH_PORTS and sum(1 for x in q if x[2] == dport) >= BRUTE_SYNS:
                    fire(src, f"brute{dport}", event("brute", f"LIVE POLICY {AUTH_PORTS[dport]} Brute Force Attempt", 1, src, dst, dport,
                                                     "tcp", "Attempted Administrator Privilege Gain", "repeated connections to auth service"))
            if now - last_flush > 3:
                flush(); last_flush = now
    except KeyboardInterrupt:
        pass
    finally:
        p.terminate(); flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
