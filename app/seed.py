"""Demo data: a water-treatment plant hit by a multi-stage intrusion."""
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (Alert, Asset, Case, CaseAlert, CaseEvent, CaseTimeline, DiscoveredDevice, EventSource,
                        NetworkConnection, NetworkSensor, SecurityEvent, User)
from app.services.ot_risk import score_device
from app.models.base import utcnow
from app.security import hash_password

DEMO_EMAIL, DEMO_PASSWORD = "admin@example.com", "password123"

# name, type, vendor, product, ot, zone, protocol, criticality, ip
ASSETS = [
    ("Endress+Hauser Promag 400 Flow Meter", "other_ot", "Endress+Hauser", "Promag 400", True, "field", "profinet", "high", "10.1.1.10"),
    ("Siemens SIPART PS2 Valve Positioner", "other_ot", "Siemens", "SIPART PS2", True, "field", "hart", "medium", "10.1.1.20"),
    ("Allen-Bradley ControlLogix 5580", "plc", "Rockwell Automation", "ControlLogix 5580", True, "control", "ethernet_ip", "critical", "10.2.1.10"),
    ("Siemens S7-1500 CPU 1516-3", "plc", "Siemens", "S7-1500", True, "control", "profinet", "critical", "10.2.1.20"),
    ("Schneider Modicon M340", "plc", "Schneider Electric", "Modicon M340", True, "control", "modbus", "critical", "10.2.1.30"),
    ("AVEVA InTouch HMI - Control Room A", "hmi", "AVEVA", "InTouch", True, "supervisory", "opc_ua", "high", "10.3.1.5"),
    ("Siemens WinCC SCADA Server", "scada_server", "Siemens", "WinCC", True, "supervisory", "opc_ua", "critical", "10.3.1.6"),
    ("OSIsoft PI Historian", "historian", "AVEVA", "PI Server", True, "supervisory", "https", "high", "10.3.1.20"),
    ("Fortinet FortiGate 200F", "industrial_network", "Fortinet", "FortiGate 200F", False, "dmz", "https", "critical", "10.4.0.1"),
    ("Windows Server 2022 - Active Directory", "operating_system", "Microsoft", "Windows Server 2022", False, "it", "https", "high", "10.5.0.10"),
    ("Cisco Catalyst 9300 Switch", "industrial_network", "Cisco", "Catalyst 9300", False, "it", "https", "medium", "10.5.0.2"),
]

# asset index, cve, severity, cvss, title
ALERTS = [
    (3, "CVE-2023-44374", "critical", 9.8, "Siemens S7-1500 CPU - Pre-Auth Remote Code Execution"),
    (2, "CVE-2024-6242", "high", 8.4, "Rockwell ControlLogix - CIP Authentication Bypass"),
    (4, "CVE-2021-22779", "high", 8.1, "Schneider Modicon M340 - Unencrypted Modbus Credential Exposure"),
    (6, "CVE-2022-24289", "medium", 6.5, "Siemens WinCC - SQL Injection in Web Management Interface"),
    (8, "CVE-2023-27997", "critical", 9.8, "FortiOS - Out-of-Bound Write in SSL VPN (CISA KEV)"),
    (7, "CVE-2023-34348", "medium", 5.3, "AVEVA PI Server - Improper Access Control"),
]

# hours ago, src, type, severity, signature, src_ip, dst_ip, dst_port, proto, action
Suri, Zeek = "suricata", "zeek"
EVENTS = [
    (8.0, Suri, "alert", "medium", "ET SCAN Potential VPN Brute Force", "203.0.113.42", "10.4.0.1", 443, "tcp", "allowed"),
    (7.9, Suri, "alert", "high", "ET POLICY Successful VPN Login After Multiple Failures", "203.0.113.42", "10.4.0.1", 443, "tcp", "allowed"),
    (7.5, Zeek, "conn", "info", None, "10.5.0.50", "10.3.1.5", 445, "tcp", None),
    (7.4, Suri, "alert", "high", "ET SCAN Nmap SYN Scan - Multiple Ports", "10.5.0.50", "10.2.1.0", None, "tcp", "allowed"),
    (6.7, Zeek, "conn", "medium", None, "10.5.0.50", "10.3.1.10", 3389, "tcp", "SF"),
    (6.3, Zeek, "conn", "medium", None, "10.3.1.10", "10.3.1.20", 445, "tcp", None),
    (6.0, Suri, "dns", "high", "ET TROJAN DNS Query for Suspected C2 Domain", "10.3.1.10", "8.8.8.8", 53, "udp", None),
    (5.5, Suri, "alert", "critical", "ET EXPLOIT Modbus TCP Unauthorized Write - Non-Engineering Source", "10.3.1.10", "10.2.1.30", 502, "tcp", "blocked"),
    (5.5, Suri, "alert", "critical", "ET EXPLOIT CIP Protocol - Unauthorized Program Upload Attempt", "10.3.1.10", "10.2.1.10", 44818, "tcp", "blocked"),
    (5.0, Suri, "alert", "high", "ET POLICY Large Outbound Data Transfer - Possible Exfiltration", "10.3.1.10", "203.0.113.42", 443, "tcp", "allowed"),
    (4.0, Zeek, "conn", "info", None, "10.2.1.10", "10.3.1.5", 44818, "tcp", None),
    (2.0, Zeek, "http", "info", None, "10.3.1.10", "10.3.1.20", 443, "tcp", None),
]

TECHNIQUES = [
    {"id": "T1133", "name": "External Remote Services", "confidence": 0.95},
    {"id": "T1110", "name": "Brute Force", "confidence": 0.88},
    {"id": "T1046", "name": "Network Service Discovery", "confidence": 0.90},
    {"id": "T1021.001", "name": "Remote Desktop Protocol", "confidence": 0.92},
    {"id": "T1071.004", "name": "DNS", "confidence": 0.78},
    {"id": "T0855", "name": "Unauthorized Command Message", "confidence": 0.95},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "confidence": 0.82},
]


SENSORS = [("Plant A - SPAN Port Sensor (Control Network)", "zeek", "Plant A", "10.2.0.0/16"),
           ("DMZ Perimeter - Suricata IDS", "suricata", "DMZ", "10.4.0.0/24")]

# ip, hostname, vendor, model, ot_type, ot, protocols, industrial, services, correlated asset index or None
DEVICES = [
    ("10.2.1.40", "PLC-BACKUP-01", "Siemens", "S7-1200", "plc", True, ["modbus", "http"], ["modbus"], ["modbus", "http"], None),
    ("10.2.1.99", None, "Unknown", None, None, True, ["modbus"], ["modbus"], ["modbus", "telnet"], None),
    ("10.5.0.77", "raspberrypi", "Raspberry Pi", "4B", None, False, ["ssh"], [], ["ssh"], None),
    ("10.1.1.30", "VFD-PUMP-P103", "ABB", "ACS880", "ied", True, ["profinet"], [], ["profinet"], 0),
]

# src, dst, protocol, port, encrypted
CONNECTIONS = [
    ("10.3.1.5", "10.2.1.10", "ethernet_ip", 44818, False), ("10.3.1.5", "10.2.1.20", "profinet", 102, False),
    ("10.3.1.6", "10.2.1.30", "modbus", 502, False), ("10.3.1.6", "10.3.1.20", "https", 443, True),
    ("10.3.1.10", "10.3.1.20", "smb", 445, False), ("10.5.0.50", "10.3.1.10", "rdp", 3389, True),
    ("10.4.0.1", "10.5.0.10", "https", 443, True), ("10.2.1.10", "10.1.1.10", "profinet", 34964, False),
    ("10.2.1.30", "10.1.1.20", "modbus", 502, False), ("203.0.113.42", "10.4.0.1", "https", 443, True),
]


async def seed_demo(db: AsyncSession) -> None:
    if (await db.execute(select(User).where(User.email == DEMO_EMAIL))).scalar_one_or_none():
        return
    now = utcnow()
    user = User(email=DEMO_EMAIL, hashed_password=hash_password(DEMO_PASSWORD), full_name="Admin User",
                company="Demo Water Utility", role="admin", is_verified=True)
    db.add(user)
    await db.flush()

    assets = [Asset(user_id=user.id, name=n, asset_type=t, vendor=v, product=p, is_ot_asset=ot, network_zone=z,
                    primary_protocol=proto, criticality=c, last_known_ip=ip, discovery_method="manual")
              for n, t, v, p, ot, z, proto, c, ip in ASSETS]
    db.add_all(assets)
    await db.flush()

    # is_synthetic=True: this is demo data, never a real vulnerability match. It is excluded from the
    # dashboard, /alerts/stats/overview and /alerts/ by default (see routers/alerts.py).
    alerts = [Alert(user_id=user.id, asset_id=assets[i].id, cve_id=cve, severity=sev, cvss_score=cvss, title=title,
                    description=f"{title}. Apply the vendor patch or compensating controls.",
                    remediation="Apply vendor firmware/software update; restrict network exposure.",
                    created_at=now - timedelta(hours=n * 3), is_synthetic=True)
              for n, (i, cve, sev, cvss, title) in enumerate(ALERTS)]
    db.add_all(alerts)

    sources = {Suri: EventSource(user_id=user.id, name="DMZ Suricata IDS", source_type=Suri),
               Zeek: EventSource(user_id=user.id, name="Control Net Zeek Sensor", source_type=Zeek)}
    db.add_all(sources.values())
    await db.flush()

    # is_synthetic=True: scripted demo telemetry, not real sensor traffic. Excluded from /events/, /events/stats
    # and from /events/sources by default.
    events = [SecurityEvent(user_id=user.id, source_id=sources[src].id, source_type=src,
                            timestamp=now - timedelta(hours=h), event_type=et, severity=sev, signature=sig,
                            source_ip=sip, dest_ip=dip, dest_port=dport, protocol=proto, action=act, is_synthetic=True)
              for h, src, et, sev, sig, sip, dip, dport, proto, act in EVENTS]
    db.add_all(events)
    for s in sources.values():
        s.event_count = sum(1 for e in events if e.source_type == s.source_type)
        s.last_event_at = now
    await db.flush()

    sensors = [NetworkSensor(user_id=user.id, name=n, sensor_type=t, location=loc, network_segment=seg,
                             last_heartbeat=now, last_discovery_count=2) for n, t, loc, seg in SENSORS]
    db.add_all(sensors)
    await db.flush()
    for ip, host, vendor, model, ot_type, ot, protos, industrial, services, asset_idx in DEVICES:
        dev = DiscoveredDevice(
            user_id=user.id, sensor_id=sensors[0].id, ip_address=ip, hostname=host, manufacturer=vendor, model=model,
            ot_device_type=ot_type, is_ot_device=ot, protocols=protos, industrial_protocols=industrial,
            services_detected=services, discovery_method="sensor_report",
            asset_id=assets[asset_idx].id if asset_idx is not None else None, is_correlated=asset_idx is not None)
        dev.risk_score, dev.risk_factors = score_device(dev)
        db.add(dev)
    db.add_all([NetworkConnection(user_id=user.id, source_ip=a, target_ip=b, protocol=p, port=port, is_encrypted=enc,
                                  bytes_transferred=1_000_000) for a, b, p, port, enc in CONNECTIONS])

    # is_synthetic=True: a scripted walkthrough case, not a real triaged incident. Excluded from /cases/,
    # MITRE coverage, case search and "similar cases" by default.
    case = Case(
        user_id=user.id, severity="critical", status="investigating", confidence_score=0.91, created_by="agent",
        is_synthetic=True,
        title="Multi-Stage OT Intrusion: VPN Compromise -> Lateral Movement -> PLC Access Attempt",
        summary="Attacker brute-forced the VPN, scanned internal networks, pivoted to an engineering workstation "
                "over RDP, then attempted unauthorized Modbus/CIP writes against PLCs (blocked by the firewall).",
        attack_narrative="Initial access via VPN brute force from 203.0.113.42, followed by reconnaissance, "
                         "lateral movement, C2 beaconing, blocked PLC manipulation, and data exfiltration.",
        mitre_tactics=["TA0001", "TA0007", "TA0008", "TA0011", "TA0010", "TA0104"], mitre_techniques=TECHNIQUES,
    )
    db.add(case)
    await db.flush()
    db.add_all([CaseAlert(case_id=case.id, alert_id=a.id) for a in alerts[:2]])
    linked = [e for e in events if e.severity != "info"]
    db.add_all([CaseEvent(case_id=case.id, event_id=e.id) for e in linked])
    for e in linked:
        e.processed = "in_case"
    db.add_all([CaseTimeline(case_id=case.id, timestamp=e.timestamp, entry_type="event", source="agent",
                             content=e.signature) for e in events if e.signature])
    await db.commit()
