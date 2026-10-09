"""OT/ICS risk scoring (0-100). Pure functions, no I/O.

Managed asset  = 0.40 * vulnerability + 0.35 * exposure + 0.25 * criticality
Discovered dev = 0.60 * exposure + 0.40 * device profile
"""
from datetime import datetime, timedelta, timezone

DEVICE_WEIGHT = {"plc": 2.0, "hmi": 1.8, "rtu": 2.0, "ied": 1.5, "scada_server": 2.5, "historian": 1.3,
                 "engineering_workstation": 1.2, "safety_system": 3.0}
ZONE_EXPOSURE = {"field": 10, "control": 25, "supervisory": 35, "safety_system": 40, "dmz": 20, "it": 15}
# 0 = no auth/encryption ... 1 = strong
PROTOCOL_SECURITY = {"modbus": 0.0, "profibus": 0.1, "dnp3": 0.2, "ethernet_ip": 0.3, "profinet": 0.4, "opc_ua": 0.7,
                     "https": 0.9, "http": 0.1, "ssh": 0.8, "telnet": 0.0}
CLEARTEXT_SERVICES = {"telnet", "ftp", "http"}
WEAK_OT_PROTOCOLS = {"modbus", "dnp3"}
CRITICALITY_FLOOR = {"low": 5, "medium": 30, "high": 70, "critical": 100}
SEVERITY_POINTS = {"critical": 25, "high": 15, "medium": 5}


def clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


def vulnerability_score(alerts: list, now: datetime | None = None) -> float:
    if not alerts:
        return 0.0
    now = now or datetime.now(timezone.utc)
    score = sum(SEVERITY_POINTS.get(a.severity, 0) for a in alerts)
    avg = sum(a.cvss_score or 0 for a in alerts) / len(alerts)
    score *= 1.2 if avg >= 9.0 else 0.8 if avg < 7.0 else 1.0
    aged = sum(1 for a in alerts if a.created_at and (a.created_at if a.created_at.tzinfo else a.created_at.replace(tzinfo=timezone.utc)) < now - timedelta(days=30))
    return clamp(score + aged * 10)


def exposure_score(asset) -> float:
    if not asset.is_ot_asset:
        return 0.0
    score = ZONE_EXPOSURE.get(asset.network_zone or "", 20)
    if asset.primary_protocol:
        score += (1 - PROTOCOL_SECURITY.get(asset.primary_protocol.lower(), 0.5)) * 30
    return clamp(score)


def criticality_score(asset) -> float:
    if not asset.is_ot_asset:
        return 0.0
    score = DEVICE_WEIGHT.get(asset.asset_type, 1.0) * 25
    return clamp(max(score, CRITICALITY_FLOOR.get(asset.criticality or "", 0)))


def score_asset(asset, alerts: list) -> tuple[float, dict]:
    v, e, c = vulnerability_score(alerts), exposure_score(asset), criticality_score(asset)
    total = clamp(0.40 * v + 0.35 * e + 0.25 * c)
    return round(total, 1), {"vulnerability": round(v, 1), "exposure": round(e, 1), "criticality": round(c, 1)}


def score_device(device) -> tuple[float, list[str]]:
    """Returns (score, risk_factors)."""
    factors: list[str] = []
    exposure = 0.0
    if device.is_ot_device:
        exposure += 15
        for svc in device.services_detected or []:
            if svc.lower() in CLEARTEXT_SERVICES:
                exposure += 15
                factors.append(f"cleartext_service:{svc.lower()}")
        for proto in device.industrial_protocols or []:
            if proto.lower() in WEAK_OT_PROTOCOLS:
                exposure += 20
                factors.append(f"unauthenticated_protocol:{proto.lower()}")
    profile = DEVICE_WEIGHT.get(device.ot_device_type or "", 2.0) * 15 if device.ot_device_type else 30.0
    if not device.is_correlated:
        factors.append("unmanaged_device")
    profile += len(factors) * 5
    return round(clamp(exposure) * 0.6 + clamp(profile) * 0.4, 1), factors
