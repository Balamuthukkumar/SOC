"""Rule-based remediation planning for OT/ICS aware alerts."""
CRITICAL_ZONES = {"control", "field", "safety_system"}
CLEARTEXT = {"modbus", "dnp3", "bacnet", "profinet", "ethercat", "profibus"}


def generate(alert, asset) -> list[dict]:
    zone = (asset.network_zone or "") if asset else ""
    protocol = ((asset.primary_protocol or "") if asset else "").lower()
    critical_zone = zone in CRITICAL_ZONES
    urgent = alert.known_exploited and alert.severity in ("critical", "high")
    steps: list[dict] = []

    def add(kind, text, downtime=None, window=False, confidence=0.9):
        steps.append({"action_type": kind, "description": text, "estimated_downtime_minutes": downtime,
                      "requires_maintenance_window": window, "priority": len(steps) + 1, "confidence": confidence})

    if urgent:
        add("urgent_containment", "Listed as actively exploited (CISA KEV): restrict network access to this asset "
            "immediately and monitor for exploitation.", 0, False, 0.95)
    if alert.remediation and critical_zone:
        add("compensating_control", f"Asset is in the {zone} zone, so patching risks process disruption. Segment/isolate "
            "it first, then patch in a maintenance window.", 0)
        add("patch", f"Schedule vendor fix in a maintenance window: {alert.remediation}", 60, True, 0.85)
    elif alert.remediation:
        add("patch", f"Apply vendor fix: {alert.remediation}", 30, False, 0.95)
    else:
        add("monitor", "No vendor fix is recorded. Track the vendor advisory and add detection for exploitation attempts.", 0, False, 0.7)
    if protocol in CLEARTEXT:
        add("network_segmentation", f"{protocol} has no authentication or encryption: allow it only from engineering "
            "workstations and wrap it in a VPN/TLS overlay where supported.", 0, False, 0.85)
    if asset is not None and asset.is_ot_asset and alert.severity in ("critical", "high"):
        add("detection", "Add IDS signatures/alerts for this CVE on the OT network sensors.", 0, False, 0.8)
    add("accept_risk", "If no mitigation is feasible, document the risk acceptance with an owner and review date.", 0, False, 1.0)
    return steps
