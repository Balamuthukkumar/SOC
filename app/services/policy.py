"""Autonomy levels and approval rules for response actions."""

AUTONOMY_LEVELS = {
    "L0": {"name": "Read-only", "auto_approve": []},
    "L1": {"name": "Assisted", "auto_approve": ["notify", "ticket"]},
    "L2": {"name": "Approved actions", "auto_approve": ["notify", "ticket"]},
    "L3": {"name": "Guarded autonomy",
           "auto_approve": ["notify", "ticket", "block_ip", "block_domain", "snapshot_logs"]},
    "L4": {"name": "Crisis mode",
           "auto_approve": ["notify", "ticket", "block_ip", "block_domain", "disable_user", "revoke_token",
                            "snapshot_logs", "preserve_pcap", "disable_egress"]},
}
ALWAYS_HUMAN = {"isolate_host", "quarantine_vlan", "rotate_secret"}
CONTAINMENT = {"isolate_host", "quarantine_vlan", "disable_egress", "block_ip", "disable_user"}
OT_RESTRICTED_ZONES = {"control", "field", "safety_system"}
ACTION_TYPES = {"notify", "ticket", "block_ip", "block_domain", "disable_user", "revoke_token", "isolate_host",
                "quarantine_vlan", "rotate_secret", "snapshot_logs", "preserve_pcap", "disable_egress"}


def check_action(action_type: str, autonomy_level: str = "L1", asset_zone: str | None = None,
                 asset_is_ot: bool = False) -> dict:
    level = AUTONOMY_LEVELS.get(autonomy_level, AUTONOMY_LEVELS["L1"])
    if asset_is_ot and asset_zone in OT_RESTRICTED_ZONES and action_type in CONTAINMENT:
        return {"approved": False, "requires_human": True,
                "reason": f"OT asset in {asset_zone} zone - containment always requires human approval"}
    if action_type in ALWAYS_HUMAN:
        return {"approved": False, "requires_human": True, "reason": f"'{action_type}' always requires human approval"}
    if action_type in level["auto_approve"]:
        return {"approved": True, "requires_human": False, "reason": f"Auto-approved at {autonomy_level} ({level['name']})"}
    return {"approved": False, "requires_human": True,
            "reason": f"'{action_type}' not auto-approved at {autonomy_level}"}
