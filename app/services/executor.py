"""Executes approved plan actions.

Handlers are SIMULATED: they log and report success, nothing touches a firewall/EDR/IdP. Replace an entry in
HANDLERS with a real integration to make that action live.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ResponsePlan

log = logging.getLogger(__name__)


def _sim(message: str):
    async def handler(action: dict) -> tuple[bool, str]:
        target = action.get("target", "unknown")
        log.info("SIMULATED %s -> %s", action.get("action_type"), target)
        return True, message.format(target=target) + " (simulated)"
    return handler


HANDLERS = {
    "notify": _sim("Notification sent to {target}"),
    "ticket": _sim("Ticket created in {target}"),
    "block_ip": _sim("Firewall block queued for {target}"),
    "block_domain": _sim("DNS sinkhole created for {target}"),
    "disable_user": _sim("Account {target} disabled"),
    "revoke_token": _sim("Sessions revoked for {target}"),
    "isolate_host": _sim("Host {target} isolated"),
    "quarantine_vlan": _sim("VLAN {target} quarantined"),
    "rotate_secret": _sim("Credentials rotated for {target}"),
    "snapshot_logs": _sim("Log snapshot archived for {target}"),
    "preserve_pcap": _sim("PCAP capture started for {target}"),
    "disable_egress": _sim("Egress blocked for {target}"),
}


async def execute_plan(db: AsyncSession, plan: ResponsePlan) -> dict:
    plan.status = "executing"
    ordered = sorted(plan.actions or [], key=lambda a: a.get("priority", 99))
    results, failed = [], 0
    for action in ordered:
        kind, target = action.get("action_type", "unknown"), action.get("target", "unknown")
        handler = HANDLERS.get(kind)
        if not handler:
            outcome = {"status": "skipped", "detail": f"Unknown action type: {kind}"}
        else:
            try:
                ok, detail = await handler(action)
                outcome = {"status": "completed" if ok else "failed", "detail": detail}
            except Exception as exc:
                log.error("action %s failed: %s", kind, type(exc).__name__)
                outcome = {"status": "error", "detail": "Action failed"}
        failed += outcome["status"] in ("failed", "error")
        outcome |= {"action": kind, "target": target, "executed_at": datetime.now(timezone.utc).isoformat()}
        results.append(outcome)
        action["execution_result"] = outcome
    plan.actions = ordered
    plan.status = "partial" if failed else "completed"
    await db.commit()
    return {"plan_id": plan.id, "status": plan.status, "total_actions": len(ordered),
            "succeeded": sum(r["status"] == "completed" for r in results), "failed": failed, "results": results}
