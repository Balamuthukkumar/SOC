from sqlalchemy import select

from app.models import Alert, ApprovalRequest, Asset, Case, CaseAlert, ResponsePlan
from app.services.agents.base import BaseAgent
from app.services.policy import ACTION_TYPES, check_action

SYSTEM = """You are an incident response specialist for an OT/ICS environment. Produce an ordered response plan.
Action types: notify, ticket, block_ip, block_domain, disable_user, revoke_token, isolate_host, quarantine_vlan,
rotate_secret, snapshot_logs, preserve_pcap, disable_egress. Containment first, then investigation, then cleanup.
Prefer network segmentation over host actions on OT assets. Always start with notify and include snapshot_logs.
JSON: {"actions":[{"action_type","target","reason","priority"}],"rationale":""}"""


def fallback_plan(case: Case) -> dict:
    actions = [{"action_type": "notify", "target": "incident-response-team", "reason": f"New case: {case.title}", "priority": 1},
               {"action_type": "snapshot_logs", "target": "affected-assets", "reason": "Preserve evidence", "priority": 2}]
    if case.severity in ("critical", "high"):
        actions.append({"action_type": "block_ip", "target": "suspicious-source",
                        "reason": "High-severity case - contain suspected attacker", "priority": 3})
    return {"actions": actions, "rationale": "Rule-based plan (no LLM configured)."}


class ResponseAgent(BaseAgent):
    agent_type = "response"

    async def run(self, case_id: int, autonomy_level: str = "L1") -> dict:
        case = (await self.db.execute(select(Case).where(Case.id == case_id, Case.user_id == self.user_id))).scalar_one_or_none()
        if not case:
            raise LookupError("Case not found")
        assets = (await self.db.execute(
            select(Asset).join(Alert, Alert.asset_id == Asset.id).join(CaseAlert, CaseAlert.alert_id == Alert.id)
            .where(CaseAlert.case_id == case_id).distinct())).scalars().all()
        context = f"Case: {case.title}\nSeverity: {case.severity}\nSummary: {case.summary}\nTactics: {case.mitre_tactics}\n" + \
            "\n".join(f"Asset {a.name} type={a.asset_type} zone={a.network_zone} OT={a.is_ot_asset}" for a in assets)
        plan = await self.llm_json(SYSTEM, context) or fallback_plan(case)

        ot_zone = next((a.network_zone for a in assets if a.is_ot_asset), None)
        actions, needs_human = [], False
        for raw in plan.get("actions", []):
            if raw.get("action_type") not in ACTION_TYPES:
                continue
            check = check_action(raw["action_type"], autonomy_level, ot_zone, bool(ot_zone))
            needs_human |= check["requires_human"]
            actions.append({**raw, "policy_check": check})
        status = "pending_approval" if needs_human else "approved"
        record = ResponsePlan(case_id=case_id, user_id=self.user_id, actions=actions, status=status,
                              autonomy_level=autonomy_level, rationale=plan.get("rationale"))
        self.db.add(record)
        await self.db.flush()
        if needs_human:
            self.db.add(ApprovalRequest(plan_id=record.id, reason=plan.get("rationale") or "Actions require human review"))
        await self.step("create_plan", f"plan {record.id}: {len(actions)} actions, {status}")
        return {"plan_id": record.id, "status": status, "actions": actions, "needs_approval": needs_human,
                "summary": f"Plan with {len(actions)} actions ({'approval required' if needs_human else 'auto-approved'})"}
