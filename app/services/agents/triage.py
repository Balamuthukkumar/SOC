from datetime import timedelta

from sqlalchemy import select

from app.models import Alert, Case, CaseAlert, CaseEvent, CaseTimeline, SecurityEvent
from app.models.base import utcnow
from app.services.agents.base import BaseAgent
from app.services.mitre import map_signature_to_techniques, get_technique

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
MAX_TECHNIQUES = 8

SYSTEM = """You are a triage analyst for an OT/ICS environment. Given correlated alerts and events decide whether
they form one incident. JSON: {"is_incident":bool,"title","summary","severity"(info|low|medium|high|critical),
"confidence":0-1,"attack_narrative","mitre_tactics":["TA0001"],"mitre_techniques":[{"id","name","confidence"}],
"recommended_actions":[]}"""


def correlate(alerts: list[Alert], events: list[SecurityEvent]) -> list[dict]:
    """Cluster by shared IPs (events) and by asset (alerts); merge clusters that share an IP."""
    groups: list[dict] = []
    for ev in events:
        ips = {ip for ip in (ev.source_ip, ev.dest_ip) if ip}
        hits = [g for g in groups if g["ips"] & ips]
        if not hits:
            groups.append({"alerts": [], "events": [ev], "ips": set(ips)})
            continue
        head = hits[0]
        head["events"].append(ev)
        head["ips"] |= ips
        for other in hits[1:]:
            head["events"] += other["events"]
            head["ips"] |= other["ips"]
            groups.remove(other)
    by_asset: dict[int, list[Alert]] = {}
    for a in alerts:
        by_asset.setdefault(a.asset_id, []).append(a)
    groups += [{"alerts": al, "events": [], "ips": set()} for al in by_asset.values()]
    return [g for g in groups if g["alerts"] or any(e.severity != "info" for e in g["events"])]


def rule_fallback(alerts: list[Alert], events: list[SecurityEvent]) -> dict:
    """Deterministic triage used when no LLM is available.

    Title names the most severe finding; techniques are ranked by how many distinct events support them, and
    confidence grows with that support (so one stray keyword never outranks a repeated pattern).
    """
    sevs = [a.severity for a in alerts] + [e.severity for e in events]
    top = next((s for s in SEVERITY_ORDER if s in sevs), "info")
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    worst = min((e for e in events if e.signature), key=lambda e: (rank.get(e.severity, 9), e.timestamp), default=None)
    ips = {ip for e in events for ip in (e.source_ip, e.dest_ip) if ip}
    if alerts and (not worst or rank.get(alerts[0].severity, 9) <= rank.get(worst.severity, 9)):
        title = alerts[0].title
    elif worst:
        extra = len(events) - 1
        title = worst.signature + (f" (+{extra} related events across {len(ips)} hosts)" if extra else "")
    else:
        title = f"{events[0].event_type} activity" if events else "Untitled investigation"

    support: dict[str, int] = {}
    for e in events:
        for t in {t["id"] for t in map_signature_to_techniques(f"{e.signature or ''} {e.category or ''}")}:
            support[t] = support.get(t, 0) + 1
    ranked = sorted(support.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_TECHNIQUES]
    techniques = [{"id": t, "name": (get_technique(t) or {}).get("name", t), "confidence": round(min(0.9, 0.4 + 0.15 * n), 2)}
                  for t, n in ranked]
    tactics = sorted({tac for t in techniques for tac in (get_technique(t["id"]) or {}).get("tactics", [])})
    confidence = round(min(0.85, 0.35 + 0.05 * len(events)), 2) if events else 0.4
    return {"is_incident": True, "title": title[:200],
            "summary": f"Correlated {len(alerts)} alerts and {len(events)} events across {len(ips)} hosts. Manual review recommended.",
            "severity": top, "confidence": confidence, "mitre_tactics": tactics, "mitre_techniques": techniques,
            "attack_narrative": f"Automated correlation of {len(alerts)} alerts and {len(events)} events"
                                + (f"; most severe: {worst.signature}." if worst else "."),
            "recommended_actions": ["Review correlated events", "Assess affected assets"]}


class TriageAgent(BaseAgent):
    agent_type = "triage"

    async def run(self, hours_back: int = 24) -> dict:
        cutoff = utcnow() - timedelta(hours=hours_back)
        linked = select(CaseAlert.alert_id)
        alerts = (await self.db.execute(select(Alert).where(
            Alert.user_id == self.user_id, Alert.created_at >= cutoff, Alert.id.not_in(linked))
            .order_by(Alert.created_at.desc()).limit(100))).scalars().all()
        events = (await self.db.execute(select(SecurityEvent).where(
            SecurityEvent.user_id == self.user_id, SecurityEvent.timestamp >= cutoff,
            SecurityEvent.processed == "pending").order_by(SecurityEvent.timestamp.desc()).limit(500))).scalars().all()
        await self.step("gather", f"{len(alerts)} alerts, {len(events)} events")
        groups = correlate(alerts, events)
        await self.step("correlate", f"{len(groups)} clusters")

        created = n_alerts = n_events = 0
        for g in groups:
            if await self.make_case(g["alerts"], g["events"]):
                created += 1
                n_alerts += len(g["alerts"])
                n_events += len(g["events"])
        await self.db.flush()
        return {"cases_created": created, "alerts_triaged": n_alerts, "events_triaged": n_events,
                "summary": f"Created {created} cases from {n_alerts} alerts and {n_events} events"}

    @staticmethod
    def context(alerts, events) -> str:
        lines = [f"ALERT [{a.severity}] {a.title} cve={a.cve_id} cvss={a.cvss_score}" for a in alerts[:20]]
        lines += [f"EVENT [{e.severity}] {e.event_type} {e.source_ip}->{e.dest_ip}:{e.dest_port} sig={e.signature}"
                  for e in events[:50]]
        return "\n".join(lines)

    async def make_case(self, alerts, events) -> Case | None:
        data = await self.llm_json(SYSTEM, self.context(alerts, events)) or rule_fallback(alerts, events)
        if not data.get("is_incident", True):
            return None
        # A case is demo/test-only when every piece of evidence behind it is. One piece of real evidence is
        # enough to treat the whole case as real, since that's where the genuine risk sits.
        evidence = list(alerts) + list(events)
        synthetic = bool(evidence) and all(getattr(x, "is_synthetic", False) for x in evidence)
        case = Case(user_id=self.user_id, title=data.get("title", "Untitled investigation")[:200],
                    summary=data.get("summary"), severity=data.get("severity", "medium"),
                    confidence_score=data.get("confidence", 0.5), mitre_tactics=data.get("mitre_tactics"),
                    mitre_techniques=data.get("mitre_techniques"), attack_narrative=data.get("attack_narrative"),
                    created_by="agent", is_synthetic=synthetic)
        self.db.add(case)
        await self.db.flush()
        self.db.add_all([CaseAlert(case_id=case.id, alert_id=a.id) for a in alerts])
        for e in events:
            self.db.add(CaseEvent(case_id=case.id, event_id=e.id))
            e.processed = "in_case"
        self.db.add(CaseTimeline(case_id=case.id, entry_type="ai_analysis", source="agent",
                                 content=data.get("attack_narrative") or data.get("summary") or ""))
        self.db.add_all([CaseTimeline(case_id=case.id, entry_type="action", source="agent",
                                      content=f"Recommended: {a}") for a in data.get("recommended_actions", [])])
        await self.step("create_case", f"{case.title} ({case.severity})")
        return case
