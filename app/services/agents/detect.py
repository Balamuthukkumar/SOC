from datetime import timedelta

from sqlalchemy import func, select

from app.models import SecurityEvent
from app.models.base import utcnow
from app.services.agents.base import BaseAgent

OT_PORTS = {502: "Modbus", 102: "S7comm", 44818: "EtherNet/IP", 20000: "DNP3", 4840: "OPC-UA"}

SYSTEM = """You are a network security analyst for OT/ICS environments. From aggregated event statistics,
identify likely threats. JSON: {"findings":[{"title","severity"(critical|high|medium|low),"description",
"affected_ips":[],"indicators":[],"recommended_actions":[]}]}"""


class DetectAgent(BaseAgent):
    agent_type = "detect"

    async def run(self, hours_back: int = 24) -> dict:
        cutoff = utcnow() - timedelta(hours=hours_back)
        stats = await self._stats(cutoff)
        await self.step("aggregate", f"{stats['total']} events")
        if not stats["total"]:
            return {"findings": [], "summary": "No events to analyze"}

        findings = self.rules(stats)
        await self.step("rules", f"{len(findings)} findings")
        if stats["total"] > 5 and stats["alerts"]:
            ctx = "\n".join(f"{k}: {v}" for k, v in stats.items())
            out = await self.llm_json(SYSTEM, ctx)
            if out:
                findings += out.get("findings", [])
        return {"findings": findings, "total_events_analyzed": stats["total"],
                "summary": f"Analyzed {stats['total']} events, found {len(findings)} findings"}

    async def _stats(self, cutoff) -> dict:
        E = SecurityEvent
        base = (E.user_id == self.user_id, E.timestamp >= cutoff)

        async def grouped(col, limit=20, **extra):
            q = (select(col, func.count()).where(*base, col.isnot(None)).group_by(col)
                 .order_by(func.count().desc()).limit(limit))
            return dict((await self.db.execute(q)).all())

        total = (await self.db.execute(select(func.count(E.id)).where(*base))).scalar_one()
        alerts = (await self.db.execute(select(func.count(E.id)).where(*base, E.event_type == "alert"))).scalar_one()
        return {"total": total, "alerts": alerts, "top_source_ips": await grouped(E.source_ip),
                "top_dest_ports": await grouped(E.dest_port), "severity": await grouped(E.severity),
                "top_signatures": await grouped(E.signature, 10)}

    @staticmethod
    def rules(stats: dict) -> list[dict]:
        out = []
        for ip, n in stats["top_source_ips"].items():
            if n > 50:
                out.append({"title": f"High-volume activity from {ip}", "severity": "medium",
                            "description": f"{ip} generated {n} events - possible scanning.",
                            "affected_ips": [ip], "indicators": ["high_volume"],
                            "recommended_actions": ["Investigate source IP"]})
        for port, n in stats["top_dest_ports"].items():
            if port in OT_PORTS:
                out.append({"title": f"OT protocol traffic on port {port} ({OT_PORTS[port]})",
                            "severity": "high" if n > 10 else "medium",
                            "description": f"{n} events targeting {OT_PORTS[port]}. Verify they are authorized.",
                            "affected_ips": [], "indicators": ["ot_protocol"],
                            "recommended_actions": [f"Confirm {OT_PORTS[port]} traffic comes from engineering workstations"]})
        crit, high = stats["severity"].get("critical", 0), stats["severity"].get("high", 0)
        if crit + high > 5:
            out.append({"title": f"Elevated threat level: {crit} critical + {high} high events", "severity": "high",
                        "description": "Unusual concentration of high-severity events.",
                        "affected_ips": list(stats["top_source_ips"])[:5], "indicators": ["elevated_severity"],
                        "recommended_actions": ["Run triage"]})
        return out
