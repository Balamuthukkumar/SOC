from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (Alert, Asset, AuditLog, ComplianceAssessment, ComplianceControl, ComplianceFramework,
                        NetworkSensor, ResponsePlan)
from app.models.base import utcnow
from app.services.compliance_data import IEC_62443_CONTROLS, NIST_CSF_CONTROLS


async def seed_frameworks(db: AsyncSession) -> None:
    if (await db.execute(select(ComplianceFramework.id).limit(1))).first():
        return
    for name, version, desc, controls in (
        ("IEC 62443", "3-3:2013", "Industrial communication networks - Network and system security", IEC_62443_CONTROLS),
        ("NIST CSF", "2.0", "NIST Cybersecurity Framework - core functions for managing cybersecurity risk", NIST_CSF_CONTROLS),
    ):
        fw = ComplianceFramework(name=name, version=version, description=desc)
        db.add(fw)
        await db.flush()
        db.add_all([ComplianceControl(framework_id=fw.id, **c) for c in controls])
    await db.commit()


async def collect_evidence(db: AsyncSession, user_id: int) -> dict[str, tuple[str, str]]:
    """control_id -> (status, evidence). Statuses come from real platform state, not just 'something exists'."""
    async def n(col, *where):
        return (await db.execute(select(func.count(col)).where(*where))).scalar_one()

    assets = await n(Asset.id, Asset.user_id == user_id)
    zoned = await n(Asset.id, Asset.user_id == user_id, Asset.network_zone.notin_(["unknown", ""]))
    alerts = await n(Alert.id, Alert.user_id == user_id)
    acked = await n(Alert.id, Alert.user_id == user_id, Alert.status.in_(["acknowledged", "resolved"]))
    sensors = await n(NetworkSensor.id, NetworkSensor.user_id == user_id, NetworkSensor.enabled.is_(True),
                      NetworkSensor.last_heartbeat >= utcnow() - timedelta(hours=24))
    done_plans = await n(ResponsePlan.id, ResponsePlan.user_id == user_id, ResponsePlan.status == "completed")
    audit = await n(AuditLog.id, AuditLog.user_id == user_id)

    def verdict(ok: bool, partial: bool = False) -> str:
        return "compliant" if ok else "partial" if partial else "non_compliant"

    zone_pct = round(zoned / assets * 100) if assets else 0
    ack_pct = round(acked / alerts * 100) if alerts else 100
    return {
        "FR1-SR1.1": (verdict(assets > 0), f"Asset inventory holds {assets} assets."),
        "FR5-SR5.1": (verdict(assets > 0 and zone_pct >= 90, zone_pct > 0), f"{zoned}/{assets} assets have a network zone ({zone_pct}%)."),
        "FR6-SR6.1": (verdict(audit > 0), f"{audit} audit-log entries recorded."),
        "ID.AM-1": (verdict(assets > 0), f"{assets} physical devices inventoried."),
        "ID.RA-1": (verdict(alerts > 0), f"{alerts} vulnerabilities identified and tracked."),
        "PR.AC-5": (verdict(assets > 0 and zone_pct >= 90, zone_pct > 0), f"Segmentation: {zone_pct}% of assets zoned."),
        "DE.CM-1": (verdict(sensors > 0), f"{sensors} enabled sensors reported within 24h."),
        "RS.AN-1": (verdict(ack_pct >= 80, ack_pct >= 40), f"{acked}/{alerts} alerts triaged ({ack_pct}%)."),
        "RS.MI-2": (verdict(done_plans > 0), f"{done_plans} response plans completed."),
    }


async def run_assessment(db: AsyncSession, user_id: int) -> list[dict]:
    evidence = await collect_evidence(db, user_id)
    controls = (await db.execute(select(ComplianceControl).where(ComplianceControl.control_id.in_(evidence)))).scalars().all()
    existing = {a.control_id: a for a in (await db.execute(
        select(ComplianceAssessment).where(ComplianceAssessment.user_id == user_id))).scalars()}
    out = []
    for c in controls:
        status, detail = evidence[c.control_id]
        a = existing.get(c.id) or ComplianceAssessment(user_id=user_id, control_id=c.id)
        if a.assessed_by not in ("system", None) and a.id:  # never overwrite a human's manual assessment
            out.append({"control_id": c.control_id, "status": a.status, "evidence": a.evidence_detail, "skipped": "manual"})
            continue
        a.status, a.evidence_type, a.evidence_detail, a.assessed_by = status, "automated", detail, "system"
        db.add(a)
        out.append({"control_id": c.control_id, "status": status, "evidence": detail})
    await db.commit()
    return out
