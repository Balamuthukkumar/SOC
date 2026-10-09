"""TF-IDF case similarity, search, and blast radius. No external model required."""
import math
import re
from collections import Counter

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, Asset, Case, CaseAlert, CaseEvent, DiscoveredDevice, SecurityEvent

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{1,}")


def tokens(text: str) -> list[str]:
    return TOKEN_RE.findall((text or "").lower())


def case_text(c: Case) -> str:
    techs = " ".join(t["id"] + " " + t.get("name", "") if isinstance(t, dict) else str(t) for t in c.mitre_techniques or [])
    return " ".join(filter(None, [c.title, c.title, c.summary, c.attack_narrative, techs, " ".join(map(str, c.mitre_tactics or []))]))


def vectors(docs: list[list[str]]) -> list[dict[str, float]]:
    n = len(docs)
    df = Counter(t for d in docs for t in set(d))
    idf = {t: math.log((1 + n) / (1 + c)) + 1 for t, c in df.items()}
    out = []
    for d in docs:
        tf = Counter(d)
        total = sum(tf.values()) or 1
        out.append({t: (c / total) * idf[t] for t, c in tf.items()})
    return out


def cosine(a: dict[str, float], b: dict[str, float]) -> float:
    dot = sum(v * b.get(t, 0) for t, v in a.items())
    na, nb = math.sqrt(sum(v * v for v in a.values())), math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def rank(query_tokens: list[str], cases: list[Case], exclude_id: int | None = None, limit: int = 10, min_score: float = 0.05):
    pool = [c for c in cases if c.id != exclude_id]
    if not pool or not query_tokens:
        return []
    vecs = vectors([query_tokens] + [tokens(case_text(c)) for c in pool])
    scored = sorted(((cosine(vecs[0], v), c) for v, c in zip(vecs[1:], pool)), key=lambda x: -x[0])
    return [(s, c) for s, c in scored if s >= min_score][:limit]


def brief(score: float, c: Case) -> dict:
    return {"case_id": c.id, "title": c.title, "severity": c.severity, "status": c.status, "similarity": round(score, 3)}


async def user_cases(db: AsyncSession, user_id: int, include_synthetic: bool = False) -> list[Case]:
    where = [Case.user_id == user_id]
    if not include_synthetic:
        where.append(Case.is_synthetic.is_(False))
    return (await db.execute(select(Case).where(*where))).scalars().all()


async def search_cases(db, user_id: int, query: str, limit: int, include_synthetic: bool = False) -> list[dict]:
    pool = await user_cases(db, user_id, include_synthetic=include_synthetic)
    return [brief(s, c) for s, c in rank(tokens(query), pool, limit=limit)]


async def similar_cases(db, user_id: int, case_id: int, limit: int, include_synthetic: bool = False) -> list[dict] | None:
    """Looks up the target case regardless of provenance (so a case-detail page always loads), but only ever
    ranks it against real cases by default — a demo/test case is never offered as a 'similar' real incident
    unless an admin explicitly opts in with include_synthetic."""
    target = (await db.execute(select(Case).where(Case.id == case_id, Case.user_id == user_id))).scalar_one_or_none()
    if not target:
        return None
    pool = await user_cases(db, user_id, include_synthetic=include_synthetic)
    return [brief(s, c) for s, c in rank(tokens(case_text(target)), pool, exclude_id=case_id, limit=limit)]


async def blast_radius(db: AsyncSession, user_id: int, case_id: int) -> dict | None:
    case = (await db.execute(select(Case).where(Case.id == case_id, Case.user_id == user_id))).scalar_one_or_none()
    if not case:
        return None
    assets = {a.id: a for a in (await db.execute(select(Asset).join(Alert, Alert.asset_id == Asset.id)
              .join(CaseAlert, CaseAlert.alert_id == Alert.id).where(CaseAlert.case_id == case_id))).scalars()}
    events = (await db.execute(select(SecurityEvent).join(CaseEvent, CaseEvent.event_id == SecurityEvent.id)
              .where(CaseEvent.case_id == case_id))).scalars().all()
    ips = {ip for e in events for ip in (e.source_ip, e.dest_ip) if ip}
    # IPs that belong to a known asset/device are affected assets too, not just opaque addresses
    by_ip = {a.last_known_ip: a for a in (await db.execute(select(Asset).where(Asset.user_id == user_id, Asset.last_known_ip.in_(ips)))).scalars()} if ips else {}
    devices = {d.ip_address: d for d in (await db.execute(select(DiscoveredDevice).where(
        DiscoveredDevice.user_id == user_id, DiscoveredDevice.ip_address.in_(ips)))).scalars()} if ips else {}
    assets |= {a.id: a for a in by_ip.values()}

    cid = f"case-{case.id}"
    nodes = [{"id": cid, "type": "case", "label": case.title, "severity": case.severity}]
    edges = []
    for a in assets.values():
        nodes.append({"id": f"asset-{a.id}", "type": "asset", "label": a.name, "zone": a.network_zone,
                      "is_ot": a.is_ot_asset, "criticality": a.criticality})
        edges.append({"from": cid, "to": f"asset-{a.id}", "label": "affects"})
    roles: dict[str, set[str]] = {}
    for e in events:
        if e.source_ip: roles.setdefault(e.source_ip, set()).add("source")
        if e.dest_ip: roles.setdefault(e.dest_ip, set()).add("destination")
    for ip, r in sorted(roles.items()):
        d = devices.get(ip)
        nodes.append({"id": f"ip-{ip}", "type": "ip", "label": ip, "roles": sorted(r),
                      "risk_score": d.risk_score if d else None, "managed": ip in by_ip})
        edges.append({"from": cid, "to": f"ip-{ip}", "label": "/".join(sorted(r))})
        if ip in by_ip:
            edges.append({"from": f"ip-{ip}", "to": f"asset-{by_ip[ip].id}", "label": "is"})
    for t in case.mitre_techniques or []:
        tid = t["id"] if isinstance(t, dict) else str(t)
        nodes.append({"id": f"mitre-{tid}", "type": "mitre", "label": f"{tid} {t.get('name', '')}".strip() if isinstance(t, dict) else tid})
        edges.append({"from": cid, "to": f"mitre-{tid}", "label": "uses_technique"})
    count = lambda kind: sum(n["type"] == kind for n in nodes)
    return {"case_id": case.id, "nodes": nodes, "edges": edges,
            "summary": {"total_nodes": len(nodes), "assets_affected": count("asset"), "ips_involved": count("ip"),
                        "techniques_used": count("mitre"), "ot_assets_affected": sum(bool(n.get("is_ot")) for n in nodes)}}
