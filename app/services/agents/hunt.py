"""Hunt agent: hypothesis -> structured event filters -> read-only query.

The LLM never writes SQL. It returns filter objects that are validated against a column whitelist and compiled
with SQLAlchemy, always scoped to the caller's user_id.
"""
import re

from fastapi.encoders import jsonable_encoder
from sqlalchemy import select

from app.models import SecurityEvent
from app.services.agents.base import BaseAgent

E = SecurityEvent
COLUMNS = {n: getattr(E, n) for n in (
    "id", "timestamp", "event_type", "severity", "signature", "signature_id", "category", "source_ip", "source_port",
    "dest_ip", "dest_port", "protocol", "action", "hostname", "username", "domain", "url", "user_agent",
    "bytes_in", "bytes_out", "source_type", "processed", "is_synthetic")}
# is_synthetic always included so a hunt result is never mistaken for a real finding — hunt itself does not
# filter synthetic rows out (an analyst may deliberately want to see test data they just ingested).
DEFAULT_COLUMNS = ["id", "timestamp", "event_type", "severity", "source_ip", "dest_ip", "dest_port", "signature",
                   "is_synthetic"]
TEXT_COLUMNS = {"signature", "category", "hostname", "username", "domain", "url", "user_agent"}
OPS = {"eq", "ne", "like", "in", "gte", "lte"}
MAX_QUERIES, MAX_ROWS = 3, 100

PROTOCOL_PORTS = {"modbus": [502], "s7": [102], "s7comm": [102], "ethernet/ip": [44818], "cip": [44818],
                  "dnp3": [20000], "opc": [4840], "rdp": [3389], "smb": [445], "ssh": [22], "dns": [53]}
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
STOPWORDS = {"the", "a", "an", "to", "from", "of", "and", "or", "in", "on", "for", "with", "is", "are", "was", "any",
             "that", "this", "show", "find", "look", "events", "traffic", "activity", "suspicious", "possible"}

SYSTEM = f"""You are a threat hunter for an OT/ICS platform. Turn the hypothesis into up to {MAX_QUERIES} event
filters over these columns: {', '.join(COLUMNS)}. Ops: eq, ne, like (use %), in (list), gte, lte.
JSON: {{"queries":[{{"description","columns":[],"filters":[{{"field","op","value"}}],"order_by":"timestamp",
"order":"desc","limit":50}}],"sigma_rule":"optional Sigma YAML","explanation":""}}"""


def fallback_queries(hypothesis: str) -> dict:
    text = hypothesis.lower()
    queries = []
    for ip in IP_RE.findall(text)[:2]:
        for field in ("source_ip", "dest_ip"):
            queries.append({"description": f"Events with {field} {ip}", "filters": [{"field": field, "op": "eq", "value": ip}]})
    ports = sorted({p for k, ps in PROTOCOL_PORTS.items() if k in text for p in ps})
    if ports:
        queries.append({"description": f"Traffic to ports {ports}", "filters": [{"field": "dest_port", "op": "in", "value": ports}]})
    words = [w for w in re.findall(r"[a-z0-9_.-]{3,}", text) if w not in STOPWORDS and not IP_RE.fullmatch(w)][:3]
    for w in words:
        queries.append({"description": f"Signature/category/domain mentioning '{w}'", "any_text": f"%{w}%"})
    return {"queries": queries[:MAX_QUERIES] or [{"description": "Most severe recent events",
            "filters": [{"field": "severity", "op": "in", "value": ["critical", "high"]}]}],
            "explanation": "Keyword-based hunt (no LLM configured)."}


def build_query(user_id: int, q: dict):
    cols = [c for c in q.get("columns") or [] if c in COLUMNS] or DEFAULT_COLUMNS
    stmt = select(*[COLUMNS[c].label(c) for c in cols]).where(E.user_id == user_id)
    for f in q.get("filters") or []:
        field, op, value = f.get("field"), f.get("op"), f.get("value")
        if field not in COLUMNS or op not in OPS:
            raise ValueError(f"Rejected filter: {field!r} {op!r}")
        col = COLUMNS[field]
        if op == "eq": stmt = stmt.where(col == value)
        elif op == "ne": stmt = stmt.where(col != value)
        elif op == "gte": stmt = stmt.where(col >= value)
        elif op == "lte": stmt = stmt.where(col <= value)
        elif op == "in":
            if not isinstance(value, list): raise ValueError("'in' needs a list")
            stmt = stmt.where(col.in_(value[:50]))
        elif op == "like":
            if field not in TEXT_COLUMNS: raise ValueError(f"'like' not allowed on {field}")
            stmt = stmt.where(col.ilike(str(value)))
    if q.get("any_text"):
        stmt = stmt.where(E.signature.ilike(q["any_text"]) | E.category.ilike(q["any_text"])
                                     | E.domain.ilike(q["any_text"]) | E.hostname.ilike(q["any_text"]))
    order = COLUMNS.get(q.get("order_by"), E.timestamp)
    stmt = stmt.order_by(order.asc() if q.get("order") == "asc" else order.desc())
    try:
        limit = max(1, min(int(q.get("limit", MAX_ROWS)), MAX_ROWS))
    except (TypeError, ValueError):
        limit = MAX_ROWS
    return stmt.limit(limit)


class HuntAgent(BaseAgent):
    agent_type = "hunt"

    async def run(self, hypothesis: str = "") -> dict:
        if not hypothesis.strip():
            raise ValueError("A hunting hypothesis is required")
        plan = await self.llm_json(SYSTEM, f"Hypothesis: {hypothesis}")
        if not plan or not plan.get("queries"):
            plan = fallback_queries(hypothesis)
            await self.step("fallback_queries", plan["explanation"])
        results = []
        for q in plan["queries"][:MAX_QUERIES]:
            try:
                rows = jsonable_encoder([dict(r._mapping) for r in (await self.db.execute(build_query(self.user_id, q))).all()])
                results.append({"query": q, "rows": rows, "row_count": len(rows)})
                await self.step("execute_query", f"{q.get('description', '')}: {len(rows)} rows")
            except Exception as exc:
                results.append({"query": q, "rows": [], "row_count": 0, "error": str(exc)})
                await self.step("query_rejected", str(exc))
        return {"hypothesis": hypothesis, "query_results": results, "sigma_rule": plan.get("sigma_rule"),
                "explanation": plan.get("explanation"),
                "summary": f"Executed {len(results)} queries for: {hypothesis}"[:200]}
