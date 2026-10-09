"""Exercise the LLM code paths with a scripted model (no network, no API key)."""
import json

import httpx
import pytest

from app.services import ai as ai_mod
from app.services.agents.base import BaseAgent
from app.services.ai import AIClient, Completion


class ScriptedAI(AIClient):
    """Returns canned JSON chosen by a keyword in the system prompt."""
    def __init__(self, replies: dict[str, object]):
        super().__init__("test", "scripted-model", "k", None)
        self.replies, self.calls = replies, []

    async def complete(self, system, user, **kw):
        self.calls.append((system[:40], user))
        for key, reply in self.replies.items():
            if key in system:
                if isinstance(reply, Exception):
                    raise reply
                text = reply if isinstance(reply, str) else json.dumps(reply)
                self.prompt_tokens += 10; self.completion_tokens += 5
                return Completion(text, self.model, 10, 5)
        raise AssertionError("unexpected prompt: " + system[:60])


def use_ai(monkeypatch, replies):
    fake = ScriptedAI(replies)
    monkeypatch.setattr("app.services.agents.base.get_ai", lambda: fake)
    return fake


async def test_detect_merges_llm_findings(client, auth, monkeypatch):
    fake = use_ai(monkeypatch, {"network security analyst": {"findings": [
        {"title": "C2 beaconing", "severity": "high", "description": "d", "affected_ips": ["10.3.1.10"]}]}})
    r = (await client.post("/api/v1/cases/pipeline", headers=auth, params={"hours_back": 168})).json()["data"]
    assert any(f["title"] == "C2 beaconing" for f in r["detect"]["findings"])
    runs = (await client.get("/api/v1/cases/agents/runs", headers=auth)).json()
    detect = next(x for x in runs if x["agent_type"] == "detect")
    assert detect["model_used"] == "scripted-model" and detect["prompt_tokens"] > 0 and fake.calls


async def test_triage_uses_llm_case_and_respects_not_incident(client, auth, monkeypatch):
    use_ai(monkeypatch, {"triage analyst": {
        "is_incident": True, "title": "LLM titled incident", "summary": "s", "severity": "critical", "confidence": 0.93,
        "attack_narrative": "n", "mitre_tactics": ["TA0001"], "mitre_techniques": [{"id": "T1133", "name": "External Remote Services", "confidence": 0.9}],
        "recommended_actions": ["Reset VPN credentials"]}})
    await client.post("/api/v1/cases/auto-triage", headers=auth, params={"hours_back": 168})
    # Built purely from the synthetic seed data, so the resulting case is synthetic too — fetch as admin.
    cases = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()["cases"]
    llm = [c for c in cases if c["title"] == "LLM titled incident"]
    assert llm and llm[0]["confidence_score"] == 0.93 and llm[0]["mitre_techniques"][0]["id"] == "T1133"
    detail = (await client.get(f"/api/v1/cases/{llm[0]['id']}", headers=auth)).json()
    assert any("Reset VPN credentials" in t["content"] for t in detail["timeline"])


async def test_triage_skips_when_llm_says_not_incident(client, auth, monkeypatch):
    use_ai(monkeypatch, {"triage analyst": {"is_incident": False}})
    params = {"include_synthetic": "true"}
    before = (await client.get("/api/v1/cases/", headers=auth, params=params)).json()["total"]
    r = (await client.post("/api/v1/cases/auto-triage", headers=auth, params={"hours_back": 168})).json()["data"]
    assert r["cases_created"] == 0 and (await client.get("/api/v1/cases/", headers=auth, params=params)).json()["total"] == before


@pytest.mark.parametrize("bad", ["this is not json", RuntimeError("API down"), "{}"[:1]])
async def test_every_agent_falls_back_when_llm_misbehaves(client, auth, monkeypatch, bad):
    use_ai(monkeypatch, {"network security analyst": bad, "triage analyst": bad, "threat hunter": bad, "incident response": bad})
    assert (await client.post("/api/v1/cases/pipeline", headers=auth, params={"hours_back": 168})).status_code == 200
    h = await client.post("/api/v1/hunt/", headers=auth, json={"hypothesis": "modbus writes"})
    assert h.status_code == 200 and any(q["row_count"] for q in h.json()["data"]["query_results"])
    cid = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()["cases"][0]["id"]
    p = await client.post("/api/v1/response-plans/generate", headers=auth, params={"case_id": cid})
    assert p.status_code == 200 and p.json()["data"]["actions"]


async def test_hunt_llm_filters_run_and_malicious_ones_are_rejected(client, auth, monkeypatch):
    use_ai(monkeypatch, {"threat hunter": {"queries": [
        {"description": "critical blocked", "filters": [{"field": "severity", "op": "eq", "value": "critical"}, {"field": "action", "op": "eq", "value": "blocked"}], "limit": 5},
        {"description": "tenant escape", "filters": [{"field": "user_id", "op": "eq", "value": 999}]},
        {"description": "injection", "filters": [{"field": "severity", "op": "eq; DROP TABLE users", "value": "x"}]}],
        "sigma_rule": "title: t", "explanation": "e"}})
    d = (await client.post("/api/v1/hunt/", headers=auth, json={"hypothesis": "blocked critical"})).json()["data"]
    ok, esc, inj = d["query_results"]
    assert ok["row_count"] == 2 and all(r["severity"] == "critical" for r in ok["rows"])
    assert "Rejected" in esc["error"] and "Rejected" in inj["error"]
    assert d["sigma_rule"] == "title: t"
    assert (await client.get("/api/v1/auth/me", headers=auth)).status_code == 200  # users table untouched


async def test_response_llm_plan_is_policy_checked(client, auth, monkeypatch):
    use_ai(monkeypatch, {"incident response": {"rationale": "contain", "actions": [
        {"action_type": "notify", "target": "soc", "reason": "r", "priority": 1},
        {"action_type": "rm_rf_everything", "target": "all", "reason": "bad", "priority": 2},
        {"action_type": "isolate_host", "target": "10.3.1.10", "reason": "c2", "priority": 3}]}})
    cid = (await client.get("/api/v1/cases/", headers=auth, params={"include_synthetic": "true"})).json()["cases"][0]["id"]
    d = (await client.post("/api/v1/response-plans/generate", headers=auth, params={"case_id": cid, "autonomy_level": "L4"})).json()["data"]
    kinds = [a["action_type"] for a in d["actions"]]
    assert kinds == ["notify", "isolate_host"]            # hallucinated action dropped
    iso = d["actions"][1]["policy_check"]
    assert iso["requires_human"] and d["status"] == "pending_approval"   # even at L4


# ---- provider wire formats -------------------------------------------------------------------
def patch_http(monkeypatch, handler):
    real = httpx.AsyncClient
    monkeypatch.setattr(ai_mod.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "transport"}))


async def test_anthropic_wire_format(monkeypatch):
    seen = {}

    def handler(req: httpx.Request):
        seen["headers"], seen["body"] = req.headers, json.loads(req.content)
        return httpx.Response(200, json={"model": "claude-sonnet-5-5", "content": [{"type": "text", "text": '```json\n{"ok": true}\n```'}],
                                         "usage": {"input_tokens": 7, "output_tokens": 3}})
    patch_http(monkeypatch, handler)
    c = AIClient("anthropic", "claude-sonnet-5-5", "sk-test", None)
    assert await c.complete_json("sys", "hello") == {"ok": True}
    assert seen["headers"]["x-api-key"] == "sk-test" and seen["headers"]["anthropic-version"]
    assert seen["body"]["model"] == "claude-sonnet-5-5" and "JSON" in seen["body"]["system"]
    assert (c.prompt_tokens, c.completion_tokens) == (7, 3)


async def test_openai_compatible_wire_format(monkeypatch):
    seen = {}

    def handler(req: httpx.Request):
        seen["url"], seen["auth"], seen["body"] = str(req.url), req.headers.get("authorization"), json.loads(req.content)
        return httpx.Response(200, json={"model": "llama3", "choices": [{"message": {"content": 'noise {"a": 1} tail'}}],
                                         "usage": {"prompt_tokens": 4, "completion_tokens": 2}})
    patch_http(monkeypatch, handler)
    c = AIClient("ollama", "llama3", None, "http://localhost:11434/v1")
    assert await c.complete_json("sys", "hi") == {"a": 1}
    assert seen["url"] == "http://localhost:11434/v1/chat/completions" and seen["auth"] is None
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]


def test_get_ai_selection(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "ai_provider", "anthropic"); monkeypatch.setattr(settings, "anthropic_api_key", None); monkeypatch.setattr(settings, "ai_api_key", None)
    assert ai_mod.get_ai() is None
    monkeypatch.setattr(settings, "anthropic_api_key", "k")
    assert ai_mod.get_ai().provider == "anthropic"
    monkeypatch.setattr(settings, "ai_provider", "openai")
    assert ai_mod.get_ai() is None                 # an Anthropic key must not be sent to another provider
    monkeypatch.setattr(settings, "ai_api_key", "sk-openai")
    c = ai_mod.get_ai()
    assert c.provider == "openai" and c.base_url == "https://api.openai.com/v1"
    monkeypatch.setattr(settings, "ai_provider", "ollama"); monkeypatch.setattr(settings, "ai_api_key", None)
    assert ai_mod.get_ai().base_url == "http://localhost:11434/v1"   # local providers need no key
