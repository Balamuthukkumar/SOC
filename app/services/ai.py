"""LLM access: Anthropic or any OpenAI-compatible endpoint (OpenAI, Ollama, vLLM, Groq...).

`get_ai()` returns None when no credentials are configured, so callers fall back to rules.
"""
import json
import logging
import re
from dataclasses import dataclass

import httpx

from app.config import settings

log = logging.getLogger(__name__)

OPENAI_COMPAT_URLS = {
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "together": "https://api.together.xyz/v1",
    "ollama": "http://localhost:11434/v1",
    "vllm": "http://localhost:8000/v1",
}
LOCAL_PROVIDERS = {"ollama", "vllm"}


@dataclass
class Completion:
    text: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class AIClient:
    def __init__(self, provider: str, model: str, api_key: str | None, base_url: str | None):
        self.provider, self.model, self.api_key, self.base_url = provider, model, api_key, base_url
        self.prompt_tokens = self.completion_tokens = 0

    async def complete(self, system: str, user: str, *, temperature: float = 0.2, max_tokens: int = 4096) -> Completion:
        async with httpx.AsyncClient(timeout=120) as http:
            if self.provider == "anthropic":
                r = await http.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                    json={"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                          "system": system, "messages": [{"role": "user", "content": user}]})
                r.raise_for_status()
                d = r.json()
                text = "".join(b["text"] for b in d["content"] if b["type"] == "text")
                usage = d.get("usage", {})
                out = Completion(text, d.get("model", self.model), usage.get("input_tokens", 0), usage.get("output_tokens", 0))
            else:
                headers = {"authorization": f"Bearer {self.api_key}"} if self.api_key else {}
                r = await http.post(
                    f"{self.base_url}/chat/completions", headers=headers,
                    json={"model": self.model, "temperature": temperature, "max_tokens": max_tokens,
                          "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
                r.raise_for_status()
                d = r.json()
                usage = d.get("usage", {})
                out = Completion(d["choices"][0]["message"]["content"], d.get("model", self.model),
                                 usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0))
        self.prompt_tokens += out.prompt_tokens
        self.completion_tokens += out.completion_tokens
        return out

    async def complete_json(self, system: str, user: str, **kw) -> dict:
        out = await self.complete(system + "\n\nRespond with a single JSON object only.", user, **kw)
        return parse_json(out.text)


def parse_json(text: str) -> dict:
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(text[start:end + 1])


def get_ai() -> AIClient | None:
    provider = settings.ai_provider
    key = settings.ai_api_key or (settings.anthropic_api_key if provider == "anthropic" else None)
    if provider == "anthropic":
        return AIClient(provider, settings.ai_default_model, key, None) if key else None
    if not key and provider not in LOCAL_PROVIDERS:
        return None
    base = settings.ai_base_url or OPENAI_COMPAT_URLS.get(provider, OPENAI_COMPAT_URLS["ollama"])
    return AIClient(provider, settings.ai_default_model, key, base)
