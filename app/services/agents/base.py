import logging
import time
from abc import ABC, abstractmethod

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AgentRun, AgentStep
from app.models.base import utcnow
from app.services.ai import AIClient, get_ai

log = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Runs `run()` inside an AgentRun ledger with per-step logging and token accounting."""

    agent_type = "base"

    def __init__(self, db: AsyncSession, user_id: int, ai: AIClient | None = None):
        self.db, self.user_id = db, user_id
        self.ai = ai if ai is not None else get_ai()
        self.run_record: AgentRun | None = None
        self._steps = 0

    async def execute(self, **kwargs) -> dict:
        self.run_record = AgentRun(user_id=self.user_id, agent_type=self.agent_type,
                                   model_used=self.ai.model if self.ai else "rules")
        self.db.add(self.run_record)
        await self.db.flush()
        try:
            result = await self.run(**kwargs)
        except Exception as exc:
            self.run_record.status, self.run_record.error_message = "failed", str(exc)[:500]
            self.run_record.completed_at = utcnow()
            await self.db.commit()
            log.exception("agent %s failed", self.agent_type)
            raise
        self.run_record.status, self.run_record.completed_at = "completed", utcnow()
        self.run_record.result_summary = str(result.get("summary", ""))[:500]
        if self.ai:
            self.run_record.prompt_tokens, self.run_record.completion_tokens = self.ai.prompt_tokens, self.ai.completion_tokens
        await self.db.commit()
        return result

    async def step(self, action: str, detail: str = "", started: float | None = None) -> None:
        self._steps += 1
        ms = int((time.time() - started) * 1000) if started else 0
        self.db.add(AgentStep(run_id=self.run_record.id, step_number=self._steps, action=action,
                              detail=detail[:1000], duration_ms=ms))

    async def llm_json(self, system: str, user: str) -> dict | None:
        """LLM call that degrades to None (caller uses rules) on any failure."""
        if not self.ai:
            return None
        t = time.time()
        try:
            out = await self.ai.complete_json(system, user)
            await self.step("llm_call", f"model={self.ai.model}", t)
            return out
        except Exception as exc:
            log.warning("LLM unavailable for %s: %s", self.agent_type, exc)
            await self.step("llm_failed", str(exc), t)
            return None

    @abstractmethod
    async def run(self, **kwargs) -> dict: ...
