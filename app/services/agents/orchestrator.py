import logging
import time

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.agents.detect import DetectAgent
from app.services.agents.triage import TriageAgent

log = logging.getLogger(__name__)


async def run_pipeline(db: AsyncSession, user_id: int, hours_back: int = 24) -> dict:
    """Detect -> Triage. A failing stage is reported but doesn't stop the next one."""
    start = time.time()
    result: dict = {}
    for name, agent_cls in (("detect", DetectAgent), ("triage", TriageAgent)):
        try:
            result[name] = await agent_cls(db, user_id).execute(hours_back=hours_back)
        except Exception as exc:
            log.error("%s agent failed: %s", name, exc)
            result[name] = {"error": str(exc)}
    result["total_duration_ms"] = int((time.time() - start) * 1000)
    result["pipeline_status"] = "completed"
    return result
