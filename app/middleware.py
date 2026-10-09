import time
import uuid
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

METRICS: dict[str, float] = defaultdict(float)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Adds X-Request-ID and records basic request metrics."""

    async def dispatch(self, request: Request, call_next):
        request.state.request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        response.headers["X-Request-ID"] = request.state.request_id
        METRICS["requests_total"] += 1
        METRICS["request_seconds_total"] += elapsed
        METRICS[f"status_{response.status_code // 100}xx"] += 1
        return response
