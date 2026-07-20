"""GET /metrics, /health, /ready — unauthenticated observability endpoints.

Ported from `crates/oauth2-actix/src/handlers/admin.rs` (`system_metrics`,
`health`, `readiness`; see `.superpowers/sdd/research-events-observability.md`
`endpoints`). Mounted at the application root with NO prefix in `create_app`
(`app.py`) — this is deliberately a different module from `/admin/metrics`
(behind `AdminGuard`, in `routes/admin/dashboard.py`), which serves the admin
dashboard SPA HTML, not Prometheus exposition text (research doc gotchas: "do
not confuse the two when porting routes").
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response
from fastapi.responses import ORJSONResponse
from prometheus_client import generate_latest

from oauth2_server.services.metrics import CONTENT_TYPE

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/metrics")
async def metrics(request: Request) -> Response:
    body = generate_latest(request.app.state.metrics.registry)
    # Content-type is EXACTLY "text/plain; version=0.0.4" — no charset
    # (research doc gotchas, divergence 22); `generate_latest`'s bytes are
    # reused as-is. The `Content-Type` header must be passed explicitly
    # (not just `media_type=`) — Starlette's `Response.init_headers` auto-
    # appends "; charset=utf-8" to any `text/*` media_type unless a
    # `content-type` header is already present in `headers=`.
    return Response(content=body, media_type=CONTENT_TYPE, headers={"content-type": CONTENT_TYPE})


@router.get("/health")
async def health() -> ORJSONResponse:
    # Always 200 — no dependency checks (that's /ready's job).
    return ORJSONResponse(
        {
            "status": "healthy",
            "service": "oauth2_server",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


@router.get("/ready")
async def ready(request: Request) -> Response:
    storage = request.app.state.storage
    try:
        await storage.healthcheck()
    except Exception:
        # Deliberate divergence from Rust parity (previously: plain-text body
        # containing `str(exc)`, per research doc gotchas "/ready failure
        # body is plain error text with 503 ... not the JSON {status,checks}
        # shape"). The raw exception text can carry a DB connection string,
        # credentials, or internal hostnames (e.g. an asyncpg DSN in the
        # error message) — leaking that to any unauthenticated caller that
        # can reach `/ready` is a real disclosure risk, not just cosmetic.
        # Log the detail server-side and return a generic body instead.
        logger.warning("readiness check failed", exc_info=True)
        return ORJSONResponse(
            {"status": "unavailable", "checks": {"database": "error"}}, status_code=503
        )
    return ORJSONResponse({"status": "ready", "checks": {"database": "ok"}})
