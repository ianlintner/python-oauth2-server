"""POST /events/ingest, GET /events/health — Phase 3c Task 3.

Ported from `crates/oauth2-actix/src/handlers/events.rs` (`ingest`, `health`;
see `.superpowers/sdd/research-events-observability.md`, `endpoints`). Not to
be confused with `routes/admin/events.py`'s `GET /admin/api/events/recent`
(AdminGuard-protected recent-events feed reading the same `app.state.events`
`RecentEventsStore`, but no relation to the event BUS wired here).
"""

from __future__ import annotations

import hmac
import logging

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse
from pydantic import ValidationError

from oauth2_server.services.events_bus import EventEnvelope

logger = logging.getLogger(__name__)

router = APIRouter()


def _extract_bearer(header: str | None) -> str | None:
    if not header or not header.lower().startswith("bearer "):
        return None
    token = header[len("Bearer ") :].strip()
    return token or None


def _unauthorized() -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_token", "error_description": "Missing or invalid bearer token"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _bearer_matches(presented: str, expected: str) -> bool:
    """Constant-time compare, safe for a non-ASCII bearer token.

    ``hmac.compare_digest`` raises ``TypeError`` ("comparing strings with
    non-ASCII characters is not supported") when either ``str`` operand
    contains a non-ASCII character, instead of returning ``False``. A raw
    HTTP client can legally send obs-text (RFC 7230 §3.2.6) in the
    Authorization header, and Starlette's ``Headers.get`` hands it back as
    a ``str`` already latin-1-decoded from the raw ASGI bytes (see
    ``starlette.datastructures.Headers``) — so ``presented.encode("latin-1")``
    round-trips losslessly back to the exact bytes the client sent. Compare
    on those bytes instead, which ``compare_digest`` fully supports, so a
    non-ASCII bearer token falls through to the normal 401 ``invalid_token``
    path rather than an unhandled 500.
    """
    return hmac.compare_digest(presented.encode("latin-1"), expected.encode("utf-8"))


@router.post("/ingest")
async def ingest(request: Request) -> ORJSONResponse:
    config = request.app.state.config

    # --- Auth guard first (Rust parity ordering, research doc `endpoints`):
    # a misconfigured deployment (auth required but no bearer token set)
    # fails CLOSED with 503 regardless of whether eventing itself is
    # enabled; only once auth passes (or is deliberately public) do we look
    # at whether there's an event bus to publish to. ---
    if not config.events_public_ingest:
        expected = config.events_ingest_bearer_token
        if not expected:
            return ORJSONResponse({"error": "event_ingest_auth_not_configured"}, status_code=503)
        presented = _extract_bearer(request.headers.get("authorization"))
        if presented is None or not _bearer_matches(presented, expected):
            return _unauthorized()

    event_bus = request.app.state.event_bus
    if event_bus is None:
        return ORJSONResponse({"error": "eventing_disabled"}, status_code=503)

    try:
        body = await request.json()
    except ValueError:
        return ORJSONResponse({"error": "invalid_request"}, status_code=400)

    try:
        envelope = EventEnvelope.model_validate(body)
    except ValidationError:
        return ORJSONResponse({"error": "invalid_request"}, status_code=400)

    # `Idempotency-Key` header (trimmed, non-empty) overrides any
    # `idempotency_key` already inside the envelope body; falling back to
    # `effective_idempotency_key()` (explicit envelope key, else event.id).
    header_key = (request.headers.get("idempotency-key") or "").strip()
    idempotency_key = header_key or envelope.effective_idempotency_key()

    idempotency_store = request.app.state.event_idempotency
    if await idempotency_store.is_duplicate_and_record(idempotency_key):
        return ORJSONResponse(
            {
                "status": "duplicate",
                "idempotency_key": idempotency_key,
                "event_id": envelope.event.id,
            },
            status_code=202,
        )

    # Non-duplicate: push into the admin recent-events ring THEN publish to
    # the bus (Rust parity, research doc gotchas: "the envelope is pushed to
    # RecentEventsStore only on the non-duplicate path").
    request.app.state.events.push(envelope.model_dump(mode="json"))
    event_bus.publish_best_effort(envelope)

    return ORJSONResponse(
        {
            "status": "accepted",
            "idempotency_key": idempotency_key,
            "event_id": envelope.event.id,
        },
        status_code=202,
    )


@router.get("/health")
async def health(request: Request) -> ORJSONResponse:
    event_bus = request.app.state.event_bus
    if event_bus is None:
        return ORJSONResponse({"enabled": False, "plugins": []})
    plugins = await event_bus.health()
    return ORJSONResponse({"enabled": True, "plugins": plugins})
