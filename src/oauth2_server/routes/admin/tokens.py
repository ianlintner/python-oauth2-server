"""Admin JSON API — token listing, detail, revoke, bulk revoke.

Ported from `crates/oauth2-actix/src/handlers/admin.rs` (list/detail) and
`admin_extra.rs` (revoke-by-user/revoke-by-client). Routes attach to
`admin_router` (see `routes/admin/__init__.py`), which already carries
`Depends(require_admin)` as a router-level dependency.

Deliberate divergence from Rust (see research-admin-api.md gotchas): the
Rust `POST /admin/api/tokens/{id}/revoke` feeds the path `id` straight into
`storage.revoke_token`, whose SQL matches on the token VALUE (access_token OR
refresh_token) — since `id` is the separate row uuid, that's a silent no-op
that still returns 200. This port resolves the row by `id` first (via
`storage.get_token_by_id`, a direct `WHERE id = :id` lookup — not the
`list_all_tokens` newest-200 scan used by `list`, which would silently miss
older rows) and revokes the actual `access_token` value, so the endpoint
actually works. An unknown `id` is still a no-op that returns 200, matching
the "no 404" contract — and, since nothing resolved, no `token.revoke`
audit entry is written either (divergence 12: single-target revoke is now
audited uniformly with the other single-target mutations, but only when the
row actually existed).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.models import Token
from oauth2_server.routes.admin._util import _json_body
from oauth2_server.routes.admin.guard import AdminActor, require_admin
from oauth2_server.services.audit import build_audit, record_audit
from oauth2_server.storage.paging import ListQuery, page_envelope

router = APIRouter()


def _token_not_found() -> ORJSONResponse:
    return ORJSONResponse({"error": "token not found"}, status_code=404)


def _token_info(token: Token) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "id": token.id,
        "client_id": token.client_id,
        "user_id": token.user_id or "",
        "scope": token.scope,
        "expires_at": token.expires_at.isoformat(),
        "created_at": token.created_at.isoformat(),
        "revoked": token.revoked,
        "expired": not token.revoked and token.expires_at <= now,
    }


@router.get("/tokens")
async def list_tokens(
    request: Request,
    limit: int | None = None,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str = "desc",
    search: str | None = None,
    status: str | None = None,
) -> ORJSONResponse:
    storage = request.app.state.storage
    q = ListQuery(
        limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir, search=search, status=status
    )
    items, total = await storage.list_tokens_page(q)
    body = page_envelope([_token_info(t) for t in items], total, q.effective_limit(), q.offset)
    return ORJSONResponse(body)


@router.get("/tokens/{token_id}")
async def get_token(token_id: str, request: Request) -> ORJSONResponse:
    storage = request.app.state.storage
    token = await storage.get_token_by_id(token_id)
    if token is None:
        return _token_not_found()
    return ORJSONResponse(_token_info(token))


@router.post("/tokens/{token_id}/revoke")
async def revoke_token_by_id(
    token_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    token = await storage.get_token_by_id(token_id)
    if token is not None:
        await storage.revoke_token(token.access_token)
        request.app.state.metrics.oauth_token_revoked_total.inc()
        await record_audit(
            storage,
            events,
            build_audit(request, actor, "token.revoke", "token", token.id, {}),
        )
    return ORJSONResponse({"message": "Token revoked"})


@router.post("/tokens/revoke-by-user")
async def revoke_tokens_by_user(
    request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    body = await _json_body(request)
    user_id = str(body.get("user_id") or "")

    count = await storage.revoke_tokens_by_user_id(user_id)

    await record_audit(
        storage,
        events,
        build_audit(
            request, actor, "token.bulk_revoke_by_user", "user", user_id, {"revoked": count}
        ),
    )

    return ORJSONResponse({"revoked": count})


@router.post("/tokens/revoke-by-client")
async def revoke_tokens_by_client(
    request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    body = await _json_body(request)
    client_id = str(body.get("client_id") or "")

    count = await storage.revoke_tokens_by_client_id(client_id)

    await record_audit(
        storage,
        events,
        build_audit(
            request, actor, "token.bulk_revoke_by_client", "client", client_id, {"revoked": count}
        ),
    )

    return ORJSONResponse({"revoked": count})
