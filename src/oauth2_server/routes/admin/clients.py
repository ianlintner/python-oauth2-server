"""Admin JSON API — OAuth client CRUD.

Ported from `crates/oauth2-actix/src/handlers/{admin,admin_extra}.rs`. Routes
are attached to `admin_router` (see `routes/admin/__init__.py`), which carries
`Depends(require_admin)` as a router-level dependency, so every handler here
is already guarded; handlers that write an audit entry additionally declare
`actor: AdminActor = Depends(require_admin)` to pull the cached actor
identity (FastAPI dependency caching means `require_admin` still only runs
once per request).

Client identity duality (see research-admin-api.md gotchas): the path `{id}`
addresses the internal `Client.id` UUID, while the storage layer keys on the
`client_id` string. Every mutation resolves `id -> client_id` by scanning
`list_all_clients()`. List/detail responses expose `grant_types`,
`redirect_uris`, `response_types`, and `contacts` as the raw JSON-encoded
strings stored in the DB (NOT parsed arrays) — only the `POST` create
response returns real arrays.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr

from oauth2_server.models import Client
from oauth2_server.routes.admin._util import _json_body, _parse_body
from oauth2_server.routes.admin.guard import AdminActor, require_admin
from oauth2_server.services.audit import build_audit, record_audit
from oauth2_server.storage.paging import ListQuery, page_envelope

router = APIRouter()
logger = logging.getLogger(__name__)

_DEFAULT_GRANT_TYPES = ["authorization_code", "refresh_token"]
_DEFAULT_AUTH_METHOD = "client_secret_basic"


class ClientUpdateBody(BaseModel):
    """PUT /clients/{id} body — all fields optional, unknown keys ignored.
    Mirrors `UserUpdateBody` (`routes/admin/users.py`): strict-typed so
    garbage (e.g. a string for `enabled`, a non-list for `redirect_uris`)
    400s instead of persisting, and `model_fields_set` distinguishes
    "provided" from "defaulted" so partial updates behave the same as the
    raw-dict version they replace."""

    model_config = ConfigDict(extra="ignore")

    name: StrictStr | None = None
    redirect_uris: list[StrictStr] | None = None
    grant_types: list[StrictStr] | None = None
    scope: StrictStr | None = None
    token_endpoint_auth_method: StrictStr | None = None
    enabled: StrictBool | None = None


def _client_not_found() -> ORJSONResponse:
    return ORJSONResponse({"error": "client not found"}, status_code=404)


async def _resolve_client(storage, client_uuid: str) -> Client | None:
    for client in await storage.list_all_clients():
        if client.id == client_uuid:
            return client
    return None


def _client_info(client: Client) -> dict:
    return {
        "id": client.id,
        "client_id": client.client_id,
        "name": client.name,
        "scope": client.scope,
        "grant_types": client.grant_types,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "redirect_uris": client.redirect_uris,
        "created_at": client.created_at.isoformat(),
    }


def _client_detail(client: Client) -> dict:
    return {
        "id": client.id,
        "client_id": client.client_id,
        "name": client.name,
        "scope": client.scope,
        "grant_types": client.grant_types,
        "redirect_uris": client.redirect_uris,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "response_types": client.response_types,
        "contacts": client.contacts,
        "logo_uri": client.logo_uri,
        "client_uri": client.client_uri,
        "policy_uri": client.policy_uri,
        "tos_uri": client.tos_uri,
        "created_at": client.created_at.isoformat(),
        "updated_at": client.updated_at.isoformat(),
    }


async def _best_effort_revoke_by_client(storage, client_id: str) -> None:
    """Mirrors the Rust `let _ = revoke_tokens_by_client_id(...)` — never
    lets a revocation failure block the enable/disable response."""
    try:
        await storage.revoke_tokens_by_client_id(client_id)
    except Exception:
        logger.warning("failed to revoke tokens for client_id=%s", client_id, exc_info=True)


@router.get("/clients")
async def list_clients(
    request: Request,
    limit: int | None = None,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str = "desc",
    search: str | None = None,
) -> ORJSONResponse:
    storage = request.app.state.storage
    q = ListQuery(limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir, search=search)
    items, total = await storage.list_clients_page(q)
    body = page_envelope([_client_info(c) for c in items], total, q.effective_limit(), q.offset)
    return ORJSONResponse(body)


@router.post("/clients", status_code=201)
async def create_client(
    request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    body = await _json_body(request)

    name = str(body.get("name") or "").strip()
    if not name:
        return ORJSONResponse(
            {"error": "invalid_request", "error_description": "name is required"},
            status_code=400,
        )

    requested_client_id = body.get("client_id")
    if requested_client_id and await storage.get_client(str(requested_client_id)) is not None:
        return ORJSONResponse(
            {"error": "already_exists", "error_description": "client_id already registered"},
            status_code=409,
        )
    client_id = requested_client_id or f"client-{uuid.uuid4().hex[:12]}"
    auth_method = body.get("token_endpoint_auth_method") or _DEFAULT_AUTH_METHOD
    is_public = auth_method == "none"
    client_secret = "" if is_public else str(body.get("client_secret") or uuid.uuid4().hex)

    redirect_uris = body["redirect_uris"] if "redirect_uris" in body else []
    grant_types = body["grant_types"] if "grant_types" in body else list(_DEFAULT_GRANT_TYPES)
    scope = body.get("scope") or ""

    now = datetime.now(timezone.utc)
    client = Client(
        id=uuid.uuid4().hex,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=json.dumps(redirect_uris),
        grant_types=json.dumps(grant_types),
        scope=scope,
        name=name,
        created_at=now,
        updated_at=now,
        token_endpoint_auth_method=auth_method,
        enabled=True,
    )
    await storage.save_client(client)

    await record_audit(
        storage,
        events,
        build_audit(
            request,
            actor,
            "client.create",
            "client",
            client.id,
            {"client_id": client_id, "name": name},
        ),
    )

    return ORJSONResponse(
        {
            "id": client.id,
            "client_id": client.client_id,
            "client_secret": None if is_public else client_secret,
            "name": client.name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "scope": scope,
            "token_endpoint_auth_method": auth_method,
            "enabled": True,
            "created_at": now.isoformat(),
        },
        status_code=201,
    )


@router.get("/clients/{client_id}")
async def get_client(client_id: str, request: Request) -> ORJSONResponse:
    storage = request.app.state.storage
    client = await _resolve_client(storage, client_id)
    if client is None:
        return _client_not_found()
    return ORJSONResponse(_client_detail(client))


@router.put("/clients/{client_id}")
async def update_client(
    client_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    client = await _resolve_client(storage, client_id)
    if client is None:
        return _client_not_found()

    body_model, error = await _parse_body(request, ClientUpdateBody)
    if error is not None:
        return error

    fields_set = body_model.model_fields_set
    updates: dict = {}
    if "name" in fields_set:
        updates["name"] = body_model.name
    if "redirect_uris" in fields_set:
        updates["redirect_uris"] = json.dumps(body_model.redirect_uris)
    if "grant_types" in fields_set:
        updates["grant_types"] = json.dumps(body_model.grant_types)
    if "scope" in fields_set:
        updates["scope"] = body_model.scope
    if "token_endpoint_auth_method" in fields_set:
        updates["token_endpoint_auth_method"] = body_model.token_endpoint_auth_method
    if "enabled" in fields_set:
        updates["enabled"] = body_model.enabled

    now = datetime.now(timezone.utc)
    updated = client.model_copy(update={**updates, "updated_at": now})
    await storage.update_client(updated)

    if updates.get("enabled") is False:
        await _best_effort_revoke_by_client(storage, client.client_id)

    await record_audit(
        storage,
        events,
        build_audit(
            request, actor, "client.update", "client", client.id, {"fields": sorted(updates)}
        ),
    )

    return ORJSONResponse(
        {
            "id": updated.id,
            "client_id": updated.client_id,
            "name": updated.name,
            "enabled": updated.enabled,
            "updated_at": now.isoformat(),
        }
    )


@router.delete("/clients/{client_id}")
async def delete_client(
    client_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    client = await _resolve_client(storage, client_id)
    if client is None:
        return _client_not_found()

    await storage.delete_client(client.client_id)

    # Deliberate divergence from Rust (which forgot to audit this handler):
    # client.delete IS audited here.
    await record_audit(
        storage,
        events,
        build_audit(
            request, actor, "client.delete", "client", client.id, {"client_id": client.client_id}
        ),
    )

    return ORJSONResponse({"message": "Client deleted"})


@router.post("/clients/{client_id}/enabled")
async def set_client_enabled(
    client_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    client = await _resolve_client(storage, client_id)
    if client is None:
        return _client_not_found()

    body = await _json_body(request)
    if not isinstance(body.get("enabled"), bool):
        return ORJSONResponse(
            {"error": "invalid_request", "error_description": "enabled must be a boolean"},
            status_code=400,
        )
    enabled = body["enabled"]

    await storage.set_client_enabled(client.client_id, enabled)
    if not enabled:
        await _best_effort_revoke_by_client(storage, client.client_id)

    await record_audit(
        storage,
        events,
        build_audit(
            request,
            actor,
            "client.enable" if enabled else "client.disable",
            "client",
            client.id,
            {"enabled": enabled},
        ),
    )

    return ORJSONResponse({"enabled": enabled})


@router.post("/clients/{client_id}/regenerate-secret")
async def regenerate_client_secret(
    client_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    client = await _resolve_client(storage, client_id)
    if client is None:
        return _client_not_found()

    if client.is_public():
        return ORJSONResponse(
            {"error": "invalid_request", "error_description": "public clients have no secret"},
            status_code=400,
        )

    new_secret = uuid.uuid4().hex
    await storage.set_client_secret(client.client_id, new_secret)

    await record_audit(
        storage,
        events,
        build_audit(request, actor, "client.regenerate_secret", "client", client.id, {}),
    )

    return ORJSONResponse({"client_id": client.client_id, "client_secret": new_secret})
