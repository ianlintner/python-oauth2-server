"""Admin JSON API — user CRUD.

Ported from `crates/oauth2-actix/src/handlers/admin_extra.rs` user handlers.
Routes attach to `admin_router` (see `routes/admin/__init__.py`), which
already carries `Depends(require_admin)` as a router-level dependency; the
`actor: AdminActor = Depends(require_admin)` parameter on mutating handlers
below only exists to pull the (cached) actor identity for the audit trail.

Unlike clients, path `{id}` here IS the storage primary key (`User.id`) — no
uuid -> key resolution is needed. `PUT` silently ignores an invalid `role`
*value* (200, unchanged) while `POST .../role` rejects it with 400 — a
deliberate inconsistency pinned by the Rust test suite and preserved here;
an invalid `role` *type* (not a string at all) is still a 400, via
`UserUpdateBody` below. Several mutations return 200 even for a nonexistent
user id, because the underlying `UPDATE ... WHERE id = ?` is a silent
no-op — only `GET`, `PUT`, and `DELETE` 404.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr

from oauth2_server.models import User
from oauth2_server.routes.admin._util import _json_body, _parse_body
from oauth2_server.routes.admin.guard import AdminActor, require_admin
from oauth2_server.security import hash_password_async
from oauth2_server.services.audit import build_audit, record_audit
from oauth2_server.storage.paging import ListQuery, page_envelope

router = APIRouter()
logger = logging.getLogger(__name__)

_VALID_ROLES = {"admin", "user"}


class UserUpdateBody(BaseModel):
    """PUT /users/{id} body — all fields optional, unknown keys ignored.
    `model_fields_set` (not "is not None") is what the handler uses to tell
    "field provided" from "field defaulted", so partial updates work the
    same as they did against the raw JSON dict this replaces. Fields are
    strict-typed so e.g. `{"enabled": "yes"}` 400s instead of silently
    coercing or persisting a garbage value."""

    model_config = ConfigDict(extra="ignore")

    email: StrictStr | None = None
    role: StrictStr | None = None
    enabled: StrictBool | None = None


def _user_not_found() -> ORJSONResponse:
    return ORJSONResponse({"error": "user not found"}, status_code=404)


def _user_info(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "enabled": user.enabled,
        "created_at": user.created_at.isoformat(),
    }


def _user_response(user: User) -> dict:
    return {**_user_info(user), "updated_at": user.updated_at.isoformat()}


async def _best_effort_revoke_by_user(storage, user_id: str) -> None:
    """Mirrors the Rust `let _ = revoke_tokens_by_user_id(...)` — never lets
    a revocation failure block the response it's cascading from."""
    try:
        await storage.revoke_tokens_by_user_id(user_id)
    except Exception:
        logger.warning("failed to revoke tokens for user_id=%s", user_id, exc_info=True)


@router.get("/users")
async def list_users(
    request: Request,
    limit: int | None = None,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str = "desc",
    search: str | None = None,
) -> ORJSONResponse:
    storage = request.app.state.storage
    q = ListQuery(limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir, search=search)
    items, total = await storage.list_users_page(q)
    body = page_envelope([_user_info(u) for u in items], total, q.effective_limit(), q.offset)
    return ORJSONResponse(body)


@router.post("/users", status_code=201)
async def create_user(
    request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    body = await _json_body(request)

    username = str(body.get("username") or "").strip()
    email = str(body.get("email") or "").strip()
    password = str(body.get("password") or "")
    if not username or not email or not password:
        return ORJSONResponse(
            {
                "error": "invalid_request",
                "error_description": "username, email, password are required",
            },
            status_code=400,
        )

    if await storage.get_user_by_username(username) is not None:
        return ORJSONResponse(
            {"error": "already_exists", "error_description": "username already registered"},
            status_code=409,
        )

    role = body.get("role") if body.get("role") in _VALID_ROLES else "user"
    enabled = bool(body.get("enabled", True))
    password_hash = await hash_password_async(password)

    now = datetime.now(timezone.utc)
    user = User(
        id=uuid.uuid4().hex,
        username=username,
        email=email,
        password_hash=password_hash,
        role=role,
        enabled=enabled,
        created_at=now,
        updated_at=now,
    )
    await storage.save_user(user)

    await record_audit(
        storage,
        events,
        build_audit(request, actor, "user.create", "user", user.id, {"username": username}),
    )

    return ORJSONResponse(_user_response(user), status_code=201)


@router.get("/users/{user_id}")
async def get_user(user_id: str, request: Request) -> ORJSONResponse:
    storage = request.app.state.storage
    user = await storage.get_user_by_id(user_id)
    if user is None:
        return _user_not_found()
    return ORJSONResponse(_user_info(user))


@router.put("/users/{user_id}")
async def update_user(
    user_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    user = await storage.get_user_by_id(user_id)
    if user is None:
        return _user_not_found()

    body_model, error = await _parse_body(request, UserUpdateBody)
    if error is not None:
        return error

    fields_set = body_model.model_fields_set
    updates: dict = {}
    if "email" in fields_set:
        updates["email"] = body_model.email
    if "role" in fields_set and body_model.role in _VALID_ROLES:
        updates["role"] = body_model.role
    if "enabled" in fields_set:
        updates["enabled"] = body_model.enabled

    now = datetime.now(timezone.utc)
    updated = user.model_copy(update={**updates, "updated_at": now})
    await storage.update_user(updated)

    if updates.get("enabled") is False:
        await _best_effort_revoke_by_user(storage, user_id)

    await record_audit(
        storage,
        events,
        build_audit(request, actor, "user.update", "user", user.id, {"fields": sorted(updates)}),
    )

    return ORJSONResponse(_user_response(updated))


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    user = await storage.get_user_by_id(user_id)
    if user is None:
        return _user_not_found()

    await storage.delete_user(user_id)
    await _best_effort_revoke_by_user(storage, user_id)

    await record_audit(
        storage,
        events,
        build_audit(request, actor, "user.delete", "user", user_id, {"username": user.username}),
    )

    return ORJSONResponse({"message": "User deleted"})


@router.post("/users/{user_id}/enabled")
async def set_user_enabled(
    user_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    body = await _json_body(request)
    if not isinstance(body.get("enabled"), bool):
        return ORJSONResponse(
            {"error": "invalid_request", "error_description": "enabled must be a boolean"},
            status_code=400,
        )
    enabled = body["enabled"]

    await storage.set_user_enabled(user_id, enabled)
    if not enabled:
        await _best_effort_revoke_by_user(storage, user_id)

    await record_audit(
        storage,
        events,
        build_audit(
            request,
            actor,
            "user.enable" if enabled else "user.disable",
            "user",
            user_id,
            {"enabled": enabled},
        ),
    )

    return ORJSONResponse({"enabled": enabled})


@router.post("/users/{user_id}/role")
async def set_user_role(
    user_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    body = await _json_body(request)
    role = body.get("role")

    if role not in _VALID_ROLES:
        return ORJSONResponse(
            {"error": "invalid_request", "error_description": "role must be 'admin' or 'user'"},
            status_code=400,
        )

    await storage.set_user_role(user_id, role)

    await record_audit(
        storage,
        events,
        build_audit(request, actor, "user.set_role", "user", user_id, {"role": role}),
    )

    return ORJSONResponse({"role": role})


@router.post("/users/{user_id}/password")
async def reset_user_password(
    user_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    body = await _json_body(request)
    password = str(body.get("password") or "")

    if len(password) < 8:
        return ORJSONResponse(
            {
                "error": "weak_password",
                "error_description": "password must be at least 8 characters",
            },
            status_code=400,
        )

    password_hash = await hash_password_async(password)
    await storage.set_user_password_hash(user_id, password_hash)
    await _best_effort_revoke_by_user(storage, user_id)

    await record_audit(
        storage,
        events,
        build_audit(request, actor, "user.reset_password", "user", user_id, {}),
    )

    return ORJSONResponse({"message": "Password reset"})
