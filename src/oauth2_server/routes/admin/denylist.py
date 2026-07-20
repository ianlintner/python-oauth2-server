"""Admin JSON API — subject denylist CRUD.

Ported from `crates/oauth2-actix/src/handlers/admin_extra.rs` denylist
handlers. Routes attach to `admin_router` (see `routes/admin/__init__.py`),
which already carries `Depends(require_admin)` as a router-level dependency;
the `actor: AdminActor = Depends(require_admin)` parameter on mutating
handlers below only exists to pull the (cached) actor identity for the audit
trail.

This module only manages the denylist *table* (kind/value/reason/expiry).
Enforcement of the `"ip"` kind lives in `middleware.py::DenylistGuard`,
mounted globally in `create_app`; the other four kinds are stored and
listable here but not enforced anywhere (see `middleware.py` docstring).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.models import DenylistEntry
from oauth2_server.routes.admin._util import _json_body
from oauth2_server.routes.admin.guard import AdminActor, require_admin
from oauth2_server.services.audit import build_audit, record_audit
from oauth2_server.storage.paging import ListQuery, page_envelope

router = APIRouter()

# Rust `DENYLIST_KIND_*` constants (oauth2-core) — the closed set of kinds
# POST /admin/api/denylist accepts.
_VALID_KINDS = ("ip", "user_id", "username", "email", "client_id")


def _invalid_request(message: str) -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_request", "error_description": message}, status_code=400
    )


def _denylist_response(entry: DenylistEntry) -> dict:
    return {
        "id": entry.id,
        "kind": entry.kind,
        "value": entry.value,
        "reason": entry.reason,
        "created_by": entry.created_by,
        "created_at": entry.created_at.isoformat(),
        "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
        "active": entry.is_active(),
    }


def _parse_expires_at(raw: object) -> tuple[datetime | None, bool]:
    """Parses an optional RFC3339 `expires_at` into a tz-aware datetime.

    Returns `(value, ok)`; `ok=False` means `raw` was present (a non-blank
    string) but not a valid RFC3339 datetime. A naive result (no offset in
    the input) is assumed UTC.
    """
    if raw is None:
        return None, True
    if not isinstance(raw, str) or not raw.strip():
        return None, True
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None, False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed, True


@router.get("/denylist")
async def list_denylist(
    request: Request,
    limit: int | None = None,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str = "desc",
) -> ORJSONResponse:
    storage = request.app.state.storage
    q = ListQuery(limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    items, total = await storage.list_denylist(q)
    body = page_envelope(
        [_denylist_response(e) for e in items], total, q.effective_limit(), q.offset
    )
    return ORJSONResponse(body)


@router.post("/denylist", status_code=201)
async def add_denylist(
    request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events
    body = await _json_body(request)

    kind = str(body.get("kind") or "").strip().lower()
    if kind not in _VALID_KINDS:
        return _invalid_request("kind must be one of: ip, user_id, username, email, client_id")

    value = str(body.get("value") or "").strip()
    if not value:
        return _invalid_request("value is required")

    expires_at, ok = _parse_expires_at(body.get("expires_at"))
    if not ok:
        return _invalid_request("expires_at must be a valid RFC3339 datetime")

    reason = str(body.get("reason") or "")
    # Bearer callers have no session, so `request.session` is `{}` and this
    # is "" — Rust parity (bearer/M2M identity is never recorded here).
    created_by = request.session.get("email", "")

    entry = DenylistEntry(
        id=uuid.uuid4().hex,
        kind=kind,
        value=value,
        reason=reason,
        created_by=created_by,
        created_at=datetime.now(timezone.utc),
        expires_at=expires_at,
    )
    # Upserts on (kind, value); the DB keeps the original row id on an
    # upsert, but the response below always reflects `entry` — an
    # intentional Rust-parity quirk (see storage/sql.py add_denylist_entry).
    await storage.add_denylist_entry(entry)

    await record_audit(
        storage,
        events,
        build_audit(
            request,
            actor,
            "denylist.add",
            "denylist",
            entry.id,
            {"kind": kind, "value": value, "reason": reason},
        ),
    )

    return ORJSONResponse(_denylist_response(entry), status_code=201)


@router.delete("/denylist/{entry_id}")
async def remove_denylist(
    entry_id: str, request: Request, actor: AdminActor = Depends(require_admin)
) -> ORJSONResponse:
    storage = request.app.state.storage
    events = request.app.state.events

    # No existence check — deleting an unknown id is a no-op DELETE that
    # still returns 200 and still writes an audit entry (Rust parity).
    await storage.remove_denylist_entry(entry_id)

    await record_audit(
        storage,
        events,
        build_audit(request, actor, "denylist.remove", "denylist", entry_id, {}),
    )

    return ORJSONResponse({"message": "Denylist entry removed"})
