"""Admin JSON API — audit log listing.

Ported from `crates/oauth2-actix/src/handlers/admin_extra.rs::list_audit_log`.
Route attaches to `admin_router` (see `routes/admin/__init__.py`), which
already carries `Depends(require_admin)` as a router-level dependency.

Unlike `GET /admin/api/events/recent` (`events.py`), `metadata` here is
returned exactly as `AuditLogEntry.metadata` stores it — the raw JSON
*string* written by `build_audit`/`write_audit_log` — never re-parsed into an
object. The events feed is the only place that does that (Rust parity).
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.models import AuditLogEntry
from oauth2_server.storage.paging import ListQuery, page_envelope

router = APIRouter()


def _audit_response(entry: AuditLogEntry) -> dict:
    return {
        "id": entry.id,
        "actor_id": entry.actor_id,
        "actor_email": entry.actor_email,
        "action": entry.action,
        "target_kind": entry.target_kind,
        "target_id": entry.target_id,
        "ip": entry.ip,
        "user_agent": entry.user_agent,
        "metadata": entry.metadata,
        "created_at": entry.created_at.isoformat(),
    }


@router.get("/audit")
async def list_audit(
    request: Request,
    limit: int | None = None,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str = "desc",
) -> ORJSONResponse:
    storage = request.app.state.storage
    q = ListQuery(limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    items, total = await storage.list_audit_log(q)
    body = page_envelope([_audit_response(e) for e in items], total, q.effective_limit(), q.offset)
    return ORJSONResponse(body)
