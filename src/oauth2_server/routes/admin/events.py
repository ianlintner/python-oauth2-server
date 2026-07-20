"""Admin JSON API — recent admin-mutation event feed.

Ported from `crates/oauth2-actix/src/handlers/events.rs::recent_events`.
Reads the in-memory `RecentEventsStore` ring buffer at `app.state.events`
(see `services/events.py`), fed by `record_audit` on every mutating admin
handler (Tasks 8-10). Route attaches to `admin_router` (see
`routes/admin/__init__.py`), which already carries `Depends(require_admin)`
as a router-level dependency.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.storage.paging import ListQuery, page_envelope

router = APIRouter()


@router.get("/events/recent")
async def recent_events(
    request: Request, limit: int | None = None, offset: int = 0
) -> ORJSONResponse:
    events = request.app.state.events
    q = ListQuery(limit=limit, offset=offset)
    items, total = events.list(q.effective_limit(), q.offset)
    body = page_envelope(items, total, q.effective_limit(), q.offset)
    return ORJSONResponse(body)
