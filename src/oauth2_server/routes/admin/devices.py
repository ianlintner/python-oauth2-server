"""Admin JSON API — device authorization listing + forced expiry.

Ported from `crates/oauth2-actix/src/handlers/admin.rs` (list) and
`admin_extra.rs` (expire). Routes attach to `admin_router` (see
`routes/admin/__init__.py`), which already carries `Depends(require_admin)`
as a router-level dependency.

Unlike `TokenInfo.user_id`, `DeviceInfo.user_id` stays `null` when unset
(Rust parity — only the token serializer coerces `None` to `""`).
`POST /device/{code}/expire` always returns 200, even for an unknown device
code (the underlying `UPDATE ... WHERE device_code = ?` is a silent no-op) —
no audit entry, matching the Rust handler.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.models import DeviceAuthorization
from oauth2_server.storage.paging import ListQuery, page_envelope

router = APIRouter()


def _device_info(device: DeviceAuthorization) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "id": device.id,
        "device_code": device.device_code,
        "user_code": device.user_code,
        "client_id": device.client_id,
        "scope": device.scope,
        "created_at": device.created_at.isoformat(),
        "expires_at": device.expires_at.isoformat(),
        "approved": device.approved,
        "denied": device.denied,
        "used": device.used,
        "expired": device.expires_at <= now,
        "user_id": device.user_id,
    }


@router.get("/device")
async def list_devices(
    request: Request,
    limit: int | None = None,
    offset: int = 0,
    sort_by: str | None = None,
    sort_dir: str = "desc",
) -> ORJSONResponse:
    storage = request.app.state.storage
    q = ListQuery(limit=limit, offset=offset, sort_by=sort_by, sort_dir=sort_dir)
    items, total = await storage.list_device_authorizations_page(q)
    body = page_envelope([_device_info(d) for d in items], total, q.effective_limit(), q.offset)
    return ORJSONResponse(body)


@router.post("/device/{device_code}/expire")
async def expire_device(device_code: str, request: Request) -> ORJSONResponse:
    storage = request.app.state.storage
    await storage.expire_device_authorization(device_code)
    return ORJSONResponse({"message": "Device code expired"})
