"""Admin JSON API — summary dashboard + capability flags.

Ported from `crates/oauth2-actix/src/handlers/admin.rs::dashboard` and
`admin_extra.rs::capabilities`. Routes attach to `admin_router` (see
`routes/admin/__init__.py`), which already carries `Depends(require_admin)`
as a router-level dependency.

Deliberate divergence from Rust (see research-admin-api.md gotchas): the
Rust handler wraps every storage call in `.unwrap_or_default()`, so a broken
backend silently reports all-zeros with 200. This port does not swallow
storage errors — a failure here propagates like any other unhandled
exception (500), rather than lying about the counts.

`GET /capabilities` is static in this port: both storage backends this
server ships (`SqlStorage` and `MongoStorage`, see
`storage/factory.py`) truly support every listed capability, so there's no
backend query to proxy (unlike Rust, which reports `false` for denylist/
audit_log on its Mongo backend because those methods are no-op stubs
there — this port's `MongoStorage` actually implements them).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

router = APIRouter()

_CAPABILITIES = {
    "events": True,
    "device_flow": True,
    "key_rotation": True,
    "user_crud": True,
    "client_crud": True,
    "denylist": True,
    "audit_log": True,
    "bulk_revoke": True,
}


@router.get("/dashboard")
async def dashboard(request: Request) -> ORJSONResponse:
    storage = request.app.state.storage
    now = datetime.now(timezone.utc)

    clients = await storage.list_all_clients()
    users = await storage.list_all_users()
    tokens = await storage.list_all_tokens()
    devices = await storage.list_all_device_authorizations()

    public_clients = sum(1 for c in clients if c.is_public())
    total_tokens = len(tokens)
    revoked_tokens = sum(1 for t in tokens if t.revoked)
    active_tokens = sum(1 for t in tokens if not t.revoked and t.expires_at > now)
    expired_tokens = sum(1 for t in tokens if not t.revoked and t.expires_at <= now)
    pending_device_codes = sum(
        1 for d in devices if not d.approved and not d.denied and d.expires_at > now
    )

    return ORJSONResponse(
        {
            "total_clients": len(clients),
            "public_clients": public_clients,
            "confidential_clients": len(clients) - public_clients,
            "total_users": len(users),
            "enabled_users": sum(1 for u in users if u.enabled),
            "total_tokens": total_tokens,
            "active_tokens": active_tokens,
            "revoked_tokens": revoked_tokens,
            "expired_tokens": expired_tokens,
            "pending_device_codes": pending_device_codes,
        }
    )


@router.get("/capabilities")
async def capabilities() -> ORJSONResponse:
    return ORJSONResponse(dict(_CAPABILITIES))
