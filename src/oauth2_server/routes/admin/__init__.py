"""Admin JSON API — mounted under `/admin/api`, guarded by `require_admin`.

Ported from `crates/oauth2-actix/src/handlers/{admin,admin_extra,admin_keys}.rs`,
mounted in Rust under `web::scope("/admin").wrap(AdminGuard)`. This task wires
only the guard plumbing and a temporary `GET /admin/api/ping` endpoint to
exercise RBAC end-to-end; the real endpoints (clients/users/tokens/devices/
dashboard/denylist/audit/keys) attach to `admin_router` in Tasks 8-10 and 13.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from oauth2_server.routes.admin.guard import require_admin

admin_router = APIRouter(prefix="/admin/api", dependencies=[Depends(require_admin)])


@admin_router.get("/ping")
async def ping() -> dict[str, bool]:
    return {"ok": True}
