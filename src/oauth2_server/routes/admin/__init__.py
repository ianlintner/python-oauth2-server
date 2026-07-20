"""Admin JSON API — mounted under `/admin/api`, guarded by `require_admin`.

Ported from `crates/oauth2-actix/src/handlers/{admin,admin_extra,admin_keys}.rs`,
mounted in Rust under `web::scope("/admin").wrap(AdminGuard)`. `admin_router`
carries `Depends(require_admin)` as a router-level dependency; every route
included below (via `include_router`) inherits that guard automatically
(FastAPI merges the including router's own `dependencies` into each route it
adds — see `APIRouter.add_api_route`), so `clients_router`/`users_router`
don't redeclare it.

Clients and users CRUD land here in Task 8; tokens/devices/dashboard/
capabilities/events (Task 9), denylist/audit (Task 10), and signing-key
rotation/listing (Task 13) attach the same way.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from oauth2_server.routes.admin.audit import router as audit_router
from oauth2_server.routes.admin.clients import router as clients_router
from oauth2_server.routes.admin.dashboard import router as dashboard_router
from oauth2_server.routes.admin.denylist import router as denylist_router
from oauth2_server.routes.admin.devices import router as devices_router
from oauth2_server.routes.admin.events import router as events_router
from oauth2_server.routes.admin.guard import require_admin
from oauth2_server.routes.admin.keys import router as keys_router
from oauth2_server.routes.admin.tokens import router as tokens_router
from oauth2_server.routes.admin.users import router as users_router

admin_router = APIRouter(prefix="/admin/api", dependencies=[Depends(require_admin)])

admin_router.include_router(clients_router)
admin_router.include_router(users_router)
admin_router.include_router(tokens_router)
admin_router.include_router(devices_router)
admin_router.include_router(dashboard_router)
admin_router.include_router(events_router)
admin_router.include_router(denylist_router)
admin_router.include_router(audit_router)
admin_router.include_router(keys_router)
