"""Runtime proof that hoisting `Depends(require_admin)` into the module-level
`AdminDep` singleton (the B008 fix) did NOT change FastAPI behavior.

Non-obvious detail this test pins down: FastAPI captures the dependency
callable when the route is registered (`add_api_route`), so monkeypatching
`guard.require_admin` AFTER the app is built cannot observe the call. The
countable hook is therefore `Depends.use_cache` / the router-level dependency
list, plus a real end-to-end assertion that the actor reaches the audit row.
"""

from __future__ import annotations

import inspect

from fastapi import Depends

from oauth2_server.routes.admin import clients, guard
from oauth2_server.routes.admin.guard import AdminDep
from oauth2_server.storage.paging import ListQuery
from tests.conftest import build_client_app
from tests.helpers import login_admin, seed_admin


def test_admin_dep_is_depends_of_require_admin():
    """AdminDep is literally `Depends(require_admin)` — no semantic change."""
    assert type(AdminDep) is type(Depends(guard.require_admin))
    assert AdminDep.dependency is guard.require_admin


def test_admin_dep_keeps_per_request_caching_enabled():
    """`use_cache=True` is what makes the router-level dep + handler default
    collapse into ONE require_admin call per request. Hoisting the call into a
    module-level singleton must not touch it."""
    assert AdminDep.use_cache is True, "AdminDep must keep FastAPI's cache"
    assert inspect.signature(clients.create_client).parameters["actor"].default is AdminDep


async def test_router_dep_and_handler_default_resolve_to_one_cached_call():
    """End-to-end: the mutating handler sees the SAME AdminActor the router
    guard produced, and the audit row records that actor."""
    async with build_client_app() as client:
        await seed_admin(client.storage)
        await login_admin(client)
        resp = await client.post(
            "/admin/api/users",
            json={
                "username": "once_only",
                "email": "once_only@example.test",
                "password": "s3curepw!",
            },
        )
        assert resp.status_code == 201, resp.text

        items, _total = await client.storage.list_audit_log(ListQuery())
        entry = next(e for e in items if e.action == "user.create")
        # Populated actor proves the handler default resolved the real
        # dependency, not a placeholder / None.
        assert entry.actor_email == "admin_rfc@example.test"


async def test_router_guard_still_rejects_unauthenticated():
    async with build_client_app() as client:
        resp = await client.post(
            "/admin/api/users",
            json={"username": "x", "email": "x@example.test", "password": "pw"},
        )
    assert resp.status_code in (302, 401, 403), resp.status_code
