"""Runtime proof that hoisting `Depends(require_admin)` into the module-level
`AdminDep` singleton (the B008 fix) did NOT change FastAPI behavior.

FastAPI captures the dependency callable when registering a route, so
monkeypatching `guard.require_admin` after app construction does not observe
calls. Instead install an `app.dependency_overrides` counting replacement for
the captured callable; assert router-level and handler-level requirements
resolve once per request, and that the actor reaches the audit row.
"""

from __future__ import annotations

import inspect

from fastapi import Depends, Request

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
        calls = 0

        async def counted_admin(request: Request):
            nonlocal calls
            calls += 1
            return await guard.require_admin(request)

        client.app.dependency_overrides[guard.require_admin] = counted_admin
        resp = await client.post(
            "/admin/api/users",
            json={
                "username": "once_only",
                "email": "once_only@example.test",
                "password": "s3curepw!",
            },
        )
        assert resp.status_code == 201, resp.text
        assert calls == 1, "router and handler must share one admin dependency call"

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
