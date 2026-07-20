"""Admin RBAC guard tests — ported from Rust `tests/admin_rbac.rs` +
`crates/oauth2-actix/src/middleware/admin_guard.rs` unit tests.

`/admin/api/ping` (added purely for this task) exercises the guard;
real admin endpoints land in Tasks 8-10.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from oauth2_server.models import Token
from oauth2_server.routes.admin.guard import client_id_in_allowlist
from tests.conftest import build_client_app
from tests.helpers import login_admin, login_session, seed_admin


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


async def _seed_token(
    storage,
    client_id: str,
    scope: str,
    *,
    expires_at: datetime | None = None,
    revoked: bool = False,
) -> Token:
    token = Token(
        id=uuid.uuid4().hex,
        access_token=uuid.uuid4().hex,
        client_id=client_id,
        scope=scope,
        expires_at=expires_at or _future(),
        revoked=revoked,
    )
    await storage.save_token(token)
    return token


# --- Session path ---


async def test_unauthenticated_admin_api_redirects_to_login():
    async with build_client_app() as client:
        resp = await client.get("/admin/api/ping", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/login?error=login_required" in resp.headers["location"]


async def test_plain_user_session_gets_403():
    async with build_client_app() as client:
        await login_session(client)  # default seeded user_rfc, role=user
        resp = await client.get("/admin/api/ping")
        assert resp.status_code == 403
        assert resp.json() == {
            "error": "insufficient_permissions",
            "error_description": "Admin access required",
        }


async def test_admin_session_passes():
    async with build_client_app() as client:
        await seed_admin(client.storage)
        await login_admin(client)
        resp = await client.get("/admin/api/ping")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


async def test_admin_email_allowlist_grants_admin():
    # role=user (the default seeded user_rfc) but email is in admin_emails.
    # Uppercase in config to also exercise the lowercasing validator.
    async with build_client_app({"admin_emails": ["USER_RFC@EXAMPLE.TEST"]}) as client:
        await login_session(client)
        resp = await client.get("/admin/api/ping")
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


# --- Bearer path ---


async def test_bearer_without_admin_scope_403():
    async with build_client_app({"admin_client_ids": ["client1"]}) as client:
        token = await _seed_token(client.storage, "client1", "read")
        resp = await client.get(
            "/admin/api/ping", headers={"Authorization": f"Bearer {token.access_token}"}
        )
        assert resp.status_code == 403
        assert resp.json() == {
            "error": "insufficient_scope",
            "error_description": "Token requires 'admin' scope",
        }


async def test_bearer_with_admin_scope_and_allowlist_passes():
    async with build_client_app({"admin_client_ids": ["client1"]}) as client:
        token = await _seed_token(client.storage, "client1", "admin read")
        resp = await client.get(
            "/admin/api/ping", headers={"Authorization": f"Bearer {token.access_token}"}
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}


async def test_bearer_admin_scope_non_allowlisted_client_403():
    async with build_client_app({"admin_client_ids": ["other-client"]}) as client:
        token = await _seed_token(client.storage, "client1", "admin read")
        resp = await client.get(
            "/admin/api/ping", headers={"Authorization": f"Bearer {token.access_token}"}
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "insufficient_scope"


async def test_bearer_admin_scope_empty_allowlist_denies_all():
    # Unset/empty admin_client_ids must fail-closed even with a valid
    # admin-scoped token.
    async with build_client_app() as client:
        token = await _seed_token(client.storage, "client1", "admin read")
        resp = await client.get(
            "/admin/api/ping", headers={"Authorization": f"Bearer {token.access_token}"}
        )
        assert resp.status_code == 403
        assert resp.json()["error"] == "insufficient_scope"


async def test_invalid_bearer_401():
    async with build_client_app() as client:
        resp = await client.get(
            "/admin/api/ping", headers={"Authorization": "Bearer does-not-exist"}
        )
        assert resp.status_code == 401
        assert resp.json() == {
            "error": "invalid_token",
            "error_description": "Bearer token is invalid or expired",
        }


async def test_expired_bearer_401():
    async with build_client_app({"admin_client_ids": ["client1"]}) as client:
        token = await _seed_token(
            client.storage,
            "client1",
            "admin read",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        resp = await client.get(
            "/admin/api/ping", headers={"Authorization": f"Bearer {token.access_token}"}
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"


async def test_revoked_bearer_401():
    async with build_client_app({"admin_client_ids": ["client1"]}) as client:
        token = await _seed_token(client.storage, "client1", "admin read", revoked=True)
        resp = await client.get(
            "/admin/api/ping", headers={"Authorization": f"Bearer {token.access_token}"}
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"


# --- client_id_in_allowlist unit tests ---


def test_allowlist_exact_trimmed_match():
    assert client_id_in_allowlist("mcp", []) is False
    assert client_id_in_allowlist("mcp", ["   "]) is False
    assert client_id_in_allowlist("mcp", [" other ", " mcp ", " third "]) is True
    assert client_id_in_allowlist("mcp_evil", [" other ", " mcp ", " third "]) is False
