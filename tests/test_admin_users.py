"""HTTP-level tests for the admin users CRUD API — ported from Rust
`tests/admin_paging.rs` (user sections) + `tests/admin_extra.rs` (user
mutation + audit/events fan-out sections).

Every request authenticates as an admin session (`seed_admin` +
`login_admin`); RBAC itself is covered by `test_admin_rbac.py`.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from oauth2_server import security
from oauth2_server.models import Token, User
from oauth2_server.storage.paging import ListQuery
from tests.conftest import build_client_app
from tests.helpers import login_admin, seed_admin


async def _login(client) -> None:
    await seed_admin(client.storage)
    await login_admin(client)


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


async def _seed_extra_user(storage, username: str, **overrides) -> User:
    fields = dict(
        id=uuid.uuid4().hex,
        username=username,
        email=f"{username}@example.test",
        password_hash=security.hash_password("password123"),
    )
    fields.update(overrides)
    user = User(**fields)
    await storage.save_user(user)
    return user


async def _clear_default_users(storage) -> None:
    # build_client_app seeds "user_rfc" (id="u1"); _login's seed_admin adds
    # "admin_rfc" (id="admin1"); migrations/sql/V5__insert_default_data.sql
    # additionally seeds a dev "testuser" (id="test-user-id") on every fresh
    # storage. Tests asserting exact counts start from a clean users table —
    # safe post-login because the session guard trusts the signed session
    # cookie, not a DB re-lookup.
    await storage.delete_user("u1")
    await storage.delete_user("admin1")
    await storage.delete_user("test-user-id")


# --- Pagination ---


async def test_list_users_paged():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await _clear_default_users(storage)
        for i in range(8):
            await _seed_extra_user(storage, f"user-{i:02d}")

        resp = await client.get("/admin/api/users", params={"limit": 3, "offset": 6})
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 8
        assert len(body["items"]) == 2


async def test_list_users_returns_no_password_hash():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.get("/admin/api/users")
        body = resp.json()
        for item in body["items"]:
            assert "password_hash" not in item


# --- Detail ---


async def test_get_user_returns_detail():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.get("/admin/api/users/u1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "user_rfc"
        assert "password_hash" not in body


async def test_get_user_404_for_missing():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.get("/admin/api/users/does-not-exist")
        assert resp.status_code == 404
        assert resp.json() == {"error": "user not found"}


# --- Create ---


async def test_create_user_succeeds_and_hashes_password():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/users",
            json={"username": "newuser", "email": "new@example.test", "password": "s3curepw!"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["username"] == "newuser"
        assert body["role"] == "user"
        assert body["enabled"] is True
        assert "updated_at" in body

        stored = await client.storage.get_user_by_username("newuser")
        assert stored.password_hash.startswith("$argon2")
        assert stored.password_hash != "s3curepw!"


async def test_create_user_rejects_missing_fields():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/users", json={"username": "", "email": "", "password": ""}
        )
        assert resp.status_code == 400
        assert resp.json() == {
            "error": "invalid_request",
            "error_description": "username, email, password are required",
        }


async def test_create_user_rejects_duplicate_username():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/users",
            json={"username": "user_rfc", "email": "dup@example.test", "password": "s3curepw!"},
        )
        assert resp.status_code == 409
        assert resp.json() == {
            "error": "already_exists",
            "error_description": "username already registered",
        }


# --- Update ---


async def test_update_user_patches_email_and_role():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.put(
            "/admin/api/users/u1", json={"email": "changed@example.test", "role": "admin"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == "changed@example.test"
        assert body["role"] == "admin"

        reloaded = await client.storage.get_user_by_id("u1")
        assert reloaded.email == "changed@example.test"
        assert reloaded.role == "admin"


async def test_update_user_ignores_invalid_role():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.put("/admin/api/users/u1", json={"role": "superhacker"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "user"

        reloaded = await client.storage.get_user_by_id("u1")
        assert reloaded.role == "user"


async def test_update_user_404_for_missing():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.put("/admin/api/users/does-not-exist", json={"email": "x@example.test"})
        assert resp.status_code == 404


async def test_put_user_rejects_non_bool_enabled():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.put("/admin/api/users/u1", json={"enabled": "not-a-bool"})
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

        reloaded = await client.storage.get_user_by_id("u1")
        assert reloaded.enabled is True


# --- Delete ---


async def test_delete_user_removes_row_and_revokes_tokens():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        token = Token(
            id=uuid.uuid4().hex,
            access_token=uuid.uuid4().hex,
            client_id="client1",
            user_id="u1",
            expires_at=_future(),
        )
        await storage.save_token(token)

        resp = await client.delete("/admin/api/users/u1")
        assert resp.status_code == 200
        assert resp.json() == {"message": "User deleted"}
        assert await storage.get_user_by_id("u1") is None

        reloaded_token = await storage.get_token_by_access_token(token.access_token)
        assert reloaded_token.revoked is True


async def test_delete_user_404_for_missing():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.delete("/admin/api/users/does-not-exist")
        assert resp.status_code == 404


# --- Enable / disable ---


async def test_set_user_enabled_toggles_flag_and_revokes_on_disable():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        token = Token(
            id=uuid.uuid4().hex,
            access_token=uuid.uuid4().hex,
            client_id="client1",
            user_id="u1",
            expires_at=_future(),
        )
        await storage.save_token(token)

        resp = await client.post("/admin/api/users/u1/enabled", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json() == {"enabled": False}

        reloaded_user = await storage.get_user_by_id("u1")
        assert reloaded_user.enabled is False
        reloaded_token = await storage.get_token_by_access_token(token.access_token)
        assert reloaded_token.revoked is True

        resp = await client.post("/admin/api/users/u1/enabled", json={"enabled": True})
        assert resp.status_code == 200
        reloaded_user = await storage.get_user_by_id("u1")
        assert reloaded_user.enabled is True


async def test_set_user_enabled_rejects_missing_enabled_field():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        token = Token(
            id=uuid.uuid4().hex,
            access_token=uuid.uuid4().hex,
            client_id="client1",
            user_id="u1",
            expires_at=_future(),
        )
        await storage.save_token(token)
        original = await storage.get_user_by_id("u1")
        assert original.enabled is True

        resp = await client.post("/admin/api/users/u1/enabled", json={})
        assert resp.status_code == 400
        assert resp.json() == {
            "error": "invalid_request",
            "error_description": "enabled must be a boolean",
        }

        reloaded_user = await storage.get_user_by_id("u1")
        assert reloaded_user.enabled is True
        reloaded_token = await storage.get_token_by_access_token(token.access_token)
        assert reloaded_token.revoked is False


# --- Role ---


async def test_set_user_role_rejects_invalid_role():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post("/admin/api/users/u1/role", json={"role": "root"})
        assert resp.status_code == 400
        assert resp.json() == {
            "error": "invalid_request",
            "error_description": "role must be 'admin' or 'user'",
        }


async def test_set_user_role_updates_role():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post("/admin/api/users/u1/role", json={"role": "admin"})
        assert resp.status_code == 200
        assert resp.json() == {"role": "admin"}
        reloaded = await client.storage.get_user_by_id("u1")
        assert reloaded.role == "admin"


# --- Password reset ---


async def test_reset_user_password_rejects_weak_password():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post("/admin/api/users/u1/password", json={"password": "short"})
        assert resp.status_code == 400
        assert resp.json() == {
            "error": "weak_password",
            "error_description": "password must be at least 8 characters",
        }


async def test_reset_user_password_updates_hash_and_revokes_tokens():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        original = await storage.get_user_by_id("u1")
        token = Token(
            id=uuid.uuid4().hex,
            access_token=uuid.uuid4().hex,
            client_id="client1",
            user_id="u1",
            expires_at=_future(),
        )
        await storage.save_token(token)

        resp = await client.post("/admin/api/users/u1/password", json={"password": "newpassword1"})
        assert resp.status_code == 200
        assert resp.json() == {"message": "Password reset"}

        reloaded = await storage.get_user_by_id("u1")
        assert reloaded.password_hash.startswith("$argon2")
        assert reloaded.password_hash != original.password_hash

        reloaded_token = await storage.get_token_by_access_token(token.access_token)
        assert reloaded_token.revoked is True


# --- Audit trail / event fan-out ---


async def test_admin_mutation_writes_audit_entry():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/users",
            json={
                "username": "audited",
                "email": "audited@example.test",
                "password": "s3curepw!",
            },
        )
        assert resp.status_code == 201

        items, total = await client.storage.list_audit_log(ListQuery())
        assert total >= 1
        entry = next(e for e in items if e.action == "user.create")
        assert entry.actor_email == "admin_rfc@example.test"
        assert entry.target_kind == "user"
        assert "audited" in entry.metadata


async def test_admin_mutation_fans_out_to_events():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/users",
            json={
                "username": "fanout",
                "email": "fanout@example.test",
                "password": "s3curepw!",
            },
        )
        assert resp.status_code == 201

        items, _total = client.app.state.events.list(10, 0)
        event = next(e for e in items if e["event_type"] == "user.create")
        assert event["source"] == "admin"
        assert event["idempotency_key"]
        assert event["target_kind"] == "user"
        assert event["metadata"]["username"] == "fanout"
