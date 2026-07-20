"""HTTP-level tests for the admin tokens API — ported from Rust
`tests/admin_paging.rs` (token sections) + `tests/admin_extra.rs` (bulk
revoke + revoke-by-id sections).

Every request authenticates as an admin session (`seed_admin` +
`login_admin`); RBAC itself is covered by `test_admin_rbac.py`.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone

from oauth2_server.models import Token
from tests.conftest import build_client_app
from tests.helpers import login_admin, seed_admin, seed_client


async def _login(client) -> None:
    await seed_admin(client.storage)
    await login_admin(client)


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def _past(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


async def _seed_token(storage, **overrides) -> Token:
    fields = dict(
        id=uuid.uuid4().hex,
        access_token=uuid.uuid4().hex,
        client_id="client1",
        expires_at=_future(),
    )
    fields.update(overrides)
    token = Token(**fields)
    await storage.save_token(token)
    return token


async def _introspect(client, access_token: str, client_id="client1", client_secret="s3cret"):
    raw = f"{client_id}:{client_secret}".encode()
    return await client.post(
        "/oauth/introspect",
        data={"token": access_token},
        headers={"Authorization": "Basic " + base64.b64encode(raw).decode()},
    )


# --- Pagination ---


async def test_list_tokens_returns_paged_envelope():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        for i in range(5):
            await _seed_token(storage)

        resp = await client.get("/admin/api/tokens", params={"limit": 3, "offset": 0})
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 3
        assert body["total"] == 5
        assert body["limit"] == 3
        assert body["offset"] == 0


async def test_list_tokens_status_filter():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        active = await _seed_token(storage, expires_at=_future())
        revoked = await _seed_token(storage, expires_at=_future(), revoked=True)
        expired = await _seed_token(storage, expires_at=_past())

        resp = await client.get("/admin/api/tokens", params={"status": "active"})
        ids = {item["id"] for item in resp.json()["items"]}
        assert ids == {active.id}

        resp = await client.get("/admin/api/tokens", params={"status": "revoked"})
        ids = {item["id"] for item in resp.json()["items"]}
        assert ids == {revoked.id}

        resp = await client.get("/admin/api/tokens", params={"status": "expired"})
        ids = {item["id"] for item in resp.json()["items"]}
        assert ids == {expired.id}


async def test_list_tokens_never_exposes_token_values():
    async with build_client_app() as client:
        await _login(client)
        await _seed_token(client.storage)

        resp = await client.get("/admin/api/tokens")
        for item in resp.json()["items"]:
            assert "access_token" not in item
            assert "refresh_token" not in item


async def test_list_tokens_user_id_empty_string_when_none():
    async with build_client_app() as client:
        await _login(client)
        token = await _seed_token(client.storage, user_id=None)

        resp = await client.get("/admin/api/tokens")
        item = next(i for i in resp.json()["items"] if i["id"] == token.id)
        assert item["user_id"] == ""


# --- Detail ---


async def test_get_token_returns_detail():
    async with build_client_app() as client:
        await _login(client)
        token = await _seed_token(client.storage, user_id="u1", scope="read write")

        resp = await client.get(f"/admin/api/tokens/{token.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == token.id
        assert body["client_id"] == "client1"
        assert body["user_id"] == "u1"
        assert body["scope"] == "read write"
        assert body["revoked"] is False
        assert body["expired"] is False


async def test_get_token_404_for_missing():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.get("/admin/api/tokens/does-not-exist")
        assert resp.status_code == 404
        assert resp.json() == {"error": "token not found"}


# --- Revoke by row id ---


async def test_revoke_token_by_row_id_actually_revokes():
    # Deliberate divergence from Rust: the Rust handler passes the row `id`
    # straight into `revoke_token`, whose SQL matches on the token VALUE, so
    # it's a silent no-op. This port resolves the row first and revokes the
    # actual `access_token` value, so introspection flips inactive.
    async with build_client_app() as client:
        await _login(client)
        token = await _seed_token(client.storage)

        introspect_before = await _introspect(client, token.access_token)
        assert introspect_before.json()["active"] is True

        resp = await client.post(f"/admin/api/tokens/{token.id}/revoke")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Token revoked"}

        reloaded = await client.storage.get_token_by_access_token(token.access_token)
        assert reloaded.revoked is True

        introspect_after = await _introspect(client, token.access_token)
        assert introspect_after.json()["active"] is False


async def test_revoke_token_unknown_id_still_200():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post("/admin/api/tokens/does-not-exist/revoke")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Token revoked"}


# --- Bulk revoke ---


async def test_bulk_revoke_by_user_revokes_all_their_tokens():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        t1 = await _seed_token(storage, user_id="u1")
        t2 = await _seed_token(storage, user_id="u1")
        t3 = await _seed_token(storage, user_id="u1")

        resp = await client.post("/admin/api/tokens/revoke-by-user", json={"user_id": "u1"})
        assert resp.status_code == 200
        assert resp.json() == {"revoked": 3}

        for t in (t1, t2, t3):
            reloaded = await storage.get_token_by_access_token(t.access_token)
            assert reloaded.revoked is True


async def test_bulk_revoke_by_user_is_idempotent():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await _seed_token(storage, user_id="u1")

        first = await client.post("/admin/api/tokens/revoke-by-user", json={"user_id": "u1"})
        assert first.json() == {"revoked": 1}

        second = await client.post("/admin/api/tokens/revoke-by-user", json={"user_id": "u1"})
        assert second.json() == {"revoked": 0}


async def test_bulk_revoke_by_client_isolated_to_that_client():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await seed_client(storage, id=uuid.uuid4().hex, client_id="c2", client_secret="s3cret2")
        t1 = await _seed_token(storage, client_id="client1")
        t2 = await _seed_token(storage, client_id="c2")

        resp = await client.post(
            "/admin/api/tokens/revoke-by-client", json={"client_id": "client1"}
        )
        assert resp.status_code == 200
        assert resp.json() == {"revoked": 1}

        reloaded_t1 = await storage.get_token_by_access_token(t1.access_token)
        reloaded_t2 = await storage.get_token_by_access_token(t2.access_token)
        assert reloaded_t1.revoked is True
        assert reloaded_t2.revoked is False


async def test_bulk_revoke_writes_audit_entries():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await _seed_token(storage, user_id="u1")
        await _seed_token(storage, client_id="client1")

        await client.post("/admin/api/tokens/revoke-by-user", json={"user_id": "u1"})
        await client.post("/admin/api/tokens/revoke-by-client", json={"client_id": "client1"})

        from oauth2_server.storage.paging import ListQuery

        items, _total = await storage.list_audit_log(ListQuery())
        actions = {e.action for e in items}
        assert "token.bulk_revoke_by_user" in actions
        assert "token.bulk_revoke_by_client" in actions

        by_user_entry = next(e for e in items if e.action == "token.bulk_revoke_by_user")
        assert by_user_entry.target_kind == "user"
        assert '"revoked"' in by_user_entry.metadata

        by_client_entry = next(e for e in items if e.action == "token.bulk_revoke_by_client")
        assert by_client_entry.target_kind == "client"
