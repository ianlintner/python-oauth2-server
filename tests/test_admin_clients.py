"""HTTP-level tests for the admin clients CRUD API — ported from Rust
`tests/admin_paging.rs` (client sections) + `tests/admin_extra.rs` (client
mutation sections).

Every request authenticates as an admin session (`seed_admin` +
`login_admin`); RBAC itself is covered by `test_admin_rbac.py`.
"""

from __future__ import annotations

import json
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


async def _seed_extra_client(storage, name: str, **overrides):
    fields = dict(id=uuid.uuid4().hex, client_id=f"client-{uuid.uuid4().hex[:8]}", name=name)
    fields.update(overrides)
    return await seed_client(storage, **fields)


async def _clear_default_clients(storage) -> None:
    # build_client_app seeds "client1"; migrations/sql/V5__insert_default_data.sql
    # additionally seeds a dev "default_client" (id="default-client-id") on
    # every fresh storage. Tests asserting exact counts start from a clean
    # clients table.
    await storage.delete_client("client1")
    await storage.delete_client("default_client")


# --- Pagination ---


async def test_list_clients_returns_paged_envelope():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await _clear_default_clients(storage)
        for i in range(15):
            await _seed_extra_client(storage, f"client-{i:02d}")

        resp = await client.get("/admin/api/clients", params={"limit": 5, "offset": 0})
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 5
        assert body["total"] == 15
        assert body["limit"] == 5
        assert body["offset"] == 0


async def test_list_clients_last_page_has_remainder():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await _clear_default_clients(storage)
        for i in range(10):
            await _seed_extra_client(storage, f"client-{i:02d}")

        resp = await client.get("/admin/api/clients", params={"limit": 4, "offset": 8})
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["total"] == 10
        assert body["offset"] == 8


async def test_list_clients_search_filters_by_name():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await storage.delete_client("client1")
        await _seed_extra_client(storage, "alpha-client")
        await _seed_extra_client(storage, "beta-client")

        resp = await client.get("/admin/api/clients", params={"search": "alpha"})
        body = resp.json()
        names = [item["name"] for item in body["items"]]
        assert "alpha-client" in names
        assert "beta-client" not in names


async def test_list_clients_empty_when_none_exist():
    async with build_client_app() as client:
        await _login(client)
        await _clear_default_clients(client.storage)

        resp = await client.get("/admin/api/clients")
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == 0


async def test_list_clients_returns_raw_string_list_fields():
    # Client identity duality gotcha: list/detail expose grant_types/
    # redirect_uris as the raw JSON-encoded strings stored in the DB, not
    # parsed arrays.
    async with build_client_app() as client:
        await _login(client)
        resp = await client.get("/admin/api/clients")
        body = resp.json()
        item = next(i for i in body["items"] if i["client_id"] == "client1")
        assert isinstance(item["grant_types"], str)
        assert isinstance(item["redirect_uris"], str)
        assert json.loads(item["grant_types"]) == [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ]


# --- Detail ---


async def test_get_client_returns_detail():
    async with build_client_app() as client:
        await _login(client)
        seeded = await client.storage.get_client("client1")

        resp = await client.get(f"/admin/api/clients/{seeded.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["client_id"] == "client1"
        assert body["name"] == "test-client"
        assert isinstance(body["grant_types"], str)
        assert isinstance(body["redirect_uris"], str)


async def test_get_client_404_for_missing():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.get("/admin/api/clients/does-not-exist")
        assert resp.status_code == 404
        assert resp.json() == {"error": "client not found"}


# --- Create ---


async def test_create_client_confidential_returns_secret_once():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post("/admin/api/clients", json={"name": "New Client"})
        assert resp.status_code == 201
        body = resp.json()
        assert body["client_id"].startswith("client-")
        assert len(body["client_secret"]) > 16
        assert body["grant_types"] == ["authorization_code", "refresh_token"]
        assert body["redirect_uris"] == []

        stored = await client.storage.get_client(body["client_id"])
        assert stored.client_secret == body["client_secret"]


async def test_create_public_client_has_no_secret():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/clients",
            json={"name": "Public Client", "token_endpoint_auth_method": "none"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["client_secret"] is None
        assert body["token_endpoint_auth_method"] == "none"


async def test_create_client_rejects_empty_name():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post("/admin/api/clients", json={"name": ""})
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"


# --- Update ---


async def test_update_client_mutates_metadata():
    async with build_client_app() as client:
        await _login(client)
        seeded = await client.storage.get_client("client1")

        resp = await client.put(
            f"/admin/api/clients/{seeded.id}",
            json={"name": "Renamed", "scope": "read write", "enabled": False},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Renamed"
        assert body["enabled"] is False

        reloaded = await client.storage.get_client("client1")
        assert reloaded.name == "Renamed"
        assert reloaded.scope == "read write"
        assert reloaded.enabled is False


async def test_update_client_404_for_missing():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.put("/admin/api/clients/does-not-exist", json={"name": "x"})
        assert resp.status_code == 404


# --- Delete ---


async def test_delete_client_removes_row():
    async with build_client_app() as client:
        await _login(client)
        seeded = await client.storage.get_client("client1")

        resp = await client.delete(f"/admin/api/clients/{seeded.id}")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Client deleted"}
        assert await client.storage.get_client("client1") is None


async def test_delete_client_404_for_missing():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.delete("/admin/api/clients/does-not-exist")
        assert resp.status_code == 404


# --- Enable / disable ---


async def test_set_client_enabled_toggles_and_revokes_tokens_on_disable():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        seeded = await storage.get_client("client1")
        token = Token(
            id=uuid.uuid4().hex,
            access_token=uuid.uuid4().hex,
            client_id="client1",
            expires_at=_future(),
        )
        await storage.save_token(token)

        resp = await client.post(f"/admin/api/clients/{seeded.id}/enabled", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json() == {"enabled": False}

        reloaded_client = await storage.get_client("client1")
        assert reloaded_client.enabled is False
        reloaded_token = await storage.get_token_by_access_token(token.access_token)
        assert reloaded_token.revoked is True

        resp = await client.post(f"/admin/api/clients/{seeded.id}/enabled", json={"enabled": True})
        assert resp.status_code == 200
        reloaded_client = await storage.get_client("client1")
        assert reloaded_client.enabled is True


# --- Regenerate secret ---


async def test_regenerate_client_secret_rejects_public_clients():
    async with build_client_app() as client:
        await _login(client)
        create_resp = await client.post(
            "/admin/api/clients",
            json={"name": "Public Client", "token_endpoint_auth_method": "none"},
        )
        client_uuid = create_resp.json()["id"]

        resp = await client.post(f"/admin/api/clients/{client_uuid}/regenerate-secret")
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"


async def test_regenerate_client_secret_replaces_secret():
    async with build_client_app() as client:
        await _login(client)
        seeded = await client.storage.get_client("client1")

        resp = await client.post(f"/admin/api/clients/{seeded.id}/regenerate-secret")
        assert resp.status_code == 200
        body = resp.json()
        assert body["client_id"] == "client1"
        assert body["client_secret"] != "s3cret"

        reloaded = await client.storage.get_client("client1")
        assert reloaded.client_secret == body["client_secret"]
