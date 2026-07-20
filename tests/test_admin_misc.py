"""HTTP-level tests for the admin device/dashboard/capabilities/events API —
ported from Rust `tests/admin_paging.rs` (device + dashboard sections) and
`tests/admin_extra.rs` (capabilities section) plus the events fan-out
behavior exercised throughout `admin_extra.rs`.

Every request authenticates as an admin session (`seed_admin` +
`login_admin`); RBAC itself is covered by `test_admin_rbac.py`.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from oauth2_server import security
from oauth2_server.models import DeviceAuthorization, Token, User
from tests.conftest import build_client_app
from tests.helpers import login_admin, seed_admin, seed_client
from tests.test_device_flow import poll_device_token, start_device_flow


async def _login(client) -> None:
    await seed_admin(client.storage)
    await login_admin(client)


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


async def _seed_device(storage, **overrides) -> DeviceAuthorization:
    fields = dict(
        id=uuid.uuid4().hex,
        device_code=uuid.uuid4().hex,
        user_code="ABCD-EFGH",
        client_id="client1",
        scope="read",
        expires_at=_future(),
    )
    fields.update(overrides)
    device = DeviceAuthorization(**fields)
    await storage.save_device_authorization(device)
    return device


async def _clear_default_clients(storage) -> None:
    await storage.delete_client("client1")
    await storage.delete_client("default_client")


async def _clear_default_users(storage) -> None:
    await storage.delete_user("u1")
    await storage.delete_user("admin1")
    await storage.delete_user("test-user-id")


# --- Device list ---


async def test_list_devices_returns_paged_envelope():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        for i in range(3):
            await _seed_device(storage, user_code=f"CODE-{i:04d}")

        resp = await client.get("/admin/api/device", params={"limit": 2, "offset": 0})
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["total"] == 3
        assert body["limit"] == 2


async def test_list_devices_item_shape():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        device = await _seed_device(storage, user_id="u1")

        resp = await client.get("/admin/api/device")
        item = next(i for i in resp.json()["items"] if i["id"] == device.id)
        assert item == {
            "id": device.id,
            "device_code": device.device_code,
            "user_code": device.user_code,
            "client_id": "client1",
            "scope": "read",
            "created_at": device.created_at.isoformat(),
            "expires_at": device.expires_at.isoformat(),
            "approved": False,
            "denied": False,
            "used": False,
            "expired": False,
            "user_id": "u1",
        }


# --- Device expire ---


async def test_expire_device_then_poll_returns_expired_token():
    async with build_client_app() as client:
        await _login(client)

        start = await start_device_flow(client)
        assert start.status_code == 200, start.text
        device_code = start.json()["device_code"]

        resp = await client.post(f"/admin/api/device/{device_code}/expire")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Device code expired"}

        poll = await poll_device_token(client, device_code)
        assert poll.status_code == 400
        assert poll.json()["error"] == "expired_token"


async def test_expire_device_unknown_code_still_200():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post("/admin/api/device/does-not-exist/expire")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Device code expired"}


# --- Dashboard ---


async def test_dashboard_returns_expected_counts():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await _clear_default_clients(storage)
        await _clear_default_users(storage)

        await seed_client(storage, id=uuid.uuid4().hex, client_id="dash-c1")
        await seed_client(storage, id=uuid.uuid4().hex, client_id="dash-c2")

        await storage.save_user(
            User(
                id=uuid.uuid4().hex,
                username="dash-user",
                email="dash-user@example.test",
                password_hash=security.hash_password("password123"),
            )
        )

        resp = await client.get("/admin/api/dashboard")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_clients"] == 2
        assert body["total_users"] == 1
        assert "active_tokens" in body
        assert "pending_device_codes" in body


async def test_dashboard_counts_active_revoked_expired_tokens():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await storage.save_token(
            Token(
                id=uuid.uuid4().hex,
                access_token=uuid.uuid4().hex,
                client_id="client1",
                expires_at=_future(),
            )
        )
        await storage.save_token(
            Token(
                id=uuid.uuid4().hex,
                access_token=uuid.uuid4().hex,
                client_id="client1",
                expires_at=_future(),
                revoked=True,
            )
        )
        await storage.save_token(
            Token(
                id=uuid.uuid4().hex,
                access_token=uuid.uuid4().hex,
                client_id="client1",
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
            )
        )

        resp = await client.get("/admin/api/dashboard")
        body = resp.json()
        assert body["active_tokens"] == 1
        assert body["revoked_tokens"] == 1
        assert body["expired_tokens"] == 1
        assert body["total_tokens"] == 3


async def test_dashboard_counts_pending_device_codes():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        await _seed_device(storage, user_code="PEND-0001")
        await _seed_device(storage, user_code="APPR-0001", approved=True)
        await _seed_device(storage, user_code="DENY-0001", denied=True)
        await _seed_device(
            storage,
            user_code="EXPR-0001",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
        )

        resp = await client.get("/admin/api/dashboard")
        body = resp.json()
        assert body["pending_device_codes"] == 1


async def test_dashboard_does_not_swallow_storage_errors():
    # Deliberate divergence from Rust (which `.unwrap_or_default()`s every
    # storage call and reports all-zeros with 200 on a broken backend): this
    # port lets the exception propagate.
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage

        async def _broken_list_all_clients():
            raise RuntimeError("storage is down")

        storage.list_all_clients = _broken_list_all_clients

        with pytest.raises(Exception):
            await client.get("/admin/api/dashboard")


# --- Capabilities ---


async def test_capabilities_exposes_all_flags_true():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.get("/admin/api/capabilities")
        assert resp.status_code == 200
        assert resp.json() == {
            "events": True,
            "device_flow": True,
            "key_rotation": True,
            "user_crud": True,
            "client_crud": True,
            "denylist": True,
            "audit_log": True,
            "bulk_revoke": True,
        }


# --- Events ---


async def test_events_recent_returns_pushed_envelopes_newest_first():
    async with build_client_app() as client:
        await _login(client)

        for i in range(3):
            await client.post(
                "/admin/api/users",
                json={
                    "username": f"evt-{i}",
                    "email": f"evt-{i}@example.test",
                    "password": "s3curepw!",
                },
            )

        resp = await client.get("/admin/api/events/recent")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 3
        usernames_in_order = [
            item["metadata"]["username"]
            for item in body["items"]
            if item["event_type"] == "user.create"
        ]
        assert usernames_in_order[:3] == ["evt-2", "evt-1", "evt-0"]


async def test_events_recent_is_paginated():
    async with build_client_app() as client:
        await _login(client)
        for i in range(5):
            await client.post(
                "/admin/api/users",
                json={
                    "username": f"pg-{i}",
                    "email": f"pg-{i}@example.test",
                    "password": "s3curepw!",
                },
            )

        resp = await client.get("/admin/api/events/recent", params={"limit": 2, "offset": 0})
        body = resp.json()
        assert len(body["items"]) == 2
        assert body["total"] >= 5
        assert body["limit"] == 2
