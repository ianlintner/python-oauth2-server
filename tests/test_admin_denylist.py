"""HTTP-level tests for the admin denylist CRUD API + audit log listing —
ported from Rust `tests/admin_extra.rs` (denylist + audit sections) and
`tests/admin_storage_contract.rs` (upsert/pagination shapes, exercised here
through the HTTP layer instead of directly against storage).

Every request authenticates as an admin session (`seed_admin` +
`login_admin`) unless a test specifically exercises the bearer path; RBAC
itself is covered by `test_admin_rbac.py`.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from oauth2_server.models import AuditLogEntry, Token
from oauth2_server.storage.paging import ListQuery
from tests.conftest import build_client_app
from tests.helpers import login_admin, seed_admin


async def _login(client) -> None:
    await seed_admin(client.storage)
    await login_admin(client)


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


async def _seed_bearer_admin(client) -> Token:
    token = Token(
        id=uuid.uuid4().hex,
        access_token=uuid.uuid4().hex,
        client_id="client1",
        scope="admin read",
        expires_at=_future(),
    )
    await client.storage.save_token(token)
    return token


# --- POST /admin/api/denylist ---


async def test_add_denylist_round_trips_via_list():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/denylist",
            json={"kind": "ip", "value": "198.51.100.10", "reason": "brute force"},
        )
        assert resp.status_code == 201
        created = resp.json()
        assert created["kind"] == "ip"
        assert created["value"] == "198.51.100.10"
        assert created["reason"] == "brute force"
        assert created["active"] is True
        assert created["expires_at"] is None

        listed = await client.get("/admin/api/denylist")
        assert listed.status_code == 200
        body = listed.json()
        assert body["total"] == 1
        item = body["items"][0]
        assert item["kind"] == "ip"
        assert item["value"] == "198.51.100.10"
        assert item["active"] is True


async def test_add_denylist_rejects_unknown_kind():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post("/admin/api/denylist", json={"kind": "country", "value": "ZZ"})
        assert resp.status_code == 400
        assert resp.json() == {
            "error": "invalid_request",
            "error_description": "kind must be one of: ip, user_id, username, email, client_id",
        }


async def test_add_denylist_lowercases_kind():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/denylist", json={"kind": "IP", "value": "198.51.100.11"}
        )
        assert resp.status_code == 201
        assert resp.json()["kind"] == "ip"


async def test_add_denylist_rejects_blank_value():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post("/admin/api/denylist", json={"kind": "ip", "value": "   "})
        assert resp.status_code == 400
        assert resp.json() == {
            "error": "invalid_request",
            "error_description": "value is required",
        }


async def test_add_denylist_trims_value():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/denylist", json={"kind": "username", "value": "  mallory  "}
        )
        assert resp.status_code == 201
        assert resp.json()["value"] == "mallory"


async def test_add_denylist_upserts_on_duplicate_kind_value():
    async with build_client_app() as client:
        await _login(client)
        first = await client.post(
            "/admin/api/denylist",
            json={"kind": "username", "value": "mallory", "reason": "initial"},
        )
        assert first.status_code == 201

        second = await client.post(
            "/admin/api/denylist",
            json={"kind": "username", "value": "mallory", "reason": "updated"},
        )
        assert second.status_code == 201

        found = await client.storage.find_denylist_entry("username", "mallory")
        assert found is not None
        assert found.reason == "updated"

        listed = await client.get("/admin/api/denylist")
        assert listed.json()["total"] == 1


async def test_add_denylist_accepts_expires_at():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/denylist",
            json={
                "kind": "ip",
                "value": "198.51.100.12",
                "expires_at": "2030-01-01T00:00:00Z",
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["expires_at"] is not None
        assert body["active"] is True


async def test_add_denylist_expired_entry_is_inactive_in_list():
    async with build_client_app() as client:
        await _login(client)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        resp = await client.post(
            "/admin/api/denylist",
            json={"kind": "ip", "value": "198.51.100.13", "expires_at": past},
        )
        assert resp.status_code == 201
        assert resp.json()["active"] is False

        listed = await client.get("/admin/api/denylist")
        item = next(i for i in listed.json()["items"] if i["value"] == "198.51.100.13")
        assert item["active"] is False


async def test_add_denylist_rejects_invalid_expires_at():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/denylist",
            json={"kind": "ip", "value": "198.51.100.14", "expires_at": "not-a-date"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"


async def test_add_denylist_created_by_is_session_email():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/denylist", json={"kind": "ip", "value": "198.51.100.15"}
        )
        assert resp.json()["created_by"] == "admin_rfc@example.test"


async def test_add_denylist_created_by_empty_for_bearer():
    async with build_client_app({"admin_client_ids": ["client1"]}) as client:
        token = await _seed_bearer_admin(client)
        resp = await client.post(
            "/admin/api/denylist",
            json={"kind": "ip", "value": "198.51.100.16"},
            headers={"Authorization": f"Bearer {token.access_token}"},
        )
        assert resp.status_code == 201
        assert resp.json()["created_by"] == ""


async def test_add_denylist_writes_audit_entry():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/denylist",
            json={"kind": "ip", "value": "198.51.100.17", "reason": "spam"},
        )
        assert resp.status_code == 201

        items, _total = await client.storage.list_audit_log(ListQuery())
        entry = next(e for e in items if e.action == "denylist.add")
        assert entry.target_kind == "denylist"
        assert entry.actor_email == "admin_rfc@example.test"
        metadata = json.loads(entry.metadata)
        assert metadata == {"kind": "ip", "value": "198.51.100.17", "reason": "spam"}


async def test_add_denylist_fans_out_to_events():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/denylist", json={"kind": "ip", "value": "198.51.100.18"}
        )
        assert resp.status_code == 201

        items, _total = client.app.state.events.list(10, 0)
        event = next(e for e in items if e["event_type"] == "denylist.add")
        assert event["target_kind"] == "denylist"
        assert event["metadata"]["value"] == "198.51.100.18"


# --- DELETE /admin/api/denylist/{id} ---


async def test_remove_denylist_clears_entry():
    async with build_client_app() as client:
        await _login(client)
        created = await client.post(
            "/admin/api/denylist", json={"kind": "ip", "value": "198.51.100.20"}
        )
        entry_id = created.json()["id"]

        resp = await client.delete(f"/admin/api/denylist/{entry_id}")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Denylist entry removed"}

        listed = await client.get("/admin/api/denylist")
        assert listed.json()["total"] == 0


async def test_remove_denylist_unknown_id_still_200():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.delete("/admin/api/denylist/does-not-exist")
        assert resp.status_code == 200
        assert resp.json() == {"message": "Denylist entry removed"}


async def test_remove_denylist_writes_audit_entry_with_empty_metadata():
    async with build_client_app() as client:
        await _login(client)
        created = await client.post(
            "/admin/api/denylist", json={"kind": "ip", "value": "198.51.100.21"}
        )
        entry_id = created.json()["id"]

        resp = await client.delete(f"/admin/api/denylist/{entry_id}")
        assert resp.status_code == 200

        items, _total = await client.storage.list_audit_log(ListQuery())
        entry = next(e for e in items if e.action == "denylist.remove")
        assert entry.target_id == entry_id
        assert json.loads(entry.metadata) == {}


# --- GET /admin/api/audit ---


async def test_list_audit_log_is_paginated_newest_first():
    async with build_client_app() as client:
        await _login(client)
        storage = client.storage
        base = datetime.now(timezone.utc)
        for i in range(5):
            await storage.write_audit_log(
                AuditLogEntry(
                    id=uuid.uuid4().hex,
                    action=f"test.action.{i}",
                    created_at=base + timedelta(seconds=i),
                )
            )

        resp = await client.get("/admin/api/audit", params={"limit": 3})
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 5
        assert len(body["items"]) == 3
        assert body["items"][0]["action"] == "test.action.4"


async def test_list_audit_log_metadata_stays_json_string():
    async with build_client_app() as client:
        await _login(client)
        resp = await client.post(
            "/admin/api/denylist",
            json={"kind": "ip", "value": "198.51.100.30", "reason": "for-audit"},
        )
        assert resp.status_code == 201

        listed = await client.get("/admin/api/audit")
        assert listed.status_code == 200
        item = next(i for i in listed.json()["items"] if i["action"] == "denylist.add")
        assert isinstance(item["metadata"], str)
        parsed = json.loads(item["metadata"])
        assert parsed == {"kind": "ip", "value": "198.51.100.30", "reason": "for-audit"}
