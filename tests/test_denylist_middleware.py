"""Tests for the global `DenylistGuard` ASGI middleware + the
`check_subject_denylisted` helper — ported from Rust
`tests/admin_denylist_middleware.rs`.

`DenylistGuard` is mounted on every HTTP route in `create_app` (see
`app.py`), keyed on `request.client.host` — httpx's `ASGITransport` accepts
a `client=(host, port)` constructor arg that sets `request.client.host`, so
each test here builds its own `AsyncClient` (rather than using the shared
`client_app` fixture, whose transport defaults to `127.0.0.1`) pointed at a
chosen source IP.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from httpx import ASGITransport, AsyncClient

from oauth2_server.app import create_app
from oauth2_server.config import Config
from oauth2_server.middleware import check_subject_denylisted
from oauth2_server.models import DenylistEntry
from tests.helpers import make_storage, seed_client, seed_user


def _now() -> datetime:
    return datetime.now(timezone.utc)


@asynccontextmanager
async def build_client_from_ip(client_ip: str):
    """Like `tests.conftest.build_client_app`, but pins the ASGI transport's
    `client` (peer address) so `DenylistGuard` sees `client_ip`."""
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    storage = await make_storage()
    await seed_client(storage)
    await seed_user(storage)
    app = create_app(config, storage)
    async with AsyncClient(
        transport=ASGITransport(app=app, client=(client_ip, 123)),
        base_url="https://auth.example.com",
    ) as c:
        c.storage = storage
        c.app = app
        yield c


async def _add_denylisted_ip(storage, ip: str, **overrides) -> DenylistEntry:
    fields = dict(
        id=uuid.uuid4().hex,
        kind="ip",
        value=ip,
        reason="brute force",
        created_at=_now(),
    )
    fields.update(overrides)
    entry = DenylistEntry(**fields)
    await storage.add_denylist_entry(entry)
    return entry


# --- DenylistGuard ---


async def test_middleware_blocks_denylisted_ip():
    async with build_client_from_ip("198.51.100.5") as client:
        await _add_denylisted_ip(client.storage, "198.51.100.5")

        resp = await client.get("/health")
        assert resp.status_code == 403
        assert resp.json() == {
            "error": "access_denied",
            "error_description": "request source is denylisted",
        }


async def test_middleware_allows_non_denylisted_ip():
    async with build_client_from_ip("198.51.100.6") as client:
        await _add_denylisted_ip(client.storage, "198.51.100.99")

        resp = await client.get("/health")
        assert resp.status_code == 200


async def test_middleware_blocks_every_route_not_just_health():
    async with build_client_from_ip("198.51.100.7") as client:
        await _add_denylisted_ip(client.storage, "198.51.100.7")

        resp = await client.post("/oauth/token", data={"grant_type": "client_credentials"})
        assert resp.status_code == 403
        assert resp.json()["error"] == "access_denied"


async def test_middleware_honors_expired_denylist_entries():
    async with build_client_from_ip("198.51.100.8") as client:
        await _add_denylisted_ip(
            client.storage,
            "198.51.100.8",
            expires_at=_now() - timedelta(minutes=10),
        )

        resp = await client.get("/health")
        assert resp.status_code == 200


async def test_middleware_fails_open_on_storage_error():
    async with build_client_from_ip("198.51.100.9") as client:
        await _add_denylisted_ip(client.storage, "198.51.100.9")

        async def _broken_find_denylist_entry(kind, value):
            raise RuntimeError("storage is down")

        client.storage.find_denylist_entry = _broken_find_denylist_entry

        resp = await client.get("/health")
        assert resp.status_code == 200


async def test_middleware_passes_through_missing_client():
    # httpx's ASGITransport always sets a `client` tuple, so the "no peer
    # address" branch is exercised by driving the ASGI app directly with a
    # hand-built scope (client=None) instead of going through httpx.
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    storage = await make_storage()
    app = create_app(config, storage)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": "/health",
        "raw_path": b"/health",
        "query_string": b"",
        "headers": [],
        "client": None,
        "server": ("testserver", 443),
        "scheme": "https",
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    messages = []

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)

    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    assert status == 200


# --- check_subject_denylisted ---


async def test_check_subject_denylisted_returns_reason_for_active_entry():
    storage = await make_storage()
    await storage.add_denylist_entry(
        DenylistEntry(
            id=uuid.uuid4().hex,
            kind="username",
            value="mallory",
            reason="abuse",
            created_at=_now(),
        )
    )

    reason = await check_subject_denylisted(storage, "username", "mallory")
    assert reason == "abuse"


async def test_check_subject_denylisted_returns_none_for_unknown_value():
    storage = await make_storage()
    reason = await check_subject_denylisted(storage, "username", "unknown-user")
    assert reason is None


async def test_check_subject_denylisted_ignores_empty_value():
    storage = await make_storage()
    reason = await check_subject_denylisted(storage, "username", "")
    assert reason is None


async def test_check_subject_denylisted_ignores_expired_entry():
    storage = await make_storage()
    await storage.add_denylist_entry(
        DenylistEntry(
            id=uuid.uuid4().hex,
            kind="email",
            value="mallory@example.test",
            reason="abuse",
            created_at=_now() - timedelta(hours=2),
            expires_at=_now() - timedelta(hours=1),
        )
    )

    reason = await check_subject_denylisted(storage, "email", "mallory@example.test")
    assert reason is None


async def test_check_subject_denylisted_fails_open_on_storage_error():
    storage = await make_storage()

    async def _broken_find_denylist_entry(kind, value):
        raise RuntimeError("storage is down")

    storage.find_denylist_entry = _broken_find_denylist_entry

    reason = await check_subject_denylisted(storage, "username", "mallory")
    assert reason is None
