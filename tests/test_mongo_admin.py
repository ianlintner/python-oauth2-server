"""MongoStorage admin-domain contract tests — port of the paging/denylist/
audit contract from `tests/test_admin_storage.py` (which drives `SqlStorage`
directly), run against `MongoStorage` instead so both backends are held to
the same `ListQuery`/`(items, total)` contract (Task 3d-4).

Self-skips (module-level) unless `RUN_TESTCONTAINERS=1` is set AND
motor/testcontainers are importable — identical gate to
`tests/test_mongo_storage.py`; see that file's docstring for why. A real
mongod is started once per module via testcontainers; each test gets its own
database name so pagination/search assertions can't leak across tests.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

RUN_TESTCONTAINERS = os.environ.get("RUN_TESTCONTAINERS") == "1"

try:
    import motor.motor_asyncio  # noqa: F401
    from testcontainers.mongodb import MongoDbContainer

    _DEPS_ERROR: Exception | None = None
except ImportError as e:  # pragma: no cover - exercised when deps missing
    MongoDbContainer = None  # type: ignore[assignment,misc]
    _DEPS_ERROR = e

if RUN_TESTCONTAINERS and _DEPS_ERROR is None:
    from oauth2_server.storage.mongo import MongoStorage
else:
    MongoStorage = None  # type: ignore[assignment,misc]

pytestmark = pytest.mark.skipif(
    not RUN_TESTCONTAINERS or _DEPS_ERROR is not None,
    reason=(
        "set RUN_TESTCONTAINERS=1 (with motor + testcontainers installed) to run "
        "the MongoStorage admin contract suite against a real mongod"
    ),
)

from oauth2_server.models import (  # noqa: E402
    AuditLogEntry,
    Client,
    DenylistEntry,
    DeviceAuthorization,
    Token,
)
from oauth2_server.storage.paging import ListQuery  # noqa: E402


@pytest.fixture(scope="module")
def _mongo_container():
    with MongoDbContainer("mongo:7.0") as mongo:
        yield mongo


@pytest.fixture
async def storage(_mongo_container):
    host = _mongo_container.get_container_host_ip()
    port = _mongo_container.get_exposed_port(_mongo_container.port)
    db_name = f"oauth2_test_{uuid.uuid4().hex[:10]}"
    uri = (
        f"mongodb://{_mongo_container.username}:{_mongo_container.password}"
        f"@{host}:{port}/{db_name}?authSource=admin"
    )
    s = MongoStorage(uri)
    await s.init()
    try:
        yield s
    finally:
        await s._client.drop_database(db_name)
        s._client.close()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _client(client_id: str, name: str, created_at: datetime) -> Client:
    return Client(
        id=uuid.uuid4().hex,
        client_id=client_id,
        client_secret="s",
        redirect_uris='["https://a.example/cb"]',
        grant_types='["authorization_code"]',
        scope="read",
        name=name,
        created_at=created_at,
        updated_at=created_at,
    )


def _token(
    client_id: str, *, user_id: str | None = None, expires_at: datetime | None = None
) -> Token:
    return Token(
        id=uuid.uuid4().hex,
        access_token=uuid.uuid4().hex,
        client_id=client_id,
        user_id=user_id,
        expires_at=expires_at or (_now() + timedelta(hours=1)),
    )


def _device_auth(client_id: str, created_at: datetime) -> DeviceAuthorization:
    suffix = uuid.uuid4().hex
    return DeviceAuthorization(
        id=uuid.uuid4().hex,
        device_code=f"dc-{suffix}",
        user_code=f"UC-{suffix[:8]}",
        client_id=client_id,
        scope="read",
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=10),
    )


# --- Clients page: pagination envelope + search ---


async def test_clients_page_pagination_envelope(storage):
    base = _now()
    for i in range(15):
        await storage.save_client(_client(f"c{i}", f"client-{i}", base + timedelta(seconds=i)))

    items, total = await storage.list_clients_page(ListQuery(limit=5, offset=0))
    assert total == 15
    assert len(items) == 5

    items, total = await storage.list_clients_page(ListQuery(limit=5, offset=10))
    assert total == 15
    assert len(items) == 5

    items, total = await storage.list_clients_page(ListQuery(limit=5, offset=14))
    assert total == 15
    assert len(items) == 1


async def test_clients_page_search_filter(storage):
    base = _now()
    await storage.save_client(_client("alpha-client", "Alpha Widgets", base))
    await storage.save_client(_client("beta-client", "Beta Gadgets", base + timedelta(seconds=1)))

    items, total = await storage.list_clients_page(ListQuery(search="alpha"))
    assert total == 1
    assert items[0].client_id == "alpha-client"

    items, total = await storage.list_clients_page(ListQuery(search="beta"))
    assert total == 1
    assert items[0].client_id == "beta-client"


async def test_clients_page_sorts_by_created_at_desc_by_default(storage):
    base = _now()
    for i in range(3):
        await storage.save_client(_client(f"c{i}", f"client-{i}", base + timedelta(seconds=i)))

    items, _total = await storage.list_clients_page(ListQuery())
    assert [c.client_id for c in items] == ["c2", "c1", "c0"]


# --- Tokens page: status filter ---


async def test_tokens_page_status_filter(storage):
    await storage.save_client(_client("client1", "t", _now()))
    active = _token("client1")
    revoked = _token("client1")
    expired = _token("client1", expires_at=_now() - timedelta(hours=1))
    await storage.save_token(active)
    await storage.save_token(revoked)
    await storage.save_token(expired)
    await storage.revoke_token(revoked.access_token)

    items, total = await storage.list_tokens_page(ListQuery(status="active"))
    assert total == 1
    assert items[0].access_token == active.access_token

    items, total = await storage.list_tokens_page(ListQuery(status="revoked"))
    assert total == 1
    assert items[0].access_token == revoked.access_token

    items, total = await storage.list_tokens_page(ListQuery(status="expired"))
    assert total == 1
    assert items[0].access_token == expired.access_token


# --- Device authorizations ---


async def test_list_all_device_authorizations_caps_at_500_newest(storage):
    # Mirrors SqlStorage.list_all_device_authorizations (ORDER BY created_at
    # DESC LIMIT 500) — MongoStorage previously had no cap at all, which
    # diverged from both SqlStorage and the Rust reference implementation
    # and could make routes/admin/dashboard.py's pending_device_codes count
    # unbounded. Seed 501 staggered rows and assert the oldest is dropped.
    base = _now()
    devices = [_device_auth("client1", base + timedelta(seconds=i)) for i in range(501)]
    await asyncio.gather(*(storage.save_device_authorization(d) for d in devices))

    items = await storage.list_all_device_authorizations()

    assert len(items) == 500
    returned_ids = {d.id for d in items}
    oldest = devices[0]
    newest_500 = devices[1:]
    assert oldest.id not in returned_ids
    assert returned_ids == {d.id for d in newest_500}
    # Still newest-first.
    assert items[0].id == devices[-1].id
    assert items[-1].id == devices[1].id


# --- Denylist ---


async def test_denylist_add_find_remove_round_trip(storage):
    entry = DenylistEntry(
        id=uuid.uuid4().hex,
        kind="ip",
        value="198.51.100.1",
        reason="test",
        created_by="admin@test.example",
        created_at=_now(),
    )
    await storage.add_denylist_entry(entry)

    found = await storage.find_denylist_entry("ip", "198.51.100.1")
    assert found is not None
    assert found.reason == "test"

    await storage.remove_denylist_entry(entry.id)
    assert await storage.find_denylist_entry("ip", "198.51.100.1") is None


async def test_denylist_upsert_on_duplicate_kind_value(storage):
    # created_at is set well in the past so it can't accidentally collide
    # with the second add's timestamp and mask a regression.
    original_created_at = _now() - timedelta(days=1)
    first = DenylistEntry(
        id=uuid.uuid4().hex,
        kind="username",
        value="mallory",
        reason="first",
        created_at=original_created_at,
    )
    await storage.add_denylist_entry(first)

    second = DenylistEntry(
        id=uuid.uuid4().hex,
        kind="username",
        value="mallory",
        reason="updated",
        created_at=_now(),
    )
    await storage.add_denylist_entry(second)

    items, total = await storage.list_denylist(ListQuery())
    assert total == 1

    found = await storage.find_denylist_entry("username", "mallory")
    assert found is not None
    assert found.reason == "updated"
    # Upsert keeps the ORIGINAL row's id AND created_at — the second add's
    # id/created_at never persist. Matches `SqlStorage`'s
    # `ON CONFLICT(kind, value) DO UPDATE SET` which only touches
    # reason/created_by/expires_at, leaving id and created_at untouched.
    assert found.id == first.id
    assert found.created_at == original_created_at


async def test_denylist_list_is_paginated(storage):
    base = _now()
    for i in range(12):
        await storage.add_denylist_entry(
            DenylistEntry(
                id=uuid.uuid4().hex,
                kind="ip",
                value=f"198.51.100.{i}",
                created_at=base + timedelta(seconds=i),
            )
        )

    items, total = await storage.list_denylist(ListQuery(limit=5, offset=0))
    assert len(items) == 5
    assert total == 12

    items, total = await storage.list_denylist(ListQuery(limit=5, offset=10))
    assert len(items) == 2
    assert total == 12


async def test_denylist_find_skips_expired_entries(storage):
    entry = DenylistEntry(
        id=uuid.uuid4().hex,
        kind="ip",
        value="198.51.100.99",
        created_at=_now() - timedelta(hours=2),
        expires_at=_now() - timedelta(hours=1),
    )
    await storage.add_denylist_entry(entry)

    assert await storage.find_denylist_entry("ip", "198.51.100.99") is None


async def test_denylist_list_includes_expired_entries(storage):
    # Unlike `find_denylist_entry`, `list_denylist` has no active-only
    # filter — expired rows stay visible in the admin listing.
    entry = DenylistEntry(
        id=uuid.uuid4().hex,
        kind="ip",
        value="198.51.100.200",
        created_at=_now() - timedelta(hours=2),
        expires_at=_now() - timedelta(hours=1),
    )
    await storage.add_denylist_entry(entry)

    items, total = await storage.list_denylist(ListQuery())
    assert total == 1
    assert items[0].value == "198.51.100.200"


# --- Audit log ---


async def test_audit_log_write_and_list_newest_first(storage):
    base = _now()
    for i in range(3):
        await storage.write_audit_log(
            AuditLogEntry(
                id=uuid.uuid4().hex,
                action=f"a.{i}",
                created_at=base + timedelta(seconds=i),
            )
        )

    items, total = await storage.list_audit_log(ListQuery())
    assert total == 3
    assert items[0].action == "a.2"


async def test_audit_log_respects_limit_offset(storage):
    base = _now()
    for i in range(7):
        await storage.write_audit_log(
            AuditLogEntry(
                id=uuid.uuid4().hex,
                action=f"a.{i}",
                created_at=base + timedelta(seconds=i),
            )
        )

    items, total = await storage.list_audit_log(ListQuery(limit=2, offset=2))
    assert len(items) == 2
    assert total == 7


# --- Bulk token revocation ---


async def test_revoke_tokens_by_client_id_only_touches_that_client(storage):
    await storage.save_client(_client("c1", "t", _now()))
    await storage.save_client(_client("c2", "t", _now()))
    t1 = _token("c1")
    t2 = _token("c2")
    t3 = _token("c1")
    for t in (t1, t2, t3):
        await storage.save_token(t)

    count = await storage.revoke_tokens_by_client_id("c1")
    assert count == 2

    got1 = await storage.get_token_by_access_token(t1.access_token)
    got2 = await storage.get_token_by_access_token(t2.access_token)
    got3 = await storage.get_token_by_access_token(t3.access_token)
    assert got1.revoked is True
    assert got2.revoked is False
    assert got3.revoked is True


async def test_revoke_tokens_by_client_id_idempotent(storage):
    await storage.save_client(_client("c1", "t", _now()))
    token = _token("c1")
    await storage.save_token(token)

    first = await storage.revoke_tokens_by_client_id("c1")
    assert first == 1

    second = await storage.revoke_tokens_by_client_id("c1")
    assert second == 0


# --- Full Storage protocol coverage ---


def test_mongostorage_implements_full_storage_protocol():
    """Guards against future gaps: every public method declared on the
    `Storage` Protocol must exist on `MongoStorage` too. This is a pure
    class-attribute check (no I/O), but lives in this testcontainers-gated
    module since it needs `MongoStorage` importable (the `motor` extra)."""
    from oauth2_server.storage.base import Storage

    protocol_methods = [name for name in vars(Storage) if not name.startswith("_")]
    assert protocol_methods, "sanity: Storage Protocol must declare at least one method"
    missing = [name for name in protocol_methods if not hasattr(MongoStorage, name)]
    assert missing == []
