"""Storage-contract tests for the admin domain: user/client admin ops,
denylist, audit log, and bulk token revocation.

Ported one-for-one from the Rust `tests/admin_storage_contract.rs` suite —
these drive `SqlStorage` directly (no HTTP layer; that's Tasks 7-10).
"""

import uuid
from datetime import datetime, timedelta, timezone

from oauth2_server.models import AuditLogEntry, DenylistEntry, Token
from oauth2_server.storage.paging import ListQuery
from tests.helpers import make_storage, seed_client, seed_user


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _token(client_id: str, user_id: str | None = None) -> Token:
    return Token(
        id=uuid.uuid4().hex,
        access_token=uuid.uuid4().hex,
        client_id=client_id,
        user_id=user_id,
        expires_at=_now() + timedelta(hours=1),
    )


# --- Users ---


async def test_update_user_persists_changes():
    storage = await make_storage()
    user = await seed_user(storage)

    user.email = "changed@example.test"
    user.role = "admin"
    user.enabled = False
    user.password_hash = "new-hash"
    await storage.update_user(user)

    got = await storage.get_user_by_id(user.id)
    assert got.email == "changed@example.test"
    assert got.role == "admin"
    assert got.enabled is False
    assert got.password_hash == "new-hash"


async def test_set_user_enabled_flips_flag():
    storage = await make_storage()
    user = await seed_user(storage)
    assert user.enabled is True

    await storage.set_user_enabled(user.id, False)
    got = await storage.get_user_by_id(user.id)
    assert got.enabled is False

    await storage.set_user_enabled(user.id, True)
    got = await storage.get_user_by_id(user.id)
    assert got.enabled is True


async def test_set_user_role_updates_row():
    storage = await make_storage()
    user = await seed_user(storage)
    assert user.role == "user"

    await storage.set_user_role(user.id, "admin")
    got = await storage.get_user_by_id(user.id)
    assert got.role == "admin"


async def test_set_user_password_hash_replaces_hash():
    storage = await make_storage()
    user = await seed_user(storage)

    await storage.set_user_password_hash(user.id, "$argon2id$replaced")
    got = await storage.get_user_by_id(user.id)
    assert got.password_hash == "$argon2id$replaced"


async def test_delete_user_removes_row_and_nulls_token_references():
    storage = await make_storage()
    client = await seed_client(storage)
    user = await seed_user(storage)
    token = _token(client.client_id, user_id=user.id)
    await storage.save_token(token)

    await storage.delete_user(user.id)

    assert await storage.get_user_by_id(user.id) is None
    got_token = await storage.get_token_by_access_token(token.access_token)
    assert got_token.revoked is True
    assert got_token.user_id is None


# --- Clients ---


async def test_set_client_enabled_persists():
    storage = await make_storage()
    client = await seed_client(storage)
    assert client.enabled is True

    await storage.set_client_enabled(client.client_id, False)
    got = await storage.get_client(client.client_id)
    assert got.enabled is False

    await storage.set_client_enabled(client.client_id, True)
    got = await storage.get_client(client.client_id)
    assert got.enabled is True


async def test_set_client_secret_replaces_secret():
    storage = await make_storage()
    client = await seed_client(storage)

    await storage.set_client_secret(client.client_id, "new-secret-value")
    got = await storage.get_client(client.client_id)
    assert got.client_secret == "new-secret-value"


# --- Denylist ---


async def test_denylist_add_find_remove_round_trip():
    storage = await make_storage()
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


async def test_denylist_upsert_on_duplicate_kind_value():
    storage = await make_storage()
    first = DenylistEntry(
        id=uuid.uuid4().hex,
        kind="username",
        value="mallory",
        reason="first",
        created_at=_now(),
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
    # Upsert keeps the ORIGINAL row id — the second add's id never persists.
    assert found.id == first.id


async def test_denylist_list_is_paginated():
    storage = await make_storage()
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


async def test_denylist_find_skips_expired_entries():
    storage = await make_storage()
    entry = DenylistEntry(
        id=uuid.uuid4().hex,
        kind="ip",
        value="198.51.100.99",
        created_at=_now() - timedelta(hours=2),
        expires_at=_now() - timedelta(hours=1),
    )
    await storage.add_denylist_entry(entry)

    assert await storage.find_denylist_entry("ip", "198.51.100.99") is None


# --- Audit log ---


async def test_audit_log_write_and_list_newest_first():
    storage = await make_storage()
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


async def test_audit_log_respects_limit_offset():
    storage = await make_storage()
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


async def test_revoke_tokens_by_client_id_only_touches_that_client():
    storage = await make_storage()
    c1 = await seed_client(storage, client_id="c1", id=uuid.uuid4().hex)
    c2 = await seed_client(storage, client_id="c2", id=uuid.uuid4().hex)
    t1 = _token(c1.client_id)
    t2 = _token(c2.client_id)
    t3 = _token(c1.client_id)
    for t in (t1, t2, t3):
        await storage.save_token(t)

    count = await storage.revoke_tokens_by_client_id(c1.client_id)
    assert count == 2

    got1 = await storage.get_token_by_access_token(t1.access_token)
    got2 = await storage.get_token_by_access_token(t2.access_token)
    got3 = await storage.get_token_by_access_token(t3.access_token)
    assert got1.revoked is True
    assert got2.revoked is False
    assert got3.revoked is True


async def test_revoke_tokens_by_client_id_idempotent():
    storage = await make_storage()
    client = await seed_client(storage)
    token = _token(client.client_id)
    await storage.save_token(token)

    first = await storage.revoke_tokens_by_client_id(client.client_id)
    assert first == 1

    second = await storage.revoke_tokens_by_client_id(client.client_id)
    assert second == 0
