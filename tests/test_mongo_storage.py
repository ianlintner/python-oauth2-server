"""MongoStorage contract tests — port of the Rust `mongo_storage.rs`
testcontainers smoke test (`run_storage_contract`), plus the Phase 3d
divergences called out in `.superpowers/sdd/research-mongo-backend.md`:
atomic single-claim on `mark_authorization_code_used` /
`mark_device_authorization_used` (divergence 30), and `revoke_token_family` /
`revoke_tokens_by_user_id` actually being implemented instead of Rust's
silent no-op stubs (divergence 28).

Self-skips (module-level) unless `RUN_TESTCONTAINERS=1` is set AND
motor/testcontainers are importable — mirrors the Rust
`tests/mongo_storage.rs` CI gate (`db-tests` job). A real mongod is started
once per module via testcontainers; each test gets its own database name so
duplicate-key / atomic-claim assertions can't leak across tests.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

RUN_TESTCONTAINERS = os.environ.get("RUN_TESTCONTAINERS") == "1"

# Split in two: this try/except is purely the "are the optional deps even
# installed" self-skip signal (motor + testcontainers). The MongoStorage
# import below is deliberately UNGUARDED once RUN_TESTCONTAINERS=1 and the
# deps are present — before storage/mongo.py exists that import error is
# meant to surface as a collection ERROR (TDD step 2), not a silent skip.
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
        "the MongoStorage contract suite against a real mongod"
    ),
)

from oauth2_server.errors import OAuthError  # noqa: E402
from oauth2_server.models import AuthorizationCode, Client, DeviceAuthorization, Token, User  # noqa: E402


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


# --- helpers (mirrors tests/test_storage.py) ---


def _client(client_id: str = "client1") -> Client:
    now = datetime.now(timezone.utc)
    return Client(
        id=uuid.uuid4().hex,
        client_id=client_id,
        client_secret="s",
        redirect_uris='["https://a.example/cb"]',
        grant_types='["authorization_code"]',
        scope="read",
        name="t",
        created_at=now,
        updated_at=now,
    )


def _user(username: str = "alice") -> User:
    return User(id=uuid.uuid4().hex, username=username, password_hash="x", email="a@example.test")


def _token(at: str, *, family: str | None = None, refresh_token: str | None = "rt") -> Token:
    return Token(
        id=uuid.uuid4().hex,
        access_token=at,
        refresh_token=refresh_token,
        client_id="client1",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        token_family=family,
    )


def _auth_code(code: str = "c1") -> AuthorizationCode:
    return AuthorizationCode(
        id=uuid.uuid4().hex,
        code=code,
        client_id="client1",
        user_id="u1",
        redirect_uri="https://a.example/cb",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )


def _device_auth(device_code: str = "dc1", user_code: str = "UC1") -> DeviceAuthorization:
    return DeviceAuthorization(
        id=uuid.uuid4().hex,
        device_code=device_code,
        user_code=user_code,
        client_id="client1",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )


# --- clients ---


async def test_client_round_trip(storage):
    await storage.save_client(_client())
    got = await storage.get_client("client1")
    assert got is not None
    assert got.client_id == "client1"
    assert got.redirect_uri_list() == ["https://a.example/cb"]


async def test_duplicate_client_id_raises(storage):
    await storage.save_client(_client())
    with pytest.raises(OAuthError):
        await storage.save_client(_client())


async def test_update_client_replaces_full_document(storage):
    c = _client()
    await storage.save_client(c)
    updated = c.model_copy(update={"name": "renamed", "scope": "read write"})
    await storage.update_client(updated)
    got = await storage.get_client("client1")
    assert got.name == "renamed"
    assert got.scope == "read write"


async def test_delete_client(storage):
    await storage.save_client(_client())
    await storage.delete_client("client1")
    assert await storage.get_client("client1") is None


async def test_set_client_enabled_and_secret(storage):
    await storage.save_client(_client())
    await storage.set_client_enabled("client1", False)
    got = await storage.get_client("client1")
    assert got.enabled is False

    await storage.set_client_secret("client1", "new-secret")
    got = await storage.get_client("client1")
    assert got.client_secret == "new-secret"


# --- users ---


async def test_user_round_trip(storage):
    await storage.save_user(_user())
    got = await storage.get_user_by_username("alice")
    assert got is not None
    assert got.email == "a@example.test"
    got_by_id = await storage.get_user_by_id(got.id)
    assert got_by_id is not None
    assert got_by_id.username == "alice"


async def test_duplicate_username_raises(storage):
    await storage.save_user(_user())
    with pytest.raises(OAuthError):
        await storage.save_user(_user())


async def test_update_user_and_setters(storage):
    u = _user()
    await storage.save_user(u)

    updated = u.model_copy(update={"email": "new@example.test"})
    await storage.update_user(updated)
    got = await storage.get_user_by_id(u.id)
    assert got.email == "new@example.test"

    await storage.set_user_enabled(u.id, False)
    assert (await storage.get_user_by_id(u.id)).enabled is False

    await storage.set_user_role(u.id, "admin")
    assert (await storage.get_user_by_id(u.id)).role == "admin"

    await storage.set_user_password_hash(u.id, "new-hash")
    assert (await storage.get_user_by_id(u.id)).password_hash == "new-hash"


async def test_delete_user(storage):
    u = _user()
    await storage.save_user(u)
    await storage.delete_user(u.id)
    assert await storage.get_user_by_id(u.id) is None


# --- tokens ---


async def test_token_save_fetch_revoke(storage):
    await storage.save_client(_client())
    await storage.save_token(_token("at-1"))

    got = await storage.get_token_by_access_token("at-1")
    assert got is not None
    assert got.revoked is False
    assert got.refresh_token == "rt"

    await storage.revoke_token("at-1")
    got = await storage.get_token_by_access_token("at-1")
    assert got.revoked is True


async def test_get_token_by_refresh_token(storage):
    await storage.save_client(_client())
    await storage.save_token(_token("at-refresh", refresh_token="rt-refresh"))
    got = await storage.get_token_by_refresh_token("rt-refresh")
    assert got is not None
    assert got.access_token == "at-refresh"


async def test_get_token_by_id_round_trips(storage):
    await storage.save_client(_client())
    t = _token("at-byid")
    await storage.save_token(t)
    got = await storage.get_token_by_id(t.id)
    assert got is not None
    assert got.access_token == "at-byid"


async def test_two_tokens_with_null_refresh_token_both_save(storage):
    await storage.save_client(_client())
    await storage.save_token(_token("at-null-1", refresh_token=None))
    await storage.save_token(_token("at-null-2", refresh_token=None))

    got1 = await storage.get_token_by_access_token("at-null-1")
    got2 = await storage.get_token_by_access_token("at-null-2")
    assert got1 is not None and got1.refresh_token is None
    assert got2 is not None and got2.refresh_token is None


async def test_duplicate_access_token_raises(storage):
    await storage.save_client(_client())
    await storage.save_token(_token("at-dup"))
    with pytest.raises(OAuthError):
        await storage.save_token(_token("at-dup"))


async def test_revoke_token_family_cascades(storage):
    await storage.save_client(_client())
    fam = "fam-1"
    for i in range(3):
        await storage.save_token(_token(f"at-fam-{i}", family=fam))

    count = await storage.revoke_token_family(fam)
    assert count == 3
    for i in range(3):
        got = await storage.get_token_by_access_token(f"at-fam-{i}")
        assert got.revoked is True


async def test_revoke_tokens_by_user_id_returns_count(storage):
    await storage.save_client(_client())
    for i in range(2):
        t = _token(f"at-user-{i}").model_copy(update={"user_id": "u1"})
        await storage.save_token(t)
    # A token belonging to a different user must not be revoked.
    other = _token("at-other").model_copy(update={"user_id": "u2"})
    await storage.save_token(other)

    count = await storage.revoke_tokens_by_user_id("u1")
    assert count == 2
    assert (await storage.get_token_by_access_token("at-user-0")).revoked is True
    assert (await storage.get_token_by_access_token("at-user-1")).revoked is True
    assert (await storage.get_token_by_access_token("at-other")).revoked is False


async def test_revoke_tokens_by_client_id_returns_count(storage):
    await storage.save_client(_client())
    await storage.save_client(_client("client2"))
    for i in range(2):
        await storage.save_token(_token(f"at-c1-{i}"))
    other = _token("at-c2").model_copy(update={"client_id": "client2"})
    await storage.save_token(other)

    count = await storage.revoke_tokens_by_client_id("client1")
    assert count == 2
    assert (await storage.get_token_by_access_token("at-c2")).revoked is False


# --- authorization codes ---


async def test_authorization_code_round_trip(storage):
    await storage.save_client(_client())
    await storage.save_user(_user())
    code = _auth_code()
    await storage.save_authorization_code(code)
    got = await storage.get_authorization_code("c1")
    assert got is not None
    assert got.used is False


async def test_duplicate_authorization_code_raises(storage):
    await storage.save_client(_client())
    await storage.save_authorization_code(_auth_code())
    with pytest.raises(OAuthError):
        await storage.save_authorization_code(_auth_code())


async def test_authorization_code_round_trips_rar_details_and_dpop_bound_access_token(storage):
    """`tests/test_mongo_serde.py` only proves `authorization_details` is
    OMITTED when None (unit-level, no mongod). This proves the non-None
    case round-trips through a REAL mongod: an authorization code carrying
    RFC 9396 `authorization_details` (RAR), then a Token whose
    `access_token` is a JWT-shaped string carrying an RFC 9449 `cnf.jkt`
    claim. DPoP binding has no dedicated storage column — the `cnf.jkt`
    claim lives inside the JWT `access_token` string itself
    (`services/tokens.py`), so proving that string round-trips byte-for-byte
    through `MongoStorage` IS the DPoP-bound-token persistence proof; RAR's
    `authorization_details` is a genuine JSON-string field that needs its
    own present-value assertion."""
    await storage.save_client(_client())
    await storage.save_user(_user())

    rar_details = json.dumps([{"type": "payment_initiation", "actions": ["initiate"]}])
    code = _auth_code("c-rar").model_copy(update={"authorization_details": rar_details})
    await storage.save_authorization_code(code)
    got_code = await storage.get_authorization_code("c-rar")
    assert got_code.authorization_details == rar_details

    dpop_bound_jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJjbmYiOnsiamt0IjoiYWJjZGVmMTIzIn0sInN1YiI6ImNsaWVudDEifQ."
        "sig-not-verified-here"
    )
    await storage.save_token(_token(dpop_bound_jwt))
    got_token = await storage.get_token_by_access_token(dpop_bound_jwt)
    assert got_token is not None
    assert got_token.access_token == dpop_bound_jwt


async def test_mark_authorization_code_used_is_atomic_single_claim(storage):
    await storage.save_client(_client())
    code = _auth_code("c-race")
    await storage.save_authorization_code(code)

    assert await storage.mark_authorization_code_used("c-race") == 1
    got = await storage.get_authorization_code("c-race")
    assert got.used is True
    assert await storage.mark_authorization_code_used("c-race") == 0


# --- device authorizations ---


async def test_device_authorization_round_trip(storage):
    await storage.save_client(_client())
    d = _device_auth()
    await storage.save_device_authorization(d)

    by_dc = await storage.get_device_authorization_by_device_code("dc1")
    by_uc = await storage.get_device_authorization_by_user_code("UC1")
    assert by_dc is not None and by_dc.device_code == "dc1"
    assert by_uc is not None and by_uc.user_code == "UC1"
    assert by_dc.user_id is None


async def test_duplicate_device_code_raises(storage):
    await storage.save_client(_client())
    await storage.save_device_authorization(_device_auth())
    with pytest.raises(OAuthError):
        await storage.save_device_authorization(_device_auth(user_code="UC-OTHER"))


async def test_duplicate_user_code_raises(storage):
    await storage.save_client(_client())
    await storage.save_device_authorization(_device_auth())
    with pytest.raises(OAuthError):
        await storage.save_device_authorization(_device_auth(device_code="dc-other"))


async def test_approve_and_deny_device_authorization(storage):
    await storage.save_client(_client())
    await storage.save_device_authorization(_device_auth())

    await storage.approve_device_authorization("UC1", "u1")
    got = await storage.get_device_authorization_by_user_code("UC1")
    assert got.approved is True
    assert got.denied is False
    assert got.user_id == "u1"

    await storage.deny_device_authorization("UC1")
    got = await storage.get_device_authorization_by_user_code("UC1")
    assert got.denied is True
    assert got.approved is False


async def test_mark_device_authorization_used_is_atomic_single_claim(storage):
    await storage.save_client(_client())
    d = _device_auth("dc-race", "UC-RACE")
    await storage.save_device_authorization(d)

    assert await storage.mark_device_authorization_used("dc-race") == 1
    got = await storage.get_device_authorization_by_device_code("dc-race")
    assert got.used is True
    assert await storage.mark_device_authorization_used("dc-race") == 0


async def test_expire_device_authorization_writes_iso_string_in_the_past(storage):
    await storage.save_client(_client())
    await storage.save_device_authorization(_device_auth("dc-expire", "UC-EXPIRE"))

    await storage.expire_device_authorization("dc-expire")

    got = await storage.get_device_authorization_by_device_code("dc-expire")
    assert got.expires_at < datetime.now(timezone.utc)


# --- init()/healthcheck() behavior ---


async def test_healthcheck_succeeds(storage):
    await storage.healthcheck()  # must not raise


async def test_init_is_idempotent(storage):
    # init() runs _ensure_indexes()/_normalize_legacy_timestamps() again;
    # must not raise (duplicate index creation, empty-collection scans).
    await storage.init()
    await storage.save_client(_client())
    assert await storage.get_client("client1") is not None
