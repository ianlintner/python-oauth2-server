import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from oauth2_server.config import Config
from oauth2_server.models import AuthorizationCode, Client, DeviceAuthorization, Token, User
from oauth2_server.storage.sql import SqlStorage
from tests.helpers import make_storage

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations" / "sql"


@pytest.fixture
async def storage():
    s = SqlStorage("sqlite+aiosqlite://", MIGRATIONS)
    await s.init()
    return s


async def test_migrations_create_all_tables(storage):
    for table in (
        "clients",
        "users",
        "tokens",
        "authorization_codes",
        "device_authorizations",
        "signing_keys",
        "denylist",
        "audit_log",
    ):
        assert await storage.table_exists(table), table


async def test_client_round_trip(storage):
    c = _client()
    await storage.save_client(c)
    got = await storage.get_client(c.client_id)
    assert got is not None
    assert got.token_endpoint_auth_method == "client_secret_basic"
    assert got.redirect_uri_list() == ["https://a.example/cb"]


async def test_token_family_revocation_cascades(storage):
    await storage.save_client(_client())
    fam = "fam-1"
    for i in range(3):
        await storage.save_token(_token(f"at-{i}", family=fam))
    count = await storage.revoke_token_family(fam)
    assert count == 3
    got = await storage.get_token_by_access_token("at-0")
    assert got.revoked is True


async def test_authorization_code_single_use(storage):
    await storage.save_client(_client())
    await storage.save_user(_user())
    code = AuthorizationCode(
        id=uuid.uuid4().hex,
        code="c1",
        client_id="client1",
        user_id="u1",
        redirect_uri="https://a.example/cb",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    await storage.save_authorization_code(code)
    await storage.mark_authorization_code_used("c1")
    got = await storage.get_authorization_code("c1")
    assert got.used is True


async def test_mark_authorization_code_used_is_single_claim(storage):
    await storage.save_client(_client())
    await storage.save_user(_user())
    code = AuthorizationCode(
        id=uuid.uuid4().hex,
        code="c-race",
        client_id="client1",
        user_id="u1",
        redirect_uri="https://a.example/cb",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    await storage.save_authorization_code(code)
    assert await storage.mark_authorization_code_used("c-race") == 1
    assert await storage.mark_authorization_code_used("c-race") == 0


async def test_mark_device_authorization_used_is_single_claim(storage):
    await storage.save_client(_client())
    d = DeviceAuthorization(
        id=uuid.uuid4().hex,
        device_code="dc-race",
        user_code="UC-RACE",
        client_id="client1",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    await storage.save_device_authorization(d)
    assert await storage.mark_device_authorization_used("dc-race") == 1
    assert await storage.mark_device_authorization_used("dc-race") == 0


async def test_seed_admin_user_creates_admin_once():
    from oauth2_server.bootstrap import seed_admin_user

    storage = await make_storage()
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
        seed_password="seed-password-123",
    )
    assert await seed_admin_user(storage, config) is True
    user = await storage.get_user_by_username("admin")
    assert user is not None and user.role == "admin"
    assert user.password_hash.startswith("$argon2")
    assert await seed_admin_user(storage, config) is False  # idempotent


async def test_seed_admin_user_skipped_without_password():
    from oauth2_server.bootstrap import seed_admin_user

    storage = await make_storage()
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    assert await seed_admin_user(storage, config) is False
    assert await storage.get_user_by_username("admin") is None


def _client() -> Client:
    now = datetime.now(timezone.utc)
    return Client(
        id="cid-1",
        client_id="client1",
        client_secret="s",
        redirect_uris=json.dumps(["https://a.example/cb"]),
        grant_types=json.dumps(["authorization_code"]),
        scope="read",
        name="t",
        created_at=now,
        updated_at=now,
    )


def _user() -> User:
    return User(id="u1", username="alice", password_hash="x", email="a@example.test")


def _token(at: str, family: str | None = None) -> Token:
    return Token(
        id=uuid.uuid4().hex,
        access_token=at,
        client_id="client1",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        token_family=family,
    )
