"""Credentials and tokens at rest: representation, lookups, rotation, cutover.

Ephemeral in-memory SQLite and synthetic values only.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from oauth2_server import cutover
from oauth2_server.errors import OAuthError
from oauth2_server.models import AuthorizationCode, Client, DeviceAuthorization, Token
from oauth2_server.services.client_secrets import protect_client_secret
from oauth2_server.services.clients import ClientService
from oauth2_server.services.credential_storage import (
    SealError,
    derive_seal_key,
    digest,
    is_digest,
    is_secret_verifier,
    seal,
    secret_verifier,
    unseal,
    verify_client_secret,
)
from tests.helpers import TEST_JWT_SECRET, make_storage, seed_client

RAW_ACCESS = "synthetic-access-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
RAW_REFRESH = "synthetic-refresh-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
RAW_CODE = "synthetic-code-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
RAW_DEVICE = "synthetic-device-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
RAW_RAT = "synthetic-rat-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"


@pytest.fixture
async def storage():
    s = await make_storage()
    s.configure_secret_key(TEST_JWT_SECRET)
    return s


async def _raw(storage, sql: str, **params):
    async with storage._engine.connect() as conn:
        return (await conn.execute(text(sql), params)).all()


def _token(access: str = RAW_ACCESS, refresh: str | None = RAW_REFRESH, **kw) -> Token:
    return Token(
        id=uuid.uuid4().hex,
        access_token=access,
        refresh_token=refresh,
        client_id="client1",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        **kw,
    )


# --- representation -----------------------------------------------------------


def test_digests_are_domain_separated_and_deterministic():
    a = digest("v", "access")
    assert a == digest("v", "access")
    assert a != digest("v", "refresh")
    assert is_digest(a, "access") and not is_digest(a, "refresh")
    assert a.split("$", 1)[1] != "v"


def test_secret_verifier_is_nonrecoverable_and_legacy_never_verifies():
    v = secret_verifier("synthetic-secret")
    assert is_secret_verifier(v) and "synthetic-secret" not in v
    assert verify_client_secret(v, "synthetic-secret")
    assert not verify_client_secret(v, "other")
    # A legacy plaintext row must not verify, even against itself.
    assert not verify_client_secret("synthetic-secret", "synthetic-secret")
    assert not verify_client_secret("", "")


def test_seal_is_bound_to_client_and_key():
    key = derive_seal_key("master-one-0123456789abcdef0123456789")
    sealed = seal("hmac-secret", key, "c1")
    assert "hmac-secret" not in sealed
    assert unseal(sealed, key, "c1") == "hmac-secret"
    with pytest.raises(SealError):
        unseal(sealed, key, "c2")
    with pytest.raises(SealError):
        unseal(sealed, derive_seal_key("master-two-0123456789abcdef0123456789"), "c1")


async def test_no_raw_value_is_persisted(storage):
    await seed_client(storage, client_secret="synthetic-secret")
    await storage.save_token(_token())
    await storage.save_authorization_code(
        AuthorizationCode(
            id="a1",
            code=RAW_CODE,
            client_id="client1",
            user_id="u1",
            redirect_uri="https://a.example/cb",
            scope="read",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    await storage.save_device_authorization(
        DeviceAuthorization(
            id="d1",
            device_code=RAW_DEVICE,
            user_code="UC-1",
            client_id="client1",
            scope="read",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    async with storage._engine.connect() as conn:
        dumped = []
        for table in ("clients", "tokens", "authorization_codes", "device_authorizations"):
            dumped.extend(
                str(r) for r in (await conn.execute(text(f"SELECT * FROM {table}"))).all()
            )
    blob = "\n".join(dumped)
    for raw in (RAW_ACCESS, RAW_REFRESH, RAW_CODE, RAW_DEVICE, "synthetic-secret"):
        assert raw not in blob


# --- lookups, revocation, rotation -------------------------------------------


async def test_token_lookups_by_presented_value_only(storage):
    await seed_client(storage)
    await storage.save_token(_token())
    assert (await storage.get_token_by_access_token(RAW_ACCESS)).refresh_token == digest(
        RAW_REFRESH, "refresh"
    )
    assert await storage.get_token_by_refresh_token(RAW_REFRESH) is not None
    # Domain separation: a refresh value is not an access token and vice versa.
    assert await storage.get_token_by_access_token(RAW_REFRESH) is None
    assert await storage.get_token_by_refresh_token(RAW_ACCESS) is None
    # A stored digest presented as a credential matches nothing.
    stored = (await storage.get_token_by_access_token(RAW_ACCESS)).access_token
    assert await storage.get_token_by_access_token(stored) is None


async def test_resave_of_a_read_row_does_not_double_hash(storage):
    await seed_client(storage)
    await storage.save_token(_token())
    row = await storage.get_token_by_access_token(RAW_ACCESS)
    await storage.revoke_token_by_id(row.id)
    assert (await storage.get_token_by_access_token(RAW_ACCESS)).revoked is True


async def test_revoke_by_presented_value_and_by_id(storage):
    await seed_client(storage)
    await storage.save_token(_token())
    await storage.revoke_token(RAW_REFRESH)
    assert (await storage.get_token_by_access_token(RAW_ACCESS)).revoked is True

    other = _token("synthetic-access-2", "synthetic-refresh-2")
    await storage.save_token(other)
    await storage.revoke_token_by_id(other.id)
    assert (await storage.get_token_by_refresh_token("synthetic-refresh-2")).revoked is True


async def test_authorization_code_and_device_code_single_claim(storage):
    await seed_client(storage)
    await storage.save_authorization_code(
        AuthorizationCode(
            id="a1",
            code=RAW_CODE,
            client_id="client1",
            user_id="u1",
            redirect_uri="https://a.example/cb",
            scope="read",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    assert await storage.mark_authorization_code_used(RAW_CODE) == 1
    assert await storage.mark_authorization_code_used(RAW_CODE) == 0
    stored = (await storage.get_authorization_code(RAW_CODE)).code
    assert await storage.get_authorization_code(stored) is None
    assert await storage.mark_authorization_code_used(stored) == 0

    await storage.save_device_authorization(
        DeviceAuthorization(
            id="d1",
            device_code=RAW_DEVICE,
            user_code="UC-1",
            client_id="client1",
            scope="read",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    assert await storage.mark_device_authorization_used(RAW_DEVICE) == 1
    assert await storage.mark_device_authorization_used(RAW_DEVICE) == 0


async def test_registration_access_token_digest_lookup_and_rotation(storage):
    await seed_client(storage, registration_access_token=RAW_RAT)
    got = await storage.resolve_registration_access_token(RAW_RAT)
    assert got is not None and got.client_id == "client1"
    assert got.registration_access_token == digest(RAW_RAT, "rat")
    assert await storage.resolve_registration_access_token(got.registration_access_token) is None
    assert await storage.resolve_registration_access_token("") is None

    await storage.set_client_registration_access_token("client1", "synthetic-rat-new")
    assert await storage.resolve_registration_access_token(RAW_RAT) is None
    assert await storage.resolve_registration_access_token("synthetic-rat-new") is not None
    # An update_client of the row read back must not double-hash it.
    row = await storage.get_client("client1")
    await storage.update_client(row)
    assert await storage.resolve_registration_access_token("synthetic-rat-new") is not None


# --- client secrets: Basic/Post verifier vs HMAC key material ----------------------


async def test_client_secret_authentication_uses_verifier(storage):
    await seed_client(storage, client_secret="synthetic-secret")
    stored = (await storage.get_client("client1")).client_secret
    assert is_secret_verifier(stored)
    service = ClientService(storage)
    form = {"client_id": "client1", "client_secret": "synthetic-secret"}
    assert (await service.authenticate(form, None)).client_id == "client1"
    for bad in ("wrong", stored):  # the stored verifier is not a credential
        with pytest.raises(OAuthError):
            await service.authenticate({"client_id": "client1", "client_secret": bad}, None)


async def test_hmac_secret_unsealed_on_load_and_rotation_replaces_it(storage):
    await seed_client(storage, client_secret="synthetic-secret")
    assert (await storage.get_client("client1")).hmac_secret() == "synthetic-secret"
    verifier, sealed = await protect_client_secret("synthetic-rotated", "client1", TEST_JWT_SECRET)
    await storage.set_client_secret("client1", verifier, sealed)
    got = await storage.get_client("client1")
    assert got.hmac_secret() == "synthetic-rotated"
    assert verify_client_secret(got.client_secret, "synthetic-rotated")
    assert not verify_client_secret(got.client_secret, "synthetic-secret")


async def test_wrong_server_key_leaves_hmac_unavailable(storage):
    await seed_client(storage, client_secret="synthetic-secret")
    storage.configure_secret_key("a-different-server-key-0123456789abcdef")
    assert (await storage.get_client("client1")).hmac_secret() == ""


# --- old/new format boundary and cutover -------------------------------------------


async def _legacy_db():
    """A database as the previous release wrote it: raw values everywhere."""
    s = await make_storage()
    now = datetime.now(UTC).isoformat()
    async with s._engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO clients (id, client_id, client_secret, redirect_uris, grant_types, "
                "scope, name, created_at, updated_at, registration_access_token) VALUES "
                "('i1','legacy','legacy-secret','[]','[\"authorization_code\"]','read','n',"
                ":n,:n,:rat)"
            ),
            {"n": now, "rat": RAW_RAT},
        )
        await conn.execute(
            text(
                "INSERT INTO tokens (id, access_token, refresh_token, token_type, expires_in, "
                "scope, client_id, created_at, expires_at, revoked) VALUES "
                "('t1',:a,:r,'Bearer',3600,'read','legacy',:n,:e,0)"
            ),
            {
                "a": RAW_ACCESS,
                "r": RAW_REFRESH,
                "n": now,
                "e": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO authorization_codes (id, code, client_id, user_id, redirect_uri, "
                "scope, expires_at, used, created_at) VALUES "
                "('a1',:c,'legacy','u1','https://a.example/cb','read',:e,0,:n)"
            ),
            {"c": RAW_CODE, "n": now, "e": (datetime.now(UTC) + timedelta(minutes=5)).isoformat()},
        )
        await conn.execute(
            text(
                "INSERT INTO device_authorizations (id, device_code, user_code, client_id, scope, interval_seconds, "
                "expires_at, created_at) VALUES ('d1',:d,'UC-9','legacy','read',5,:e,:n)"
            ),
            {
                "d": RAW_DEVICE,
                "n": now,
                "e": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            },
        )
    s.configure_secret_key(TEST_JWT_SECRET)
    return s


async def test_legacy_rows_are_not_accepted_before_cutover():
    s = await _legacy_db()
    # No silent legacy acceptance: lookups digest the presented value, so the
    # raw values sitting in an unconverted database match nothing.
    assert await s.get_token_by_access_token(RAW_ACCESS) is None
    assert await s.get_token_by_refresh_token(RAW_REFRESH) is None
    assert await s.get_authorization_code(RAW_CODE) is None
    assert await s.get_device_authorization_by_device_code(RAW_DEVICE) is None
    assert await s.resolve_registration_access_token(RAW_RAT) is None
    assert not verify_client_secret((await s.get_client("legacy")).client_secret, "legacy-secret")
    report = await cutover.status(s)
    assert (
        report.marker is None and report.total_legacy == 7
    )  # incl. the default seeded client secret


async def test_convert_makes_values_findable_by_digest_and_is_idempotent():
    s = await _legacy_db()
    await cutover.convert(s, TEST_JWT_SECRET)
    assert (await s.get_token_by_access_token(RAW_ACCESS)).refresh_token == digest(
        RAW_REFRESH, "refresh"
    )
    assert await s.get_authorization_code(RAW_CODE) is not None
    assert await s.get_device_authorization_by_device_code(RAW_DEVICE) is not None
    assert await s.resolve_registration_access_token(RAW_RAT) is not None
    client = await s.get_client("legacy")
    assert verify_client_secret(client.client_secret, "legacy-secret")
    assert client.hmac_secret() == "legacy-secret"

    report = await cutover.status(s)
    assert report.marker == cutover.CUTOVER_VERSION and report.total_legacy == 0
    await cutover.convert(s, TEST_JWT_SECRET)  # re-run: nothing double-hashed
    assert await s.get_token_by_access_token(RAW_ACCESS) is not None
    # No raw value survives anywhere.
    rows = []
    for t in ("clients", "tokens", "authorization_codes", "device_authorizations"):
        rows.extend(str(r) for r in await _raw(s, f"SELECT * FROM {t}"))
    blob = "\n".join(rows)
    for raw in (RAW_ACCESS, RAW_REFRESH, RAW_CODE, RAW_DEVICE, RAW_RAT, "legacy-secret"):
        assert raw not in blob


async def test_convert_revoke_issued_rotates_but_deletes_nothing():
    s = await _legacy_db()
    await cutover.convert(s, TEST_JWT_SECRET, revoke_issued=True)
    assert (await s.get_token_by_access_token(RAW_ACCESS)).revoked is True
    assert (await s.get_authorization_code(RAW_CODE)).used is True
    assert (await s.get_device_authorization_by_device_code(RAW_DEVICE)).used is True
    assert len(await _raw(s, "SELECT id FROM tokens")) == 1


async def test_convert_keeps_cnf_and_audience_for_refresh_continuity():
    s = await _legacy_db()
    import base64

    def b64(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    jwt_like = f"{b64({'alg': 'none'})}.{b64({'cnf': {'jkt': 'thumb'}, 'aud': ['https://rs']})}.sig"
    async with s._engine.begin() as conn:
        await conn.execute(text("UPDATE tokens SET access_token = :a"), {"a": jwt_like})
    await cutover.convert(s, TEST_JWT_SECRET)
    row = await s.get_token_by_access_token(jwt_like)
    assert json.loads(row.cnf) == {"jkt": "thumb"}
    assert json.loads(row.audience) == ["https://rs"]


def test_rollback_plan_and_cli_refuse_without_confirmation(capsys):
    assert cutover.main(["rollback-plan"]) == 0
    assert "RESTORING" in capsys.readouterr().out


async def test_client_model_unchanged_columns(storage):
    # The V24 columns are additive and default empty for pre-cutover rows.
    c = await seed_client(storage, client_secret="")
    assert isinstance(c, Client) and c.client_secret_key == ""
    assert (await storage.get_client("client1")).hmac_secret() == ""
