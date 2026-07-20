"""Pure-unit tests for tolerant datetime parsing + Mongo-document field
omission on `oauth2_server.models` (`Client`/`User`/`Token`/
`AuthorizationCode`/`DeviceAuthorization`/`DenylistEntry`/`AuditLogEntry`).

Port of the Rust `chrono_serde` unit tests
(crates/oauth2-core/src/chrono_serde.rs:
required_accepts_rfc3339_string/extjson_v1_millis/extjson_v2_wrapped) and the
per-model `*_deserializes_with_bson_date` tests
(crates/oauth2-storage-mongo/src/lib.rs), plus the `token_serde_omits/
includes_refresh_token` tests. No mongod involved — these only exercise
Pydantic model validation against the shapes a Mongo driver (BSON dates,
extended-JSON, legacy mixed encodings) or the existing SQL path (ISO
strings, native datetimes) can hand back.
"""

from datetime import datetime, timezone

from oauth2_server.models import (
    AuditLogEntry,
    AuthorizationCode,
    Client,
    DenylistEntry,
    DeviceAuthorization,
    Token,
    User,
)

# 2024-04-27T12:00:00Z — the fixture instant used throughout the Rust
# chrono_serde tests (extjson_v1_millis / extjson_v2_wrapped / ...).
FIXTURE_MS = 1_714_219_200_000
FIXTURE_DT = datetime(2024, 4, 27, 12, 0, 0, tzinfo=timezone.utc)


def _client_kwargs(**overrides) -> dict:
    base = dict(
        id="cid-1",
        client_id="client1",
        client_secret="s3cret",
        redirect_uris="[]",
        grant_types="[]",
        scope="read",
        name="Test",
        created_at=FIXTURE_DT,
        updated_at=FIXTURE_DT,
    )
    base.update(overrides)
    return base


def _token_kwargs(**overrides) -> dict:
    base = dict(
        id="tok-1",
        access_token="access-1",
        client_id="client1",
        created_at=FIXTURE_DT,
        expires_at=FIXTURE_DT,
    )
    base.update(overrides)
    return base


def _auth_code_kwargs(**overrides) -> dict:
    base = dict(
        id="code-1",
        code="code-1",
        client_id="client1",
        user_id="user-1",
        redirect_uri="https://a.example/cb",
        scope="read",
        created_at=FIXTURE_DT,
        expires_at=FIXTURE_DT,
    )
    base.update(overrides)
    return base


def _device_auth_kwargs(**overrides) -> dict:
    base = dict(
        id="dev-1",
        device_code="device-1",
        user_code="USER-1",
        client_id="client1",
        scope="read",
        created_at=FIXTURE_DT,
        expires_at=FIXTURE_DT,
    )
    base.update(overrides)
    return base


# --- Token / AuthorizationCode: exclude_none dump omits, doesn't null ---


def test_token_omits_refresh_token_when_none():
    dumped = Token(**_token_kwargs()).model_dump(mode="json", exclude_none=True)
    assert "refresh_token" not in dumped


def test_token_includes_refresh_token_when_some():
    dumped = Token(**_token_kwargs(refresh_token="refresh-1")).model_dump(
        mode="json", exclude_none=True
    )
    assert dumped["refresh_token"] == "refresh-1"


def test_token_omits_token_family_when_none():
    dumped = Token(**_token_kwargs()).model_dump(mode="json", exclude_none=True)
    assert "token_family" not in dumped


def test_authorization_code_omits_optional_fields_when_none():
    dumped = AuthorizationCode(**_auth_code_kwargs()).model_dump(mode="json", exclude_none=True)
    for field in (
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "resource",
        "authorization_details",
        "claims_request",
        "token_family",
    ):
        assert field not in dumped


def test_model_dump_json_mode_renders_datetime_as_iso_string():
    dumped = Token(**_token_kwargs()).model_dump(mode="json", exclude_none=True)
    # Pydantic's JSON mode renders a UTC `datetime` with a "Z" suffix rather
    # than "+00:00" — still RFC 3339, and round-trips through
    # `_coerce_datetime`'s "Z" -> "+00:00" normalization.
    assert dumped["created_at"] == "2024-04-27T12:00:00Z"
    assert dumped["expires_at"] == "2024-04-27T12:00:00Z"
    assert datetime.fromisoformat(dumped["created_at"].replace("Z", "+00:00")) == FIXTURE_DT


# --- Tolerant datetime parsing: aware datetime + ISO string (mixed encoding) ---


def test_user_parses_bson_datetime():
    user = User(
        id="user-1",
        username="user1",
        password_hash="hash",
        email="user1@example.com",
        created_at="2024-04-27T12:00:00Z",
        updated_at=FIXTURE_DT,
    )
    assert user.created_at.timestamp() * 1000 == FIXTURE_MS
    assert user.updated_at.timestamp() * 1000 == FIXTURE_MS


def test_user_naive_datetime_assumed_utc():
    naive = datetime(2024, 4, 27, 12, 0, 0)
    user = User(
        id="user-1",
        username="user1",
        password_hash="hash",
        email="user1@example.com",
        created_at=naive,
        updated_at=naive,
    )
    assert user.created_at.tzinfo == timezone.utc
    assert user.created_at.timestamp() * 1000 == FIXTURE_MS


# --- Extended-JSON v1 ({"$date": <ms>}) and v2 ({"$date": {"$numberLong": "<ms>"}}) ---


def test_client_parses_extjson_v1_and_v2():
    v1 = Client(**_client_kwargs(created_at={"$date": FIXTURE_MS}))
    v2 = Client(**_client_kwargs(created_at={"$date": {"$numberLong": str(FIXTURE_MS)}}))
    assert v1.created_at.timestamp() * 1000 == FIXTURE_MS
    assert v2.created_at.timestamp() * 1000 == FIXTURE_MS


def test_client_minimal_doc_parses():
    client = Client(**_client_kwargs(redirect_uris="[]", grant_types="[]"))
    assert client.redirect_uri_list() == []
    assert client.grant_type_list() == []


def test_token_parses_extjson_v1_and_v2():
    v1 = Token(**_token_kwargs(expires_at={"$date": FIXTURE_MS}))
    v2 = Token(**_token_kwargs(expires_at={"$date": {"$numberLong": str(FIXTURE_MS)}}))
    assert v1.expires_at.timestamp() * 1000 == FIXTURE_MS
    assert v2.expires_at.timestamp() * 1000 == FIXTURE_MS


def test_authorization_code_parses_extjson_v1_and_v2():
    v1 = AuthorizationCode(**_auth_code_kwargs(expires_at={"$date": FIXTURE_MS}))
    v2 = AuthorizationCode(
        **_auth_code_kwargs(expires_at={"$date": {"$numberLong": str(FIXTURE_MS)}})
    )
    assert v1.expires_at.timestamp() * 1000 == FIXTURE_MS
    assert v2.expires_at.timestamp() * 1000 == FIXTURE_MS


def test_device_authorization_parses_extjson_v1_and_v2():
    v1 = DeviceAuthorization(**_device_auth_kwargs(expires_at={"$date": FIXTURE_MS}))
    v2 = DeviceAuthorization(
        **_device_auth_kwargs(expires_at={"$date": {"$numberLong": str(FIXTURE_MS)}})
    )
    assert v1.expires_at.timestamp() * 1000 == FIXTURE_MS
    assert v2.expires_at.timestamp() * 1000 == FIXTURE_MS


# --- DenylistEntry / AuditLogEntry: tolerant created_at (+ expires_at) ---


def test_denylist_entry_parses_bson_date_and_extjson():
    entry_bson = DenylistEntry(
        id="deny-1",
        kind="ip",
        value="1.2.3.4",
        created_at=FIXTURE_DT,
        expires_at={"$date": {"$numberLong": str(FIXTURE_MS)}},
    )
    entry_str = DenylistEntry(
        id="deny-2",
        kind="ip",
        value="1.2.3.4",
        created_at="2024-04-27T12:00:00Z",
        expires_at=None,
    )
    assert entry_bson.created_at.timestamp() * 1000 == FIXTURE_MS
    assert entry_bson.expires_at.timestamp() * 1000 == FIXTURE_MS
    assert entry_str.created_at.timestamp() * 1000 == FIXTURE_MS
    assert entry_str.expires_at is None


def test_audit_log_entry_parses_extjson_and_iso_string():
    entry_v1 = AuditLogEntry(id="audit-1", action="client.create", created_at={"$date": FIXTURE_MS})
    entry_str = AuditLogEntry(
        id="audit-2", action="client.create", created_at="2024-04-27T12:00:00Z"
    )
    assert entry_v1.created_at.timestamp() * 1000 == FIXTURE_MS
    assert entry_str.created_at.timestamp() * 1000 == FIXTURE_MS
