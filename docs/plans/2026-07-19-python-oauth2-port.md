# Python OAuth2 Server Port — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Python port of the Rust OAuth2/OIDC server that passes a 1:1 port of the RFC compliance test suite and runs against the *same database schema and migrations* as the Rust server.

**Architecture:** FastAPI (Starlette/ASGI) app served by uvicorn+uvloop (granian as an optional drop-in), Pydantic v2 models mirroring the Rust `oauth2-core` structs field-for-field, and an async `Storage` protocol mirroring the Rust `Storage` trait in `crates/oauth2-ports`. No actors — Rust's `TokenActor`/`ClientActor`/`AuthActor` become plain async service classes; distribution comes from stateless workers sharing Postgres (and later Redis), not in-process actors. The Python server reuses `migrations/sql/V*.sql` verbatim so both servers can point at the same database.

**Tech Stack:** Python 3.12+, uv (packaging), FastAPI, uvicorn[standard] (uvloop), Pydantic v2, SQLAlchemy 2.0 async engine with `text()` SQL (aiosqlite / asyncpg drivers), PyJWT, argon2-cffi, orjson, pytest + pytest-asyncio + httpx (ASGI transport), ruff.

## Global Constraints

- Python `>=3.12`. All I/O async; no sync DB calls in request paths.
- This is a standalone repository (`~/Projects/python-oauth2-server`). Package name: `oauth2_server`.
- DB schema is **owned by the Rust repo** — `migrations/sql/V*.sql` here are vendored copies mirrored from rust-oauth2-server. Never author schema changes in this repo; re-sync from the Rust repo instead.
- Password hashes are Argon2 PHC strings (Rust uses `argon2 = "0.5"`); Python must use `argon2-cffi` so hashes verify in both directions.
- Access-token JWTs: HS256 (Phase 1), JOSE header `typ: "at+JWT"` (RFC 9068), claims `sub, iss, aud, exp, iat, scope, jti, client_id` — `aud` serializes as a bare string when it has exactly one element, else an array (matches Rust serde).
- Env vars are identical to the Rust server: `OAUTH2_DATABASE_URL`, `OAUTH2_JWT_SECRET`, `OAUTH2_PUBLIC_URL` (issuer), `OAUTH2_ALLOWED_ORIGINS`, `OAUTH2_ACCESS_TOKENS_OPAQUE`, etc.
- Timestamps stored/handled as timezone-aware UTC (`datetime.now(timezone.utc)`).
- Test commands: `uv run pytest` from ``. Lint gate: `uv run ruff check . && uv run ruff format --check .`
- TDD throughout: every endpoint lands with its ported RFC test first.
- The ported RFC suite (Task 14) is the acceptance gate for Phase 1 — all 20 `rfc_compliance.rs` tests plus the device-flow and opaque-token tests must pass.

## Scope

**Phase 1 (this plan):** models, storage, migrations runner, JWT service, client auth, `client_credentials`, authorization-code + PKCE flow (with RFC 9207 `iss`), refresh tokens with family-cascade revocation, introspection, revocation, discovery (both well-knowns + JWKS), userinfo, ID tokens, dynamic client registration (RFC 7591) incl. public clients, device flow (RFC 8628), opaque-token mode, and the ported RFC test suite.

**Explicitly deferred to follow-up plans (write them when Phase 1 is green):**
- Phase 2: admin API/SPA, denylist, audit log, session/login UI parity, OIDC logout + `id_token_hint` validation, prompt/max_age enforcement (tests 15–18 of the RFC suite move here if login sessions aren't ready — see Task 14 note), PAR, key rotation/RS256 JWKS.
- Phase 3: social login, event bus, observability/metrics, MongoDB backend, DPoP/RAR/token-exchange, rate limiting/resilience.

## Rust → Python map

| Rust | Python |
|---|---|
| `oauth2-core/src/models/*` | `src/oauth2_server/models.py` |
| `oauth2-ports::Storage` trait | `src/oauth2_server/storage/base.py` (Protocol) |
| `oauth2-storage-sqlx` | `src/oauth2_server/storage/sql.py` (one class, dialect-aware) |
| `TokenActor` | `src/oauth2_server/services/tokens.py` (`TokenService`) |
| `ClientActor` / `AuthActor` | `services/clients.py`, `services/auth.py` |
| `oauth2-actix/handlers/*` | `src/oauth2_server/routes/*.py` |
| `oauth2-config` | `src/oauth2_server/config.py` (pydantic-settings) |
| `tests/rfc_compliance.rs` | `tests/test_rfc_compliance.py` |

---

### Task 1: Project scaffold

**Files:**
- Create: `pyproject.toml`, `src/oauth2_server/__init__.py`, `tests/test_smoke.py`, `README.md`

**Interfaces:**
- Produces: importable package `oauth2_server` with `__version__`; `uv run pytest` and ruff working.

- [ ] **Step 1: Write the failing smoke test**

`tests/test_smoke.py`:
```python
def test_package_imports():
    import oauth2_server

    assert oauth2_server.__version__ == "0.1.0"
```

- [ ] **Step 2: Create pyproject and package**

`pyproject.toml`:
```toml
[project]
name = "oauth2-server"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.30",
    "pydantic>=2.8",
    "pydantic-settings>=2.4",
    "sqlalchemy[asyncio]>=2.0",
    "aiosqlite>=0.20",
    "asyncpg>=0.29",
    "pyjwt>=2.9",
    "argon2-cffi>=23.1",
    "orjson>=3.10",
]

[dependency-groups]
dev = [
    "pytest>=8",
    "pytest-asyncio>=0.24",
    "httpx>=0.27",
    "ruff>=0.6",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py312"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/oauth2_server"]
```

`src/oauth2_server/__init__.py`:
```python
__version__ = "0.1.0"
```

- [ ] **Step 3: Run test — expect PASS**

Run: `uv sync && uv run pytest tests/test_smoke.py -v` → PASS. Also `uv run ruff check .` → clean.

- [ ] **Step 4: Commit**

```bash
git add 
git commit -m "feat(python): scaffold Python OAuth2 server package"
```

---

### Task 2: Core domain models (serde-parity with Rust)

**Files:**
- Create: `src/oauth2_server/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: Pydantic models `Client`, `User`, `Token`, `AuthorizationCode`, `DeviceAuthorization`, `Claims`, `IdTokenClaims`, `TokenResponse`, `IntrospectionResponse`, `ClientRegistration`, `ClientRegistrationResponse`. Helper `Client.is_public() -> bool`.
- Field names/types copy the Rust structs exactly (see the Rust `oauth2-core/src/models/`). JSON-array-as-string fields (`redirect_uris`, `grant_types`, `response_types`, `contacts`, `post_logout_redirect_uris`) stay strings at the model level — helpers `redirect_uri_list()` etc. parse them, matching how the Rust code stores them in TEXT columns.

- [ ] **Step 1: Write failing tests**

`tests/test_models.py`:
```python
import json
from datetime import datetime, timezone

from oauth2_server.models import Claims, Client, IntrospectionResponse


def test_client_is_public():
    c = _client(token_endpoint_auth_method="none")
    assert c.is_public() is True
    assert _client(token_endpoint_auth_method="client_secret_basic").is_public() is False


def test_client_redirect_uri_list_parses_json_string():
    c = _client(redirect_uris='["https://a.example/cb","https://b.example/cb"]')
    assert c.redirect_uri_list() == ["https://a.example/cb", "https://b.example/cb"]


def test_claims_aud_serializes_single_as_string():
    claims = Claims.new("user1", "client1", "read", 3600, "https://auth.example.com")
    data = claims.to_payload()
    assert data["aud"] == "client1"          # single aud -> bare string (Rust serde parity)
    assert data["iss"] == "https://auth.example.com"
    assert data["exp"] - data["iat"] == 3600
    assert len(data["jti"]) > 0


def test_claims_aud_serializes_multiple_as_list():
    claims = Claims.new("user1", "client1", "read", 3600, "https://auth.example.com")
    claims.aud = ["a", "b"]
    assert claims.to_payload()["aud"] == ["a", "b"]


def test_introspection_response_omits_none_fields():
    body = IntrospectionResponse(active=False).model_dump(exclude_none=True)
    assert body == {"active": False}


def _client(**overrides) -> Client:
    now = datetime.now(timezone.utc)
    base = dict(
        id="cid-1", client_id="client1", client_secret="s3cret",
        redirect_uris=json.dumps(["https://a.example/cb"]),
        grant_types=json.dumps(["authorization_code"]),
        scope="read", name="Test", created_at=now, updated_at=now,
    )
    base.update(overrides)
    return Client(**base)
```

- [ ] **Step 2: Run — expect FAIL** (`ModuleNotFoundError` / missing names)

- [ ] **Step 3: Implement `models.py`**

```python
"""Domain models — field-for-field port of crates/oauth2-core/src/models/."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Client(BaseModel):
    id: str
    client_id: str
    client_secret: str
    redirect_uris: str  # JSON array stored as string (TEXT column)
    grant_types: str    # JSON array stored as string
    scope: str
    name: str
    created_at: datetime
    updated_at: datetime
    token_endpoint_auth_method: str = "client_secret_basic"
    registration_access_token: str = ""
    response_types: str = '["code"]'
    contacts: str = ""
    logo_uri: str = ""
    client_uri: str = ""
    policy_uri: str = ""
    tos_uri: str = ""
    jwks: str = ""
    jwks_uri: str = ""
    backchannel_logout_uri: str = ""
    backchannel_logout_session_required: bool = False
    frontchannel_logout_uri: str = ""
    frontchannel_logout_session_required: bool = False
    post_logout_redirect_uris: str = ""
    enabled: bool = True
    require_state: bool = False
    tls_client_certificate_subject_dn: str = ""
    dpop_nonce_required: bool = False

    def is_public(self) -> bool:
        return self.token_endpoint_auth_method == "none"

    def redirect_uri_list(self) -> list[str]:
        return json.loads(self.redirect_uris) if self.redirect_uris else []

    def grant_type_list(self) -> list[str]:
        return json.loads(self.grant_types) if self.grant_types else []


class User(BaseModel):
    id: str
    username: str
    password_hash: str
    email: str
    enabled: bool = True
    role: str = "user"
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)

    def is_admin(self) -> bool:
        return self.role == "admin"


class Token(BaseModel):
    id: str
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int = 3600
    scope: str = ""
    client_id: str
    user_id: str | None = None
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime
    revoked: bool = False
    token_family: str | None = None


class AuthorizationCode(BaseModel):
    id: str
    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scope: str
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime
    used: bool = False
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    nonce: str | None = None
    resource: str | None = None
    authorization_details: str | None = None
    claims_request: str | None = None
    token_family: str | None = None


class DeviceAuthorization(BaseModel):
    id: str
    device_code: str
    user_code: str
    client_id: str
    scope: str
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime
    interval_seconds: int = 5
    approved: bool = False
    denied: bool = False
    used: bool = False
    user_id: str | None = None


class Claims(BaseModel):
    """RFC 9068 access-token claims."""
    sub: str
    iss: str
    aud: list[str]
    exp: int
    iat: int
    scope: str
    jti: str
    client_id: str | None = None

    @classmethod
    def new(cls, subject: str, client_id: str, scope: str,
            duration_seconds: int, issuer: str) -> "Claims":
        iat = int(_now().timestamp())
        return cls(
            sub=subject, iss=issuer, aud=[client_id], exp=iat + duration_seconds,
            iat=iat, scope=scope, jti=uuid.uuid4().hex, client_id=client_id,
        )

    def to_payload(self) -> dict[str, Any]:
        data = self.model_dump(exclude_none=True)
        if len(self.aud) == 1:
            data["aud"] = self.aud[0]  # Rust serde: single aud -> bare string
        return data


class IdTokenClaims(BaseModel):
    iss: str
    sub: str
    aud: str
    exp: int
    iat: int
    nonce: str | None = None
    at_hash: str | None = None
    c_hash: str | None = None
    email: str | None = None
    preferred_username: str | None = None
    acr: str | None = None
    auth_time: int | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int
    scope: str | None = None
    id_token: str | None = None


class IntrospectionResponse(BaseModel):
    active: bool
    scope: str | None = None
    client_id: str | None = None
    username: str | None = None
    token_type: str | None = None
    exp: int | None = None
    iat: int | None = None
    nbf: int | None = None
    sub: str | None = None
    aud: list[str] | str | None = None
    jti: str | None = None
    iss: str | None = None


class ClientRegistration(BaseModel):
    redirect_uris: list[str]
    client_name: str = ""
    grant_types: list[str] = ["authorization_code"]
    response_types: list[str] = ["code"]
    scope: str = ""
    token_endpoint_auth_method: str = "client_secret_basic"
    contacts: list[str] = []
    logo_uri: str | None = None
    client_uri: str | None = None
    policy_uri: str | None = None
    tos_uri: str | None = None
    jwks: dict | None = None
    jwks_uri: str | None = None


class ClientRegistrationResponse(BaseModel):
    client_id: str
    client_secret: str | None = None
    client_id_issued_at: int
    client_secret_expires_at: int | None = None
    registration_access_token: str
    registration_client_uri: str
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    token_endpoint_auth_method: str
    client_name: str = ""
    scope: str = ""
```

- [ ] **Step 4: Run tests — expect PASS**, then run ruff.

- [ ] **Step 5: Commit** — `git commit -m "feat(python): port core domain models with serde parity"`

---

### Task 3: Migration runner + SQL storage backend

**Files:**
- Create: `src/oauth2_server/storage/__init__.py`, `src/oauth2_server/storage/base.py`, `src/oauth2_server/storage/sql.py`, `src/oauth2_server/storage/migrations.py`
- Test: `tests/test_storage.py`

**Interfaces:**
- Consumes: models from Task 2; the repo's shared `migrations/sql/V*.sql`.
- Produces:
  - `Storage` Protocol in `base.py` mirroring the Rust trait — Phase-1 subset: `init`, `save_client/get_client/update_client/delete_client`, `save_user/get_user_by_username/get_user_by_id`, `save_token/get_token_by_access_token/get_token_by_refresh_token/revoke_token/set_token_family/revoke_token_family`, `save_authorization_code/get_authorization_code/mark_authorization_code_used`, and the 7 device-authorization methods.
  - `SqlStorage(database_url: str, migrations_dir: Path)` implementing it via SQLAlchemy async engine + `text()` SQL, dialect-aware (sqlite / postgresql).
  - `run_migrations(engine, migrations_dir)` applying `V*.sql` in version order, tracked in table `py_schema_version(version INTEGER PRIMARY KEY)`. **Note:** tracking is Python-side only; when pointing at a DB the Rust server already migrated, the runner must skip statements that fail with "already exists"/"duplicate column" — implement by checking current schema, not by swallowing errors: before each version, skip it if its version number is already recorded OR (first run against an existing DB) probe `SELECT 1 FROM clients LIMIT 1` succeeds for V1, etc. Simplest correct approach used here: on first run, detect an existing `clients` table and backfill `py_schema_version` to the highest V-file without executing anything; fresh DBs execute everything.
- **Postgres-vs-SQLite SQL dialect:** the shared migration files are written for Postgres (`TIMESTAMPTZ`, `BYTEA`, `BOOLEAN`). For SQLite (tests), `run_migrations` applies literal replacements `TIMESTAMPTZ→TEXT`, `BYTEA→BLOB`, and strips `ON CONFLICT ... DO NOTHING` incompatibilities — same trick the sqlx crate's SQLite branch effectively encodes by hand. Keep the replacement table in one place at the top of `migrations.py`.

- [ ] **Step 1: Write failing tests**

`tests/test_storage.py`:
```python
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from oauth2_server.models import AuthorizationCode, Client, Token, User
from oauth2_server.storage.sql import SqlStorage

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations" / "sql"


@pytest.fixture
async def storage():
    s = SqlStorage("sqlite+aiosqlite://", MIGRATIONS)
    await s.init()
    return s


async def test_migrations_create_all_tables(storage):
    for table in ("clients", "users", "tokens", "authorization_codes",
                  "device_authorizations", "signing_keys", "denylist", "audit_log"):
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
        id=uuid.uuid4().hex, code="c1", client_id="client1", user_id="u1",
        redirect_uri="https://a.example/cb", scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    await storage.save_authorization_code(code)
    await storage.mark_authorization_code_used("c1")
    got = await storage.get_authorization_code("c1")
    assert got.used is True


def _client() -> Client:
    now = datetime.now(timezone.utc)
    return Client(id="cid-1", client_id="client1", client_secret="s",
                  redirect_uris=json.dumps(["https://a.example/cb"]),
                  grant_types=json.dumps(["authorization_code"]),
                  scope="read", name="t", created_at=now, updated_at=now)


def _user() -> User:
    return User(id="u1", username="alice", password_hash="x", email="a@example.test")


def _token(at: str, family: str | None = None) -> Token:
    return Token(id=uuid.uuid4().hex, access_token=at, client_id="client1",
                 expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                 token_family=family)
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement**

`storage/base.py` — the Protocol (abridged to signature style; implement every method listed in Interfaces above):
```python
from typing import Protocol

from oauth2_server.models import (AuthorizationCode, Client, DeviceAuthorization,
                                  Token, User)


class Storage(Protocol):
    async def init(self) -> None: ...
    async def save_client(self, client: Client) -> None: ...
    async def get_client(self, client_id: str) -> Client | None: ...
    async def update_client(self, client: Client) -> None: ...
    async def delete_client(self, client_id: str) -> None: ...
    async def save_user(self, user: User) -> None: ...
    async def get_user_by_username(self, username: str) -> User | None: ...
    async def get_user_by_id(self, user_id: str) -> User | None: ...
    async def save_token(self, token: Token) -> None: ...
    async def get_token_by_access_token(self, access_token: str) -> Token | None: ...
    async def get_token_by_refresh_token(self, refresh_token: str) -> Token | None: ...
    async def revoke_token(self, token: str) -> None: ...
    async def set_token_family(self, access_token: str, family: str) -> None: ...
    async def revoke_token_family(self, family: str) -> int: ...
    async def save_authorization_code(self, code: AuthorizationCode) -> None: ...
    async def get_authorization_code(self, code: str) -> AuthorizationCode | None: ...
    async def mark_authorization_code_used(self, code: str) -> None: ...
    async def save_device_authorization(self, d: DeviceAuthorization) -> None: ...
    async def get_device_authorization_by_device_code(self, device_code: str) -> DeviceAuthorization | None: ...
    async def get_device_authorization_by_user_code(self, user_code: str) -> DeviceAuthorization | None: ...
    async def approve_device_authorization(self, user_code: str, user_id: str) -> None: ...
    async def deny_device_authorization(self, user_code: str) -> None: ...
    async def mark_device_authorization_used(self, device_code: str) -> None: ...
    async def expire_device_authorization(self, device_code: str) -> None: ...
```

`storage/migrations.py`:
```python
import re
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

SQLITE_REWRITES = [
    ("TIMESTAMPTZ", "TEXT"),
    ("BYTEA", "BLOB"),
]

_VERSION_RE = re.compile(r"^V(\d+)__")


def _version_of(path: Path) -> int:
    m = _VERSION_RE.match(path.name)
    if not m:
        raise ValueError(f"unversioned migration file: {path.name}")
    return int(m.group(1))


async def run_migrations(engine: AsyncEngine, migrations_dir: Path) -> None:
    files = sorted(migrations_dir.glob("V*.sql"), key=_version_of)
    is_sqlite = engine.dialect.name == "sqlite"
    async with engine.begin() as conn:
        await conn.execute(text(
            "CREATE TABLE IF NOT EXISTS py_schema_version (version INTEGER PRIMARY KEY)"))
        applied = {row[0] for row in
                   (await conn.execute(text("SELECT version FROM py_schema_version"))).all()}
        if not applied:
            # Existing DB migrated by the Rust server? Backfill instead of re-running.
            try:
                await conn.execute(text("SELECT 1 FROM clients LIMIT 1"))
                for f in files:
                    await conn.execute(
                        text("INSERT INTO py_schema_version (version) VALUES (:v)"),
                        {"v": _version_of(f)})
                return
            except Exception:
                pass  # fresh DB — run everything
        for f in files:
            v = _version_of(f)
            if v in applied:
                continue
            sql = f.read_text()
            if is_sqlite:
                for old, new in SQLITE_REWRITES:
                    sql = sql.replace(old, new)
            for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
                await conn.execute(text(stmt))
            await conn.execute(
                text("INSERT INTO py_schema_version (version) VALUES (:v)"), {"v": v})
```

`storage/sql.py` — pattern (write every method following it; column lists match the final schema from V1–V21):
```python
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from oauth2_server.models import (AuthorizationCode, Client, DeviceAuthorization,
                                  Token, User)
from oauth2_server.storage.migrations import run_migrations

_CLIENT_COLS = (
    "id, client_id, client_secret, redirect_uris, grant_types, scope, name, "
    "created_at, updated_at, token_endpoint_auth_method, registration_access_token, "
    "response_types, contacts, logo_uri, client_uri, policy_uri, tos_uri, jwks, "
    "jwks_uri, backchannel_logout_uri, backchannel_logout_session_required, "
    "frontchannel_logout_uri, frontchannel_logout_session_required, "
    "post_logout_redirect_uris, enabled, require_state, "
    "tls_client_certificate_subject_dn, dpop_nonce_required"
)


class SqlStorage:
    def __init__(self, database_url: str, migrations_dir: Path):
        self._engine: AsyncEngine = create_async_engine(database_url)
        self._migrations_dir = migrations_dir

    async def init(self) -> None:
        await run_migrations(self._engine, self._migrations_dir)

    async def table_exists(self, name: str) -> bool:
        q = ("SELECT name FROM sqlite_master WHERE type='table' AND name=:n"
             if self._engine.dialect.name == "sqlite"
             else "SELECT tablename FROM pg_tables WHERE tablename=:n")
        async with self._engine.connect() as conn:
            return (await conn.execute(text(q), {"n": name})).first() is not None

    async def save_client(self, client: Client) -> None:
        cols = _CLIENT_COLS
        params = ", ".join(f":{c.strip()}" for c in cols.split(","))
        async with self._engine.begin() as conn:
            await conn.execute(
                text(f"INSERT INTO clients ({cols}) VALUES ({params})"),
                client.model_dump(mode="json"))

    async def get_client(self, client_id: str) -> Client | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(
                text(f"SELECT {_CLIENT_COLS} FROM clients WHERE client_id = :cid"),
                {"cid": client_id})).mappings().first()
        return Client(**row) if row else None

    async def revoke_token_family(self, family: str) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                text("UPDATE tokens SET revoked = :t WHERE token_family = :f"),
                {"t": True, "f": family})
        return result.rowcount

    # ... every remaining Storage method follows the same SELECT/INSERT/UPDATE
    # text() pattern; translate the queries 1:1 from
    # crates/oauth2-storage-sqlx/src/sqlx.rs (SQLite/Postgres branches).
```
Implementation note for the executor: open `crates/oauth2-storage-sqlx/src/sqlx.rs` alongside — every method there is a direct template; keep query text and column order identical.

- [ ] **Step 4: Run tests — expect PASS.** If seed migration V5 fails on SQLite (`ON CONFLICT` differences), add a rewrite entry rather than skipping the file.

- [ ] **Step 5: Commit** — `git commit -m "feat(python): SQL storage backend over shared migrations"`

---

### Task 4: JWT service (RFC 9068) + password hashing

**Files:**
- Create: `src/oauth2_server/security.py`
- Test: `tests/test_security.py`

**Interfaces:**
- Consumes: `Claims` from Task 2.
- Produces:
  - `encode_access_token(claims: Claims, secret: str) -> str` — HS256, header `{"typ": "at+JWT"}`.
  - `decode_access_token(token: str, secret: str, issuer: str) -> Claims` — verifies signature, `exp`, `iss`; raises `jwt.PyJWTError` subtypes on failure.
  - `hash_password(password: str) -> str` / `verify_password(password: str, phc_hash: str) -> bool` via argon2-cffi (Argon2id, library defaults).

- [ ] **Step 1: Failing tests**

`tests/test_security.py`:
```python
import jwt
import pytest

from oauth2_server.models import Claims
from oauth2_server.security import (decode_access_token, encode_access_token,
                                    hash_password, verify_password)

SECRET = "unit-test-secret-not-for-production-0123456789abcdef"
ISS = "https://auth.example.com"


def test_access_token_header_typ_is_at_jwt():
    token = encode_access_token(Claims.new("u1", "c1", "read", 3600, ISS), SECRET)
    assert jwt.get_unverified_header(token)["typ"] == "at+JWT"


def test_round_trip_preserves_claims():
    token = encode_access_token(Claims.new("u1", "c1", "read", 3600, ISS), SECRET)
    claims = decode_access_token(token, SECRET, ISS)
    assert (claims.sub, claims.iss, claims.aud) == ("u1", ISS, ["c1"])


def test_wrong_issuer_rejected():
    token = encode_access_token(Claims.new("u1", "c1", "read", 3600, ISS), SECRET)
    with pytest.raises(jwt.InvalidIssuerError):
        decode_access_token(token, SECRET, "https://evil.example.com")


def test_argon2_round_trip_and_rust_interop():
    h = hash_password("hunter2")
    assert h.startswith("$argon2")
    assert verify_password("hunter2", h) and not verify_password("wrong", h)
    # PHC hash produced by the Rust server (argon2 0.5 defaults) must verify here.
    # Generate once via: cargo run --example hash_password hunter2  (or copy one
    # from a dev DB) and paste below before enabling:
    # assert verify_password("hunter2", RUST_GENERATED_HASH)
```

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement `security.py`**

```python
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from oauth2_server.models import Claims

_hasher = PasswordHasher()


def encode_access_token(claims: Claims, secret: str) -> str:
    return jwt.encode(claims.to_payload(), secret, algorithm="HS256",
                      headers={"typ": "at+JWT"})


def decode_access_token(token: str, secret: str, issuer: str) -> Claims:
    payload = jwt.decode(token, secret, algorithms=["HS256"], issuer=issuer,
                         options={"verify_aud": False})
    aud = payload.get("aud")
    if isinstance(aud, str):
        payload["aud"] = [aud]
    return Claims(**payload)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, phc_hash: str) -> bool:
    try:
        return _hasher.verify(phc_hash, password)
    except VerifyMismatchError:
        return False
```

- [ ] **Step 4: Run — PASS.** Separately, generate one Rust-side Argon2 hash, paste into the interop assertion, re-run, and keep it enabled.

- [ ] **Step 5: Commit** — `git commit -m "feat(python): JWT service (at+JWT) and argon2 password hashing"`

---

### Task 5: Config from shared env vars + app factory

**Files:**
- Create: `src/oauth2_server/config.py`, `src/oauth2_server/app.py`, `src/oauth2_server/__main__.py`
- Test: `tests/test_app.py`

**Interfaces:**
- Produces:
  - `Config` (pydantic-settings) with fields: `database_url` (env `OAUTH2_DATABASE_URL`, default `sqlite+aiosqlite://`), `jwt_secret` (`OAUTH2_JWT_SECRET`), `issuer` (`OAUTH2_PUBLIC_URL`, default `http://localhost:8080`), `allowed_origins` (`OAUTH2_ALLOWED_ORIGINS`, comma-split, default empty = deny all cross-origin), `access_tokens_opaque` (`OAUTH2_ACCESS_TOKENS_OPAQUE`, default False), `access_token_ttl_secs: int = 3600`, `refresh_token_ttl_secs: int = 86400`, `authorization_code_ttl_secs: int = 600`, `host`/`port`.
  - `Config.validate_for_production()` raising on `jwt_secret` shorter than 32 chars or equal to known-insecure defaults (port the Rust check).
  - `create_app(config: Config, storage: Storage) -> FastAPI` — registers routers as later tasks add them; ORJSONResponse default; security headers middleware (`Cache-Control: no-store`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` on `/oauth/*` responses); CORS restricted to `allowed_origins` (no origins configured → no CORS layer at all, fail-closed like the Rust `Cors::default()`).
  - `GET /health` → `{"status": "ok"}`.
  - `__main__.py` runs uvicorn with `loop="uvloop"`.

- [ ] **Step 1: Failing test**

`tests/test_app.py`:
```python
import pytest
from httpx import ASGITransport, AsyncClient

from oauth2_server.app import create_app
from oauth2_server.config import Config
from tests.helpers import make_storage  # added in this task: SqlStorage on sqlite memory


@pytest.fixture
async def client():
    config = Config(jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
                    issuer="https://auth.example.com")
    app = create_app(config, await make_storage())
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url="https://auth.example.com") as c:
        yield c


async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_insecure_jwt_secret_rejected():
    with pytest.raises(ValueError):
        Config(jwt_secret="secret", issuer="x").validate_for_production()
```

Also create `tests/helpers.py`:
```python
from pathlib import Path

from oauth2_server.storage.sql import SqlStorage

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations" / "sql"


async def make_storage() -> SqlStorage:
    s = SqlStorage("sqlite+aiosqlite://", MIGRATIONS)
    await s.init()
    return s
```

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement config + app factory** (straightforward pydantic-settings `env_prefix="OAUTH2_"` mapping plus a small `@app.middleware("http")` for the security headers; store `config` and `storage` on `app.state`).

- [ ] **Step 4: Run — PASS.** **Step 5: Commit** — `git commit -m "feat(python): config from shared env vars + FastAPI app factory"`

---

### Task 6: Client authentication + client_credentials grant

**Files:**
- Create: `src/oauth2_server/services/clients.py`, `src/oauth2_server/services/tokens.py`, `src/oauth2_server/routes/token.py`, `src/oauth2_server/errors.py`
- Modify: `src/oauth2_server/app.py` (mount router at `/oauth`)
- Test: `tests/test_token_endpoint.py`

**Interfaces:**
- Produces:
  - `errors.py`: `oauth_error(error: str, description: str | None = None, status: int = 400) -> JSONResponse` returning RFC 6749 §5.2 bodies (`{"error": ..., "error_description": ...}`) with `Cache-Control: no-store`. `invalid_client` uses status 401 + `WWW-Authenticate: Basic`.
  - `ClientService(storage)`: `authenticate(request_form, authorization_header) -> Client` — supports `client_secret_basic` (URL-decoded per RFC 6749 §2.3.1 — port the Rust url-decoding fix), `client_secret_post`, and `none` (public clients). Rules ported from Rust: public client presenting a secret → `invalid_client`; disabled client → `invalid_client`; secret compared with `secrets.compare_digest`.
  - `TokenService(storage, config)`: `issue(client, user_id, scope, *, with_refresh: bool, token_family: str | None) -> TokenResponse` — JWT or opaque (`secrets.token_urlsafe(32)`) per `config.access_tokens_opaque`; persists a `Token` row either way.
  - `POST /oauth/token` handling `grant_type=client_credentials` (no refresh token, `user_id=None`), rejecting unknown grant types with `unsupported_grant_type` and `grant_type=implicit`-adjacent abuse with `unauthorized_client` when the client's `grant_types` doesn't include the requested one.

- [ ] **Step 1: Failing tests** — seed a confidential client via `helpers.py` (add `seed_client(storage, **overrides)` and `seed_user(storage)` helpers using Task 3 models with argon2-hashed `"password123"`), then:

```python
async def test_client_credentials_issues_at_jwt(client_app):
    resp = await post_token(client_app, {"grant_type": "client_credentials"},
                            basic_auth=("client1", "s3cret"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert jwt.get_unverified_header(body["access_token"])["typ"] == "at+JWT"
    assert "refresh_token" not in body or body["refresh_token"] is None
    assert resp.headers["cache-control"] == "no-store"


async def test_wrong_secret_rejected_with_401(client_app):
    resp = await post_token(client_app, {"grant_type": "client_credentials"},
                            basic_auth=("client1", "nope"))
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def test_urlencoded_basic_secret_decoded(client_app):
    # secret "s%26cret" in Basic auth must decode to "s&cret" (RFC 6749 §2.3.1)
    ...


async def test_unsupported_grant_type(client_app):
    resp = await post_token(client_app, {"grant_type": "password"},
                            basic_auth=("client1", "s3cret"))
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"
```
(Write `post_token` helper posting `application/x-www-form-urlencoded`.)

- [ ] **Step 2: Run — FAIL.** **Step 3: Implement** the three modules; wire router in `create_app`. **Step 4: Run — PASS.** **Step 5: Commit** — `git commit -m "feat(python): client auth + client_credentials grant"`

---

### Task 7: Authorization endpoint with PKCE and RFC 9207 iss

**Files:**
- Create: `src/oauth2_server/services/auth.py`, `src/oauth2_server/routes/authorize.py`, `src/oauth2_server/sessions.py`
- Modify: `src/oauth2_server/app.py`
- Test: `tests/test_authorize.py`

**Interfaces:**
- Consumes: `ClientService`, storage, config.
- Produces:
  - `sessions.py`: signed-cookie session (itsdangerous-style via `starlette.middleware.sessions.SessionMiddleware` with `config.jwt_secret`-derived key). Session keys: `user_id`, `auth_time` (unix seconds). Test helper `login_session(client, user_id)` performs `POST /auth/login`.
  - `POST /auth/login` (form: username/password) — verifies argon2 hash, rejects disabled users, **regenerates session id on login** (port the session-fixation fix), stores `user_id` + `auth_time`, redirects to validated `return_to` (relative paths only — port `is_safe_redirect`).
  - `GET /oauth/authorize` — validates `client_id`, exact-match `redirect_uri` against the registered list (unregistered → 400 error page, never redirect), `response_type=code` only (reject `token` with `unsupported_response_type` **redirected** to the client), scope intersection, PKCE: public clients MUST send `code_challenge` with `code_challenge_method=S256` (reject `plain`); verifier/challenge length rules 43–128. Unauthenticated → 302 to `/auth/login?return_to=...`. Authenticated → mints `AuthorizationCode` (TTL `config.authorization_code_ttl_secs`, fresh `token_family=uuid4().hex`) and 302-redirects to `redirect_uri` with `code`, `state` (echoed), and **`iss=<config.issuer>`** (RFC 9207).

- [ ] **Step 1: Failing tests** — port from `rfc_compliance.rs`/`security_http.rs`:

```python
async def test_rfc9207_iss_included_in_authorization_response(app_with_session):
    await login_session(app_with_session, "u1")
    resp = await app_with_session.get("/oauth/authorize", params={
        "response_type": "code", "client_id": "client1",
        "redirect_uri": "https://a.example/cb", "scope": "read", "state": "xyz"})
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["iss"] == ["https://auth.example.com"]
    assert q["state"] == ["xyz"]
    assert "code" in q


async def test_unregistered_redirect_uri_never_redirects(app_with_session):
    await login_session(app_with_session, "u1")
    resp = await app_with_session.get("/oauth/authorize", params={
        "response_type": "code", "client_id": "client1",
        "redirect_uri": "https://evil.example/cb"})
    assert resp.status_code == 400


async def test_public_client_requires_s256_pkce(app_with_session): ...
async def test_plain_pkce_method_rejected(app_with_session): ...
async def test_implicit_response_type_rejected(app_with_session): ...
```

- [ ] **Step 2: Run — FAIL.** **Step 3: Implement.** **Step 4: Run — PASS.** **Step 5: Commit** — `git commit -m "feat(python): authorization endpoint with PKCE and RFC 9207 iss"`

---

### Task 8: authorization_code + refresh_token grants (rotation + family cascade)

**Files:**
- Modify: `src/oauth2_server/routes/token.py`, `src/oauth2_server/services/tokens.py`
- Test: `tests/test_token_endpoint.py` (extend)

**Interfaces:**
- Produces, in `POST /oauth/token`:
  - `grant_type=authorization_code`: load code; reject if unknown/expired/used (`invalid_grant`); enforce one-time use — **replaying a used code revokes the whole token family minted from it** (RFC 9700, port from Rust); `redirect_uri` must equal the one bound to the code; PKCE verify: S256(`code_verifier`) == stored challenge, verifier length 43–128; public clients exchange with **no secret** (auth method `none`) but presenting a secret is `invalid_client`. Issues access + refresh token, both tagged with the code's `token_family`. If scope includes `openid`, also mints an ID token (`IdTokenClaims`: `iss/sub/aud=client_id/exp/iat`, `nonce` echoed from the code, `email`/`preferred_username` when `email`/`profile` scopes granted, `c_hash` computed over the code).
  - `grant_type=refresh_token`: client auth required (matching the token's client); rotation — old refresh token revoked, new pair issued in the same family; **reuse of a rotated refresh token revokes the family** (`invalid_grant`).

- [ ] **Step 1: Failing tests** (full-flow helper `run_code_flow(client, *, pkce=True, scope="openid email")` that logs in, hits `/oauth/authorize`, extracts `code`, posts to `/oauth/token`):

```python
async def test_public_client_exchanges_code_without_secret(...):        # RFC test 6
async def test_public_client_must_not_present_secret(...):              # RFC test 7
async def test_used_code_replay_revokes_family(...):
async def test_pkce_verifier_mismatch_rejected(...):
async def test_refresh_rotation_and_reuse_revokes_family(...):
async def test_id_token_includes_email_and_preferred_username(...):     # RFC test 14
async def test_id_token_echoes_nonce(...):
```
Each asserts concrete status codes, `error` values, and decoded JWT claims as in the Rust suite.

- [ ] **Step 2: Run — FAIL.** **Step 3: Implement.** **Step 4: Run — PASS.** **Step 5: Commit** — `git commit -m "feat(python): auth-code and refresh grants with family cascade"`

---

### Task 9: Introspection + revocation (RFC 7662 / 7009)

**Files:**
- Create: `src/oauth2_server/routes/introspect.py`
- Modify: `src/oauth2_server/app.py`
- Test: `tests/test_introspection.py`

**Interfaces:**
- Produces:
  - `POST /oauth/introspect` — requires client auth (unless a later `public_introspection` config, default off); unknown/expired/revoked token → `{"active": false}` (200, never 404); active JWT token → full response with `scope, client_id, username, token_type, exp, iat, nbf, sub, aud, jti, iss` where **`nbf == iat`** and `iss` = configured issuer; works for opaque tokens via storage lookup; a client can only introspect its own tokens (cross-client → `active: false`).
  - `POST /oauth/revoke` — client auth required; revokes access or refresh token; **cascades to the whole `token_family`** (RFC test 19); unknown token still returns 200 (RFC 7009 §2.2); a client cannot revoke another client's token (returns 200, token stays active — port the cross-client preservation test).

- [ ] **Step 1: Failing tests** — port `rfc7662_introspection_includes_nbf_jti_aud_iss`, `rfc7662_introspection_nbf_le_iat`, `revoke_cascades_to_entire_token_family`, plus cross-client isolation and inactive-token cases as concrete asserts.

- [ ] **Step 2: Run — FAIL.** **Step 3: Implement.** **Step 4: Run — PASS.** **Step 5: Commit** — `git commit -m "feat(python): introspection and revocation with family cascade"`

---

### Task 10: Discovery, JWKS, userinfo

**Files:**
- Create: `src/oauth2_server/routes/wellknown.py`
- Modify: `src/oauth2_server/app.py`
- Test: `tests/test_wellknown.py`

**Interfaces:**
- Produces:
  - `GET /.well-known/openid-configuration` and `GET /.well-known/oauth-authorization-server` — **byte-identical JSON** (same handler). Fields (port values from the Rust `wellknown.rs`): `issuer`, `authorization_endpoint`, `token_endpoint`, `introspection_endpoint`, `revocation_endpoint`, `userinfo_endpoint`, `jwks_uri`, `registration_endpoint`, `device_authorization_endpoint`, `grant_types_supported`, `response_types_supported: ["code"]`, `code_challenge_methods_supported: ["S256"]`, `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"]`, `authorization_response_iss_parameter_supported: true`, `prompt_values_supported`, `scopes_supported`, `subject_types_supported: ["public"]`, `id_token_signing_alg_values_supported`.
  - `GET /.well-known/jwks.json` — Phase 1 (HS256) returns `{"keys": []}` exactly as the Rust server does for symmetric keys; structure ready for RS256 in Phase 2.
  - `GET|POST /oauth/userinfo` — Bearer token from `Authorization` header **only** (reject token in query string); validates JWT (or looks up opaque token) and that the token row isn't revoked; returns `sub` always, `email` when `email` scope granted, `preferred_username` when `profile` scope granted — real values loaded from storage via `get_user_by_id`.

- [ ] **Step 1: Failing tests** — port RFC tests 8, 9, 12, 13, 20 (`rfc8414_*`, `userinfo_returns_real_*`, `discovery_includes_iss_parameter_supported`) plus query-string-token rejection and revoked-token rejection.

- [ ] **Step 2: Run — FAIL.** **Step 3: Implement.** **Step 4: Run — PASS.** **Step 5: Commit** — `git commit -m "feat(python): discovery, jwks, userinfo"`

---

### Task 11: Dynamic client registration (RFC 7591)

**Files:**
- Create: `src/oauth2_server/routes/register.py`
- Modify: `src/oauth2_server/app.py`
- Test: `tests/test_registration.py`

**Interfaces:**
- Produces: `POST /connect/register` — accepts `ClientRegistration`; validation ported from Rust: `redirect_uris` required and non-empty, `token_endpoint_auth_method` ∈ {basic, post, none}; **`none` + `client_credentials` grant → 400 `invalid_client_metadata`** (RFC test 11); public clients get `client_secret=None` and `client_secret_expires_at` omitted; response is `ClientRegistrationResponse` with 201, `registration_access_token`, `registration_client_uri`. (GET/PUT/DELETE `/connect/register/{client_id}` are Phase 2.)

- [ ] **Step 1: Failing tests** — port RFC tests 10 and 11 exactly:

```python
async def test_public_client_registration_with_none_auth_method_succeeds(client):
    resp = await client.post("/connect/register", json={
        "redirect_uris": ["https://app.example/cb"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"]})
    assert resp.status_code == 201
    assert resp.json().get("client_secret") in (None, "")


async def test_public_client_registration_with_client_credentials_is_rejected(client):
    resp = await client.post("/connect/register", json={
        "redirect_uris": ["https://app.example/cb"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["client_credentials"]})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"
```

- [ ] **Step 2–5:** FAIL → implement → PASS → `git commit -m "feat(python): dynamic client registration"`

---

### Task 12: Device flow (RFC 8628)

**Files:**
- Create: `src/oauth2_server/routes/device.py`
- Modify: `src/oauth2_server/routes/token.py` (add `urn:ietf:params:oauth:grant-type:device_code`), `wellknown.py` (advertise `device_authorization_endpoint`), `app.py`
- Test: `tests/test_device_flow.py`

**Interfaces:**
- Produces:
  - `POST /oauth/device_authorization` — client auth; returns `device_code` (43-char urlsafe), `user_code` (8 chars, `XXXX-XXXX`), `verification_uri`, `verification_uri_complete`, `expires_in` (600), `interval` (5).
  - `POST /oauth/device/verify` — session-authenticated user approves/denies by `user_code`.
  - Token endpoint device grant: pending → `authorization_pending`; denied → `access_denied`; expired → `expired_token`; approved → token issued once, second poll → `invalid_grant` (code marked used).

- [ ] **Step 1: Failing test** — port `device_flow_pending_then_approved_returns_token` end-to-end (request → poll pending → approve via storage/verify endpoint → poll success → assert token works → poll again fails) and `discovery_advertises_device_authorization_endpoint`.

- [ ] **Step 2–5:** FAIL → implement → PASS → `git commit -m "feat(python): RFC 8628 device authorization grant"`

---

### Task 13: Opaque access-token mode

**Files:**
- Modify: `src/oauth2_server/services/tokens.py`, `routes/introspect.py`, `routes/wellknown.py` (userinfo lookup path)
- Test: `tests/test_opaque_tokens.py`

**Interfaces:**
- Produces: with `Config(access_tokens_opaque=True)`, `issue()` emits `secrets.token_urlsafe(32)` instead of a JWT; introspection and userinfo resolve opaque tokens purely via `get_token_by_access_token` and still return full metadata (`iss`, `jti` = token row id, `nbf`/`iat` from `created_at`).

- [ ] **Step 1: Failing test** — port `opaque_access_tokens_issue_and_introspect_successfully`: issue under opaque config, assert token has no `.` separators / fails `jwt.get_unverified_header`, then introspect → `active: true` with correct `client_id`, `scope`, `iss`.

- [ ] **Step 2–5:** FAIL → implement → PASS → `git commit -m "feat(python): opaque access token mode"`

---

### Task 14: RFC compliance suite — the acceptance gate

**Files:**
- Create: `tests/test_rfc_compliance.py`
- Create: `scripts/gate.sh`

**Interfaces:**
- Consumes: everything above.
- Produces: one file mirroring `tests/rfc_compliance.rs` — same 20 test names (snake_case preserved), same assertions, so the two suites stay diffable. Tests 1–14 and 18–20 are implementable with Tasks 2–13. Tests 15–17 (`prompt_none_without_session_returns_login_required`, `prompt_login_forces_reauthentication`, `max_age_zero_forces_reauthentication`) require `prompt`/`max_age` handling — implement it here in `routes/authorize.py`: `prompt=none` + no session → redirect with `error=login_required`; `prompt=login` → treat as unauthenticated even with a session; `max_age=0` (or `auth_time` older than `max_age`) → force re-login. Test 18 (`logout_with_invalid_aud_id_token_hint_returns_error`) needs a minimal `GET /oauth/logout` that decodes `id_token_hint` and rejects an `aud` not matching a known client — implement that minimal handler; full logout UX stays Phase 2.

- [ ] **Step 1: Write all 20 tests** by translating each Rust test body: same setup (seed clients incl. a public PKCE client, issuer `https://auth.example.com`), same request sequence, same asserts. Mark none as skip — the suite must be green in full.

- [ ] **Step 2: Run: `uv run pytest tests/test_rfc_compliance.py -v`** — fix any gaps found (expect small ones in prompt/max_age/logout, added in this task).

- [ ] **Step 3: Add the gate script** `scripts/gate.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

- [ ] **Step 4: Full suite green** → `bash scripts/gate.sh` exits 0.

- [ ] **Step 5: Commit** — `git commit -m "test(python): port RFC compliance suite as acceptance gate"`

---

### Task 15: Performance hardening + parity smoke against shared Postgres

**Files:**
- Create: `scripts/bench.sh`, `docker-compose.dev.yml` (Postgres 16)
- Modify: `src/oauth2_server/__main__.py`
- Test: manual/scripted verification (not pytest)

**Interfaces:**
- Produces a runnable, tuned server and evidence of DB parity with the Rust server.

- [ ] **Step 1: Serving tuning** in `__main__.py`: `uvicorn.run("oauth2_server.app:build", factory=True, host=config.host, port=config.port, loop="uvloop", http="httptools", workers=os.cpu_count())`; `ORJSONResponse` already default; SQLAlchemy pool sized from `OAUTH2_DATABASE_*` envs (`pool_size=max_connections`, `pool_pre_ping=True`). Document `granian --interface asgi oauth2_server.app:build` as the alternative runner in `README.md`.

- [ ] **Step 2: Cross-server DB parity smoke** (the "same DB model" proof):
  1. `docker compose -f docker-compose.dev.yml up -d` (Postgres).
  2. Run the **Rust** server against it once so *its* migrator owns the schema.
  3. Start the Python server with the same `OAUTH2_DATABASE_URL` — migration runner must backfill (no DDL executed).
  4. Register a client via the Rust server; complete a `client_credentials` grant against the **Python** server with that client; introspect the Python-issued token via the **Rust** server. All three must succeed.
  Record the commands + output in `README.md`.

- [ ] **Step 3: Benchmark** `scripts/bench.sh`: `oha -z 30s -c 64` (or `wrk`) against `POST /oauth/token` (client_credentials) and `POST /oauth/introspect`; record baseline numbers in README. No target thresholds in Phase 1 — this establishes the baseline the distributed work (Phase 3) improves on.

- [ ] **Step 4: Commit** — `git commit -m "feat(python): tuned server entrypoint + cross-server parity smoke"`

---

## Self-Review (completed)

- **Spec coverage:** high-performance Python → Task 15 + stack choice; same DB model → Tasks 3 & 15 step 2; RFC tests as spec → Task 14 gate + per-task ported tests; no actors / distributed-ready → stateless services + shared-DB design throughout. Deferred items are named explicitly in Scope.
- **Placeholder scan:** Tasks 6–13 use "port test X exactly" with the Rust test named — the Rust source is the authoritative spec the executor must open; concrete code is given wherever the Python shape isn't a mechanical translation.
- **Type consistency:** `Storage` protocol names match between Tasks 3/6/8/9/12/13; `Claims.new(subject, client_id, scope, duration_seconds, issuer)` matches the Rust 5-arg signature; `TokenService.issue` signature used consistently in Tasks 6/8/12/13.
