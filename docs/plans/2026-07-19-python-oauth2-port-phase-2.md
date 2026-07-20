# Python OAuth2 Server Port — Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the Phase 1 review backlog (refresh expiry, migration race, session/argon2/typ hardening, grant/scope/prompt policy) and port the remaining Rust feature set: admin JSON API with RBAC, denylist + audit log, full OIDC RP-initiated logout (back/front-channel), PAR (RFC 9126), RS256 key rotation + JWKS, and login/device-verify UI parity.

**Architecture:** Same as Phase 1 — FastAPI app factory `create_app(config, storage)`, plain async services, `SqlStorage` over the vendored Rust migrations. Phase 2 adds: an `/admin/api/*` router guarded by a dual-mode (bearer/session) admin guard implemented as a dependency + custom exception handler; a global denylist ASGI middleware; in-process `RecentEventsStore`, `ParStore`, and `KeySet` singletons hung off `app.state` (mirroring the Rust server's in-memory actors — documented as single-process state); and an audit service that writes best-effort to the shared `audit_log` table.

**Tech Stack:** adds `cryptography>=43` (HKDF, RSA keygen, JWK derivation) and promotes `httpx` to a runtime dependency (back-channel logout delivery). Everything else unchanged.

## Global Constraints

- Schema is **owned by the Rust repo** — Phase 2 authors **zero** new migrations. `denylist`, `audit_log`, `signing_keys` tables already exist (V8/V17, vendored). The `signing_keys` table stays orphaned (the Rust server never reads it either); key rotation is in-memory with the same explicit warning string.
- Refresh-token expiry is computed as `created_at + refresh_token_ttl_secs` — **no new column**.
- Python `>=3.12`, all I/O async, TDD per task, `bash scripts/gate.sh` (ruff + ruff format + pytest) green at every commit.
- Reference sources: research digests in the session scratchpad (`research-*.md`) and the Rust repo at `~/Projects/rust-oauth2-server` — Rust tests named per task are the authoritative spec for ported asserts.
- Error-body conventions (from Rust): OAuth endpoints use `{"error": ..., "error_description": ...}`; admin not-found bodies are single-key `{"error": "client not found"}` etc.; admin pagination envelope is always `{"items": [...], "total": N, "limit": N, "offset": N}` with limit default 25 capped at 200, default sort `created_at DESC`.
- **Deliberate divergences from Rust (record in PHASE2-BACKLOG.md "Accepted divergences" when you land them):**
  1. `decode_access_token` keeps `verify_aud=False` and Python passes explicit audiences where needed — do **not** copy the Rust jsonwebtoken-v10 stateless-path `InvalidAudience` bug.
  2. Invalid/expired/wrong-iss `id_token_hint` on logout stays a 400 (`invalid_request` "invalid id_token_hint") — Rust silently ignores broken hints; strict is safer and pinned by the existing Phase 1 test.
  3. Admin token revoke by row id actually resolves the row and revokes it (Rust's is a silent no-op because it passes the row id to a value-matching UPDATE).
  4. DenylistGuard uses `request.client.host` only — no unconditional `X-Forwarded-For` trust (Rust trusts it, spoofably).
  5. PAR strips `client_secret`/`client_assertion`/`client_assertion_type` before storing the pushed params (Rust stores raw credentials in memory).
  6. `POST /oauth/device/verify` keeps its Phase 1 JSON responses; only the GET page is HTML (Rust returns HTML for both).
  7. Admin seeding only runs when `OAUTH2_SEED_PASSWORD` is explicitly set (Rust ships an insecure default rejected only in production mode).
  8. Discovery advertises `request_parameter_supported: false` (JAR is not ported; Rust has JAR and advertises true).
  9. Dashboard summary does not swallow storage errors into zeros; a broken backend 500s.

## Rust → Python map (Phase 2 additions)

| Rust | Python |
|---|---|
| `middleware/admin_guard.rs` | `src/oauth2_server/routes/admin/guard.py` |
| `handlers/admin.rs`, `admin_extra.rs` | `src/oauth2_server/routes/admin/{clients,users,tokens,devices,dashboard,denylist,audit}.py` |
| `handlers/admin_keys.rs` | `src/oauth2_server/routes/admin/keys.py` |
| `handlers/events.rs` + RecentEventsStore | `src/oauth2_server/services/events.py` + `routes/admin/events.py` |
| `middleware/denylist.rs` | `src/oauth2_server/middleware.py` (DenylistGuard) |
| `handlers/oidc_logout.rs` | `src/oauth2_server/routes/logout.py` (rewrite) |
| `handlers/session.rs` (check_session) | `src/oauth2_server/routes/logout.py` |
| `handlers/oauth.rs::par` + AuthActor par_store | `src/oauth2_server/routes/par.py` + `services/par.py` |
| `oauth2-core/src/models/key_set.rs` | `src/oauth2_server/keys.py` |
| `oauth2-core/src/models/{denylist,audit}.rs` | `src/oauth2_server/models.py` (extend) |
| `templates/login.html` | `src/oauth2_server/templates/login.html` (minimal vendored) |

---

### Task 1: Refresh-token expiry + ID-token re-mint on refresh

**Files:**
- Modify: `src/oauth2_server/routes/token.py` (refresh branch, ~lines 153–189), `src/oauth2_server/routes/introspect.py` (~lines 32–82)
- Test: `tests/test_token_endpoint.py`, `tests/test_introspection.py` (extend)

**Interfaces:**
- Consumes: `config.refresh_token_ttl_secs` (exists, currently dead — config.py:25), `old_token.created_at`.
- Produces: refresh grant rejects expired refresh tokens with `invalid_grant` "refresh token has expired"; refresh responses for `openid`-scoped tokens include a fresh `id_token`; introspection of a value matched via `refresh_token` reports `exp = created_at + refresh_token_ttl_secs`.

- [ ] **Step 1: Write failing tests**

In `tests/test_token_endpoint.py`:

```python
async def test_expired_refresh_token_rejected(client_app):
    resp, _ = await run_code_flow(client_app, scope="read")
    refresh = resp.json()["refresh_token"]
    # Age the token row past the refresh TTL directly in storage.
    row = await client_app.storage.get_token_by_refresh_token(refresh)
    aged = row.model_copy(update={
        "created_at": row.created_at - timedelta(seconds=86400 + 60)})
    await client_app.storage.revoke_token(row.access_token)
    await client_app.storage.save_token(aged.model_copy(update={
        "id": uuid.uuid4().hex, "access_token": "at-aged", "refresh_token": "rt-aged"}))
    resp2 = await post_token(client_app, {"grant_type": "refresh_token",
                                          "refresh_token": "rt-aged"},
                             basic_auth=("client1", "s3cret"))
    assert resp2.status_code == 400
    body = resp2.json()
    assert body["error"] == "invalid_grant"
    assert "expired" in body["error_description"]


async def test_refresh_reissues_id_token_for_openid_scope(client_app):
    resp, _ = await run_code_flow(client_app, scope="openid email")
    refresh = resp.json()["refresh_token"]
    resp2 = await post_token(client_app, {"grant_type": "refresh_token",
                                          "refresh_token": refresh},
                             basic_auth=("client1", "s3cret"))
    assert resp2.status_code == 200
    body = resp2.json()
    assert body.get("id_token")
    claims = jwt.decode(body["id_token"], options={"verify_signature": False})
    assert claims["sub"] == "u1"
    assert "nonce" not in claims          # OIDC Core §12.2: no nonce on refresh
    assert claims["aud"] == "client1"


async def test_refresh_without_openid_scope_has_no_id_token(client_app):
    resp, _ = await run_code_flow(client_app, scope="read")
    resp2 = await post_token(client_app, {"grant_type": "refresh_token",
                                          "refresh_token": resp.json()["refresh_token"]},
                             basic_auth=("client1", "s3cret"))
    assert resp2.json().get("id_token") is None
```

In `tests/test_introspection.py`:

```python
async def test_refresh_token_introspects_with_refresh_expiry(client_app):
    resp, _ = await run_code_flow(client_app, scope="read")
    body = resp.json()
    intro = await post_introspect(client_app, body["refresh_token"])
    data = intro.json()
    assert data["active"] is True
    # exp reflects the refresh TTL (86400), not the access TTL (3600).
    assert data["exp"] - data["iat"] > 3600
```
(If `post_introspect` doesn't exist yet in this file, add it mirroring `post_token` with the introspection endpoint.)

- [ ] **Step 2: Run — expect FAIL** (`uv run pytest tests/test_token_endpoint.py tests/test_introspection.py -v`)

- [ ] **Step 3: Implement**

In the refresh branch of `routes/token.py`, after the revoked check and before the scope check, insert:

```python
        refresh_deadline = old_token.created_at + timedelta(
            seconds=config.refresh_token_ttl_secs)
        if datetime.now(timezone.utc) >= refresh_deadline:
            return oauth_error("invalid_grant", "refresh token has expired")
```

After issuing the rotated pair, when `"openid"` is in the granted scope and `old_token.user_id` is set, mint an ID token exactly like the auth-code branch does (same `IdTokenClaims` + `encode_id_token` call) with these differences: no `nonce`, no `c_hash`, `at_hash` computed over the **new** access token, `email`/`preferred_username` per scope from `get_user_by_id(old_token.user_id)`. Extract the auth-code branch's id-token construction into a module-level helper `_mint_id_token(config, client, user, scope, access_token, *, nonce=None, code=None) -> str` and call it from both branches so the logic lives once.

In `routes/introspect.py`: the handler already tries `get_token_by_access_token` then `get_token_by_refresh_token`. Track *which* lookup matched; when the refresh lookup matched, compute expiry/activity from `row.created_at + timedelta(seconds=config.refresh_token_ttl_secs)` instead of `row.expires_at`, and set `exp` in the response from that deadline.

- [ ] **Step 4: Run — PASS**, then full suite (`uv run pytest`) — the existing rotation/reuse tests must stay green.

- [ ] **Step 5: Commit** — `git commit -m "feat(python): enforce refresh TTL, re-mint id_token on refresh"`

---

### Task 2: Migration advisory lock, lifespan startup, admin seeding

**Files:**
- Modify: `src/oauth2_server/storage/migrations.py`, `src/oauth2_server/app.py` (`build()`, ~lines 83–100), `src/oauth2_server/config.py`
- Create: `src/oauth2_server/bootstrap.py`
- Test: `tests/test_app.py`, `tests/test_storage.py` (extend)

**Interfaces:**
- Produces: `run_migrations` serializes concurrent runners on Postgres via `pg_advisory_xact_lock`; `build()` uses a lifespan context (no `@app.on_event`); `bootstrap.seed_admin_user(storage, config) -> bool` seeds an admin-role user from `OAUTH2_SEED_USERNAME`/`OAUTH2_SEED_PASSWORD`/`OAUTH2_SEED_EMAIL` only when the password is set and the username doesn't exist.
- New Config fields: `seed_username: str = "admin"`, `seed_password: str | None = None`, `seed_email: str = "admin@example.com"`.

- [ ] **Step 1: Failing tests**

```python
# tests/test_app.py
def test_build_uses_lifespan_not_on_event(monkeypatch):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", "unit-test-secret-not-for-production-0123456789abcdef")
    from oauth2_server.app import build
    app = build()
    assert app.router.on_startup == []       # deprecated hook list must be empty
    assert app.router.lifespan_context is not None


# tests/test_storage.py
async def test_seed_admin_user_creates_admin_once():
    from oauth2_server.bootstrap import seed_admin_user
    storage = await make_storage()
    config = Config(jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
                    issuer="https://auth.example.com",
                    seed_password="seed-password-123")
    assert await seed_admin_user(storage, config) is True
    user = await storage.get_user_by_username("admin")
    assert user is not None and user.role == "admin"
    assert user.password_hash.startswith("$argon2")
    assert await seed_admin_user(storage, config) is False   # idempotent


async def test_seed_admin_user_skipped_without_password():
    from oauth2_server.bootstrap import seed_admin_user
    storage = await make_storage()
    config = Config(jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
                    issuer="https://auth.example.com")
    assert await seed_admin_user(storage, config) is False
    assert await storage.get_user_by_username("admin") is None
```

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement**

`storage/migrations.py` — inside `run_migrations`, immediately after `async with engine.begin() as conn:` add:

```python
        if engine.dialect.name == "postgresql":
            # Serialize concurrent migrators (multi-worker startup) for the
            # duration of this transaction; released automatically at commit.
            await conn.execute(
                text("SELECT pg_advisory_xact_lock(:key)"), {"key": 961_748_927})
```

`bootstrap.py`:

```python
"""Startup seeding — port of the Rust server's OAUTH2_SEED_* admin bootstrap."""
import uuid

from oauth2_server.config import Config
from oauth2_server.models import User
from oauth2_server.security import hash_password_async
from oauth2_server.storage.base import Storage


async def seed_admin_user(storage: Storage, config: Config) -> bool:
    if not config.seed_password:
        return False
    if await storage.get_user_by_username(config.seed_username) is not None:
        return False
    await storage.save_user(User(
        id=uuid.uuid4().hex, username=config.seed_username,
        password_hash=await hash_password_async(config.seed_password),
        email=config.seed_email, role="admin"))
    return True
```
(`hash_password_async` lands in Task 3; until then call the sync `hash_password` and switch in Task 3 — or land Tasks 2 and 3 in either order and reconcile.)

`app.py` `build()`: replace the `@app.on_event("startup")` block with a lifespan:

```python
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await storage.init()
        await seed_admin_user(storage, config)
        yield

    app = create_app(config, storage, lifespan=lifespan)
```
`create_app` gains a keyword-only `lifespan=None` parameter forwarded to `FastAPI(...)`. The test path (`create_app` without lifespan) is unchanged.

- [ ] **Step 4: Run — PASS.** **Step 5: Commit** — `git commit -m "feat(python): migration advisory lock, lifespan startup, admin seeding"`

---

### Task 3: Session-key HKDF, async argon2, at+JWT typ enforcement

**Files:**
- Modify: `src/oauth2_server/security.py`, `src/oauth2_server/app.py` (SessionMiddleware, line ~61), `src/oauth2_server/routes/login.py` (line ~37), `pyproject.toml` (add `cryptography>=43`, promote `httpx>=0.27` to runtime deps)
- Test: `tests/test_security.py`, `tests/test_app.py` (extend)

**Interfaces:**
- Produces:
  - `derive_session_key(jwt_secret: str) -> str` — HKDF-SHA256, `info=b"oauth2-session-cookie"`, empty salt, 32 bytes, hex-encoded. Used as `SessionMiddleware(secret_key=...)`.
  - `verify_password_async(password, phc_hash) -> bool` and `hash_password_async(password) -> str` via `anyio.to_thread.run_sync`; login route awaits the former.
  - `decode_access_token` raises `jwt.InvalidTokenError` when the JOSE header `typ` is not `"at+JWT"` (RFC 9068 hardening) — an HS256 `id_token` signed with the same secret no longer decodes as an access token.

- [ ] **Step 1: Failing tests**

```python
# tests/test_security.py
def test_session_key_is_derived_not_verbatim():
    from oauth2_server.security import derive_session_key
    key = derive_session_key(SECRET)
    assert key != SECRET
    assert key == derive_session_key(SECRET)          # deterministic
    assert len(bytes.fromhex(key)) == 32


def test_id_token_rejected_as_access_token():
    from oauth2_server.security import encode_id_token
    from oauth2_server.models import IdTokenClaims
    now = int(datetime.now(timezone.utc).timestamp())
    idt = encode_id_token(IdTokenClaims(iss=ISS, sub="u1", aud="c1",
                                        exp=now + 600, iat=now), SECRET)
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(idt, SECRET, ISS)


async def test_verify_password_async_round_trip():
    from oauth2_server.security import hash_password_async, verify_password_async
    h = await hash_password_async("hunter2")
    assert await verify_password_async("hunter2", h)
    assert not await verify_password_async("wrong", h)
```

Also assert in `tests/test_app.py` that a full login still works end-to-end (existing `login_session` tests cover this — just keep them green).

- [ ] **Step 2: Run — FAIL.** **Step 3: Implement** (`derive_session_key` uses `cryptography.hazmat.primitives.kdf.hkdf.HKDF`; wire into `app.py`; `anyio.to_thread.run_sync(verify_password, password, phc_hash)`; typ check via `jwt.get_unverified_header(token).get("typ")` before `jwt.decode`). Check `routes/introspect.py`'s best-effort `decode_access_token` call still degrades gracefully (it is inside try/except — confirm).

- [ ] **Step 4: Run full suite — PASS.** **Step 5: Commit** — `git commit -m "fix(python): HKDF session key, async argon2, enforce at+JWT typ"`

---

### Task 4: Grant-type allow-list everywhere + unified scope policy

**Files:**
- Modify: `src/oauth2_server/routes/token.py`, `src/oauth2_server/routes/authorize.py`, `src/oauth2_server/routes/device.py`, `tests/helpers.py` (seed_client default grant_types gains the device grant)
- Test: `tests/test_token_endpoint.py`, `tests/test_authorize.py`, `tests/test_device_flow.py` (extend)

**Interfaces:**
- Produces: every token-endpoint branch (`authorization_code`, `refresh_token`, device) checks `grant_type in client.grant_type_list()` → 400 `unauthorized_client` "client is not authorized for this grant type" (same message the client_credentials branch already uses). `GET /oauth/authorize` rejects clients without `authorization_code` via an **error redirect** `unauthorized_client` (after redirect_uri validation). `POST /oauth/device_authorization` returns 400 `unauthorized_client` when the client lacks the device grant. `client_credentials` scope handling switches from silent intersection to `invalid_scope` rejection ("requested scope exceeds client scope") — matching the device branch's message.
- `seed_client` default `grant_types` becomes `["authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]` so existing flows stay green.

- [ ] **Step 1: Failing tests** — one per enforcement point:

```python
async def test_auth_code_grant_requires_allowlist(client_app):
    await reseed_client(client_app, grant_types=["client_credentials"])
    resp = await post_token(client_app, {"grant_type": "authorization_code",
                                         "code": "x", "redirect_uri": "https://a.example/cb"},
                            basic_auth=("client1", "s3cret"))
    assert (resp.status_code, resp.json()["error"]) == (400, "unauthorized_client")


async def test_refresh_grant_requires_allowlist(client_app): ...   # same shape
async def test_device_grant_requires_allowlist(client_app): ...    # token endpoint
async def test_device_authorization_requires_allowlist(client_app): ...  # /oauth/device_authorization
async def test_authorize_requires_authorization_code_grant(app_with_session):
    # client with grant_types=["client_credentials"] -> 302 error redirect
    # with error=unauthorized_client (state echoed, iss present)
    ...
async def test_client_credentials_excess_scope_rejected(client_app):
    resp = await post_token(client_app, {"grant_type": "client_credentials",
                                         "scope": "read admin:everything"},
                            basic_auth=("client1", "s3cret"))
    assert (resp.status_code, resp.json()["error"]) == (400, "invalid_scope")
```
Add a `reseed_client(client_app, **overrides)` helper to `tests/helpers.py` that deletes + re-saves `client1` with overrides. Update/remove any Phase 1 test that asserted silent intersection for client_credentials.

- [ ] **Step 2: FAIL.** **Step 3: Implement** — hoist a shared check at the top of each branch; in `authorize.py` place the check right after redirect_uri validation so the error is a safe redirect. **Step 4: Full suite PASS.** **Step 5: Commit** — `git commit -m "fix(python): enforce grant-type allow-list on all grants; unified invalid_scope policy"`

---

### Task 5: prompt=none correctness (OIDC Core §3.1.2.6)

**Files:**
- Modify: `src/oauth2_server/routes/authorize.py` (lines ~144–184)
- Test: `tests/test_rfc_compliance.py` (extend)

**Interfaces:**
- Produces: `prompt=none` combined with any other prompt value → error redirect `invalid_request` "prompt=none cannot be combined with other values". `prompt=none` with a session whose `max_age` has expired (e.g. `max_age=0`) → error redirect `error=login_required` — never the login UI.

- [ ] **Step 1: Failing tests**

```python
async def test_prompt_none_with_expired_max_age_returns_login_required(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get("/oauth/authorize", params={
        "response_type": "code", "client_id": "client1",
        "redirect_uri": "https://a.example/cb", "scope": "read",
        "prompt": "none", "max_age": "0", "state": "s1"})
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["login_required"]
    assert q["state"] == ["s1"]
    assert resp.headers["location"].startswith("https://a.example/cb")


async def test_prompt_none_combined_with_login_is_invalid_request(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get("/oauth/authorize", params={
        "response_type": "code", "client_id": "client1",
        "redirect_uri": "https://a.example/cb", "scope": "read",
        "prompt": "none login"})
    assert resp.status_code == 302
    q = parse_qs(parse := urlparse(resp.headers["location"]).query)
    assert q["error"] == ["invalid_request"]
```

- [ ] **Step 2: FAIL.** **Step 3: Implement** — after parsing prompt values: reject `none`+others; move the `login_required` check so it covers `user_id is None or force_login or auth_expired` whenever `"none" in prompt_values`. **Step 4: PASS (whole suite).** **Step 5: Commit** — `git commit -m "fix(python): prompt=none returns login_required/invalid_request instead of login UI"`

---

### Task 6: Admin domain models + storage expansion + cleanup

**Files:**
- Modify: `src/oauth2_server/models.py`, `src/oauth2_server/storage/base.py`, `src/oauth2_server/storage/sql.py`
- Create: `src/oauth2_server/storage/paging.py`
- Test: `tests/test_admin_storage.py` (new), `tests/test_storage.py`

**Interfaces (produced — later tasks depend on these exact names):**
- Models: `DenylistEntry(id, kind, value, reason="", created_by="", created_at, expires_at: datetime | None = None)` with `is_active() -> bool`; `AuditLogEntry(id, actor_id="", actor_email="", action, target_kind="", target_id="", ip="", user_agent="", metadata="", created_at)`.
- `paging.py`: `ListQuery(limit: int | None, offset: int = 0, sort_by: str | None, sort_dir: str = "desc", search: str | None, status: str | None)` with `effective_limit() -> int` (default 25, cap 200); `page_envelope(items: list, total: int, limit: int, offset: int) -> dict` returning `{"items", "total", "limit", "offset"}`; `whitelist_col(requested, allowed: list[str]) -> str` (unknown/absent → last element).
- New `SqlStorage`/Protocol methods (SQL behavior from the Rust `sqlx.rs`, adapted to the shared schema):
  - `list_all_clients()`, `list_all_users()`, `list_all_tokens()` (ORDER BY created_at DESC **LIMIT 200**, Rust parity), `list_all_device_authorizations()` (LIMIT 500)
  - `list_clients_page(q)` (search LOWER name/client_id; sort whitelist `["name","client_id","created_at"]`), `list_users_page(q)` (`["username","email","role","created_at"]`), `list_tokens_page(q)` (`["client_id","user_id","scope","expires_at","created_at"]`; status filter active/revoked/expired), `list_device_authorizations_page(q)` — each returns `(items, total)`
  - `update_user(user)`, `delete_user(user_id)` (revokes + NULLs `user_id` on the user's tokens, then deletes the row), `set_user_enabled(user_id, enabled)`, `set_user_role(user_id, role)`, `set_user_password_hash(user_id, password_hash)`
  - `set_client_enabled(client_id, enabled)`, `set_client_secret(client_id, client_secret)`
  - `revoke_tokens_by_user_id(user_id) -> int`, `revoke_tokens_by_client_id(client_id) -> int` (both `AND revoked = false`, returning rowcount — idempotent)
  - `add_denylist_entry(entry)` (`ON CONFLICT(kind, value) DO UPDATE SET reason, created_by, expires_at` — original id survives), `remove_denylist_entry(id)`, `list_denylist(q) -> (items, total)` (expired rows included), `find_denylist_entry(kind, value) -> DenylistEntry | None` (returns only active entries — expiry filtered in Python via `is_active()`, Rust parity)
  - `write_audit_log(entry)`, `list_audit_log(q) -> (items, total)` (sort whitelist `["actor_id","action","target_kind","created_at"]`, default created_at DESC)
- Cleanup: `expire_device_authorization(device_code)` now writes `now − 1s` using the dialect-aware `_dump` conversion (works on asyncpg); `set_token_family` is **deleted** from Protocol and impl (dead code).

- [ ] **Step 1: Failing tests** — port the Rust `tests/admin_storage_contract.rs` suite one-for-one into `tests/test_admin_storage.py` (test names: `test_update_user_persists_changes`, `test_set_user_enabled_flips_flag`, `test_set_user_role_updates_row`, `test_set_user_password_hash_replaces_hash`, `test_delete_user_removes_row_and_nulls_token_references`, `test_set_client_enabled_persists`, `test_set_client_secret_replaces_secret`, `test_denylist_add_find_remove_round_trip`, `test_denylist_upsert_on_duplicate_kind_value`, `test_denylist_list_is_paginated` (12 entries → 5/0 and 5/10 slices), `test_denylist_find_skips_expired_entries`, `test_audit_log_write_and_list_newest_first`, `test_audit_log_respects_limit_offset` (7 entries, limit=2 offset=2), `test_revoke_tokens_by_client_id_only_touches_that_client`, `test_revoke_tokens_by_client_id_idempotent`) — each driving `SqlStorage` directly via `make_storage()`. Add to `tests/test_storage.py`: `test_expire_device_authorization_expires_row` (save a device auth, expire it, reload → `expires_at < now`).

- [ ] **Step 2: FAIL.** **Step 3: Implement** models + paging + SQL methods following the existing `sql.py` `text()` idiom; every dynamic column name must pass through `whitelist_col` (never interpolate user input). **Step 4: PASS + full suite** (removal of `set_token_family` must not break anything — it has zero callers). **Step 5: Commit** — `git commit -m "feat(python): admin storage layer (paging, denylist, audit, user/client admin ops)"`

---

### Task 7: Admin guard (RBAC) + audit/events infrastructure

**Files:**
- Create: `src/oauth2_server/routes/admin/__init__.py`, `src/oauth2_server/routes/admin/guard.py`, `src/oauth2_server/services/audit.py`, `src/oauth2_server/services/events.py`
- Modify: `src/oauth2_server/config.py`, `src/oauth2_server/sessions.py`, `src/oauth2_server/routes/login.py`, `src/oauth2_server/app.py`
- Test: `tests/test_admin_rbac.py` (new)

**Interfaces:**
- Config: `admin_client_ids: list[str] = []` (env `OAUTH2_ADMIN_CLIENT_IDS`, comma-split like `allowed_origins`), `admin_emails: list[str] = []` (env `OAUTH2_ADMIN_EMAILS`, lowercased on validation).
- `sessions.set_login(request, user)` now stores `user_id`, `auth_time`, `role`, `email`, `username` (signature changes from `set_login(request, user_id)` to take the `User` — update `routes/login.py` caller).
- `guard.py`:
  - `class AdminActor: actor_id: str; actor_email: str` (dataclass; empty strings for bearer callers — Rust parity).
  - `class AdminAuthError(Exception)` carrying a prebuilt `Response`.
  - `async def require_admin(request: Request) -> AdminActor` — FastAPI dependency. Bearer header present → validate first: unknown/revoked/expired token → 401 `{"error":"invalid_token","error_description":"Bearer token is invalid or expired"}`; valid but `"admin"` not in scope-split or `client_id` not in `config.admin_client_ids` (empty list = deny all, fail-closed) → 403 `{"error":"insufficient_scope","error_description":"Token requires 'admin' scope"}` / 403. No bearer → session: no `user_id` → **302** redirect `Location: /auth/login?error=login_required` (Rust-pinned, even for API paths); authenticated but not admin (`role != "admin"` and lowercased email not in `admin_emails`) → 403 `{"error":"insufficient_permissions","error_description":"Admin access required"}`.
  - `client_id_in_allowlist(client_id: str, allowlist: list[str]) -> bool` — exact trimmed match, empty allowlist denies (unit-tested).
- `create_app` registers an exception handler for `AdminAuthError` returning `exc.response`.
- `services/events.py`: `class RecentEventsStore(capacity=500)` — `push(event: dict)`, `list(limit, offset) -> (items, total)` newest-first. Instance at `app.state.events`.
- `services/audit.py`:
  - `def build_audit(request, actor: AdminActor, action: str, target_kind: str, target_id: str, metadata: dict) -> AuditLogEntry` (ip from `request.client.host`, user_agent header, `metadata=json.dumps(metadata)`).
  - `async def record_audit(storage, events: RecentEventsStore, entry: AuditLogEntry) -> None` — `write_audit_log` wrapped in try/except (log only, never raise), then `events.push({"event_type": entry.action, "source": "admin", "idempotency_key": entry.id, "received_at": ..., "actor_id", "actor_email", "target_kind", "target_id", "metadata": <parsed object>})`.
- `routes/admin/__init__.py` exposes `admin_router = APIRouter(prefix="/admin/api", dependencies=[Depends(require_admin)])`; app mounts it. (Sub-routers from Tasks 8–10, 13 attach here.)

- [ ] **Step 1: Failing tests** — port from Rust `tests/admin_rbac.rs` + guard unit tests: `test_unauthenticated_admin_api_redirects_to_login` (302, Location contains `/auth/login?error=login_required`), `test_plain_user_session_gets_403` (`insufficient_permissions`), `test_admin_session_passes` (login as seeded admin user → any admin GET returns 200; seed an admin user via storage + `login_session`), `test_admin_email_allowlist_grants_admin` (role=user but email in `admin_emails`), `test_bearer_without_admin_scope_403` (`insufficient_scope`), `test_bearer_with_admin_scope_and_allowlist_passes`, `test_bearer_admin_scope_non_allowlisted_client_403`, `test_invalid_bearer_401` (`invalid_token`), `test_allowlist_exact_trimmed_match` (unit: `""`/`"   "` deny; `" other , mcp "` matches `"mcp"`; `"mcp_evil"` doesn't). Use a placeholder admin endpoint for this task: add `GET /admin/api/ping` → `{"ok": true}` inside the router (replaced organically as real endpoints land). Fixture: extend `tests/conftest.py` `build_client_app` to accept `config_overrides` for `admin_client_ids`/`admin_emails`, and add helpers `seed_admin(storage)` + `login_admin(client)` to `tests/helpers.py`.

- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): admin guard (session+bearer RBAC), audit service, recent-events store"`

---

### Task 8: Admin API — clients + users CRUD

**Files:**
- Create: `src/oauth2_server/routes/admin/clients.py`, `src/oauth2_server/routes/admin/users.py`
- Modify: `src/oauth2_server/routes/admin/__init__.py`
- Test: `tests/test_admin_clients.py`, `tests/test_admin_users.py` (new)

**Interfaces (contract from Rust `admin.rs`/`admin_extra.rs` — see research digest; all under `/admin/api`):**
- Clients: `GET /clients` (Page of ClientInfo — `grant_types`/`redirect_uris` as **raw stored JSON strings**), `POST /clients` (CreateClientRequest; empty name → 400 `invalid_request` "name is required"; auto `client_id` `"client-"+uuid4().hex[:12]`; public iff auth method `"none"`; secret default `uuid4().hex` 32 chars; grant_types default `["authorization_code","refresh_token"]`; 201 body returns **arrays** + secret exactly once, `None` for public; audits `client.create`), `GET /clients/{id}` (internal-uuid lookup via `list_all_clients` scan; 404 `{"error":"client not found"}`; ClientDetail with raw-string list fields), `PUT /clients/{id}` (partial update, arrays re-serialized to JSON strings; 200 partial echo `{id, client_id, name, enabled, updated_at}`; audits `client.update`), `DELETE /clients/{id}` (resolve uuid→client_id, 200 `{"message":"Client deleted"}`; **also audits `client.delete`** — divergence: Rust forgot), `POST /clients/{id}/enabled` (`{"enabled": bool}` → 200 echo; disable best-effort `revoke_tokens_by_client_id`; audits `client.enable`/`client.disable`), `POST /clients/{id}/regenerate-secret` (public → 400 "public clients have no secret"; 200 `{client_id, client_secret}`; audits `client.regenerate_secret`).
- Users: `GET /users` (Page of UserInfo `{id, username, email, role, enabled, created_at}`), `POST /users` (username/email/password required → 400 "username, email, password are required"; duplicate username → 409 `{"error":"already_exists","error_description":"username already registered"}`; role only admin|user else silently "user"; argon2 via `hash_password_async`; 201 UserResponse incl. `updated_at`; audits `user.create`), `GET /users/{id}` (404 `{"error":"user not found"}`), `PUT /users/{id}` (email/role/enabled optional; invalid role silently ignored; 404; 200 UserResponse; audits `user.update`), `DELETE /users/{id}` (404 if absent; delete + revoke; 200 `{"message":"User deleted"}`; audits `user.delete`), `POST /users/{id}/enabled` (200 echo, no 404; disable revokes; audits), `POST /users/{id}/role` (not admin|user → 400 "role must be 'admin' or 'user'"; 200 echo, no 404; audits `user.set_role`), `POST /users/{id}/password` (<8 chars → 400 `{"error":"weak_password","error_description":"password must be at least 8 characters"}`; hash + `set_user_password_hash` + revoke; 200 `{"message":"Password reset"}`; audits `user.reset_password`).
- All timestamps RFC3339 (`datetime.isoformat()` on tz-aware values is fine).

- [ ] **Step 1: Failing tests** — port from `admin_paging.rs`/`admin_extra.rs`: pagination envelope (15 clients limit=5), last-page remainder, search filter, empty list, client detail + 404, create confidential (secret once, `client-` prefix) / public (no secret) / empty-name 400, update mutates + reload, enable toggles + token revoked, regenerate-secret (public 400 / replaces), user create (hash `$argon2`, dup 409, missing-fields 400), user update (patch email+role, invalid role ignored, ghost 404), delete (row gone + token revoked), enabled toggle, role 400 on invalid, weak password 400, reset revokes tokens, and `test_admin_mutation_writes_audit_entry` (user.create appears in `list_audit_log` with actor_email from session, metadata containing username) + `test_admin_mutation_fans_out_to_events` (`app.state.events` contains the envelope with parsed metadata).

- [ ] **Step 2: FAIL.** **Step 3: Implement** both routers (each handler: resolve → mutate → `record_audit`). **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): admin clients + users CRUD with audit trail"`

---

### Task 9: Admin API — tokens, devices, dashboard, capabilities, events

**Files:**
- Create: `src/oauth2_server/routes/admin/tokens.py`, `src/oauth2_server/routes/admin/devices.py`, `src/oauth2_server/routes/admin/dashboard.py`, `src/oauth2_server/routes/admin/events.py`
- Test: `tests/test_admin_tokens.py`, `tests/test_admin_misc.py` (new)

**Interfaces:**
- `GET /tokens` (Page of TokenInfo `{id, client_id, user_id ("" when null), scope, expires_at, created_at, revoked, expired}`; status filter; never exposes token values), `GET /tokens/{id}` (scan `list_all_tokens`; 404 `{"error":"token not found"}`), `POST /tokens/{id}/revoke` (resolve row by id in `list_all_tokens`, then `revoke_token(row.access_token)`; unknown id still 200 `{"message":"Token revoked"}` — divergence 3: we actually revoke), `POST /tokens/revoke-by-user` (`{"user_id"}` → 200 `{"revoked": N}`; audits `token.bulk_revoke_by_user` with metadata `{"revoked": N}`), `POST /tokens/revoke-by-client` (same by client).
- `GET /device` (Page of DeviceInfo `{id, device_code, user_code, client_id, scope, created_at, expires_at, approved, denied, used, expired, user_id}`), `POST /device/{code}/expire` (calls the fixed `expire_device_authorization`; always 200 `{"message":"Device code expired"}`).
- `GET /dashboard` — `{total_clients, public_clients, confidential_clients, total_users, enabled_users, total_tokens, active_tokens, revoked_tokens, expired_tokens, pending_device_codes}` computed from the `list_all_*` methods (active = not revoked and not expired; pending = not approved/denied/expired).
- `GET /capabilities` — static `{"events": true, "device_flow": true, "key_rotation": true, "user_crud": true, "client_crud": true, "denylist": true, "audit_log": true, "bulk_revoke": true}`.
- `GET /events/recent` — Page envelope over `app.state.events`.

- [ ] **Step 1: Failing tests** — token list + status filter, token detail 404, revoke-by-row-id actually revokes (introspection flips inactive), bulk revoke counts + idempotency + isolation (c1 vs c2), device list shape, device expire → subsequent device-grant poll returns `expired_token`, dashboard counts (2 clients + 1 user seeded), capabilities all-true, events/recent returns pushed envelopes newest-first.

- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): admin tokens/devices/dashboard/capabilities/events endpoints"`

---

### Task 10: Denylist + audit endpoints + DenylistGuard middleware

**Files:**
- Create: `src/oauth2_server/routes/admin/denylist.py`, `src/oauth2_server/routes/admin/audit.py`, `src/oauth2_server/middleware.py`
- Modify: `src/oauth2_server/app.py` (mount DenylistGuard)
- Test: `tests/test_admin_denylist.py`, `tests/test_denylist_middleware.py` (new)

**Interfaces:**
- `GET /admin/api/denylist` (Page of DenylistResponse `{id, kind, value, reason, created_by, created_at, expires_at (nullable), active}` — active computed via `is_active()`; expired rows listed), `POST /admin/api/denylist` (kind lowercased, must be in `{"ip","user_id","username","email","client_id"}` else 400 "kind must be one of: ip, user_id, username, email, client_id"; blank value → 400 "value is required"; value trimmed; `created_by` = session email (empty for bearer); upsert; 201; audits `denylist.add` metadata `{kind, value, reason}`), `DELETE /admin/api/denylist/{id}` (200 `{"message":"Denylist entry removed"}` even for ghosts; audits `denylist.remove`).
- `GET /admin/api/audit` — Page of AuditLogResponse (metadata stays a JSON **string** — Rust parity; `/events/recent` has the parsed-object variant).
- `middleware.py`: `DenylistGuard` (pure ASGI or BaseHTTPMiddleware): every HTTP request → `find_denylist_entry("ip", request.client.host)`; active hit → 403 `{"error":"access_denied","error_description":"request source is denylisted"}`; any storage exception or missing client → pass through (fail-open, Rust parity). Mounted in `create_app` for all routes.
- `check_subject_denylisted(storage, kind, value) -> str | None` helper in `middleware.py` (empty value → None; storage errors → None) — defined + tested but not wired into handlers (Rust parity; wiring is a Phase 3 decision).

- [ ] **Step 1: Failing tests** — HTTP round trips (add→list echoes kind/value/active, unknown kind 400, upsert duplicate keeps total==1 + updated reason, remove clears), audit list paginated newest-first (limit=3 of 5), middleware blocks a denylisted IP (httpx ASGITransport `client=("198.51.100.5", 123)` constructor arg sets `request.client.host`) with 403 `access_denied`, allows unlisted, honors expired entries, `check_subject_denylisted` returns reason / None / None-for-empty.

- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS (full suite — middleware must not break existing tests; sqlite in-memory storage is on `app.state`).** **Step 5: Commit** — `git commit -m "feat(python): denylist + audit admin endpoints, global IP denylist middleware"`

---

### Task 11: OIDC RP-initiated logout — full port

**Files:**
- Modify: `src/oauth2_server/routes/logout.py` (rewrite), `src/oauth2_server/routes/register.py` + `src/oauth2_server/models.py` (registration accepts/echoes logout fields), `src/oauth2_server/routes/wellknown.py` (discovery fields), `src/oauth2_server/app.py` (`app.state.http_client = httpx.AsyncClient(timeout=10)` created in create_app / closed in lifespan)
- Test: `tests/test_logout.py` (new), `tests/test_registration.py`, `tests/test_wellknown.py` (extend)

**Interfaces:**
- `GET /oauth/logout` (GET only, Rust parity) with optional `id_token_hint`, `post_logout_redirect_uri`, `state`, `sid`. Flow:
  1. `id_token_hint` present → decode with alg pinned from header (HS256→`jwt_secret`; RS256→`config.id_token_private_key_pem`-derived public key **once Task 13 lands** — until then HS256 only), `verify_exp` on, issuer validated. Invalid → **400** `invalid_request` "invalid id_token_hint" (divergence 2 — stricter than Rust). Valid → each `aud` checked via `get_client`; none registered → 400 "id_token_hint aud does not match a registered client" (existing message, keep). Valid + `sub` → best-effort `await storage.revoke_tokens_by_user_id(sub)`.
  2. `request.session.clear()` always.
  3. Back-channel: for every client from `list_all_clients()` with non-empty `backchannel_logout_uri`, build `logout_token` — HS256(`jwt_secret`), header `typ="logout+JWT"`, claims `iss`, `aud=client_id`, `iat`, `exp=iat+120`, `jti=uuid4().hex`, `events={"http://schemas.openid.net/event/backchannel-logout": {}}`, `sub` (when known), `sid` only when `client.backchannel_logout_session_required` and sid present; skip entirely when neither sub nor sid. POST `logout_token=<jwt>` form-encoded via `request.app.state.http_client`, all exceptions swallowed.
  4. Front-channel: if any client has `frontchannel_logout_uri` → 200 HTML page with one hidden sandboxed iframe per such client (`?iss=<issuer>` + `&sid=` when required+present) and, when a validated redirect exists, a `setTimeout` JS redirect whose URL is `json.dumps(url).replace("<", "\\u003c").replace("/", "\\/")` (XSS breakout defense, unit-tested).
  5. `post_logout_redirect_uri` validation chain (exact messages): parse failure → 400 "Invalid post_logout_redirect_uri"; non-http(s) → "post_logout_redirect_uri must use http or https"; fragment → "post_logout_redirect_uri must not contain a fragment"; not an exact member of any client's `post_logout_redirect_uris` JSON list nor any client's `redirect_uris` → "Unregistered post_logout_redirect_uri". Valid → 302 with `state` appended as an encoded query pair (exact-Location test).
  6. No redirect → 200 `{"status": "logged_out"}`.
- `GET /oauth/check_session` → 200 `text/html` containing the OIDC Session Management postMessage/SHA-256 verifier script (port the Rust page's script verbatim in spirit; body must contain `postMessage` and `SHA-256`).
- `Client.get_post_logout_redirect_uris()` helper on the model (JSON-array-string parse, `[]` on failure).
- Registration: `ClientRegistration` gains `backchannel_logout_uri`, `backchannel_logout_session_required`, `frontchannel_logout_uri`, `frontchannel_logout_session_required`, `post_logout_redirect_uris: list[str]`; persisted onto the Client row; 201 response echoes them.
- Discovery adds: `end_session_endpoint`, `check_session_iframe`, `backchannel_logout_supported: true`, `backchannel_logout_session_supported: true`, `frontchannel_logout_supported: true`, `frontchannel_logout_session_supported: true`.

- [ ] **Step 1: Failing tests** — port (names preserved): `test_simple_logout_returns_ok` (200 `{"status":"logged_out"}`), `test_logout_accepts_registered_post_logout_redirect_uri` (302, Location startswith), `test_logout_redirects_with_exact_state` (Location == `https://app.example.com/logged-out?state=xyz`, exercising the `redirect_uris` fallback with empty `post_logout_redirect_uris`), `test_logout_rejects_unregistered_post_logout_redirect_uri` (400 `invalid_request`), `test_logout_renders_frontchannel_iframes` (200, body contains `<iframe`, the uri, `iss=`), `test_backchannel_logout_posts_valid_token` (swap `app.state.http_client` for one built on `httpx.MockTransport` capturing the request; assert form body starts `logout_token=`, header typ `logout+JWT`, claims iss/aud/iat/exp/jti/events/sub), `test_valid_hint_revokes_users_tokens` (tokens introspect inactive after logout), `test_client_registration_includes_logout_fields` (201 echo), `test_check_session_iframe_returns_html`, `test_discovery_includes_session_management_fields`, XSS units `test_frontchannel_redirect_url_is_json_encoded` / `test_no_redirect_script_when_absent`. Keep existing `test_logout_with_invalid_aud_id_token_hint_returns_error` green.

- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): full OIDC RP-initiated logout with back/front-channel"`

---

### Task 12: PAR (RFC 9126)

**Files:**
- Create: `src/oauth2_server/services/par.py`, `src/oauth2_server/routes/par.py`
- Modify: `src/oauth2_server/routes/authorize.py` (request_uri consumption at top), `src/oauth2_server/routes/wellknown.py`, `src/oauth2_server/app.py` (`app.state.par_store = ParStore()`, mount router)
- Test: `tests/test_par.py` (new), `tests/test_wellknown.py` (extend)

**Interfaces:**
- `services/par.py`:
```python
PAR_TTL_SECS = 60

@dataclass
class ParEntry:
    client_id: str
    params: dict[str, str]
    created_at: float          # time.monotonic()

class ParStore:
    def store(self, client_id: str, params: dict[str, str]) -> str:
        """Sweep expired, insert, return 'urn:ietf:params:oauth:request-uri:<uuid4>'."""
    def take(self, request_uri: str) -> ParEntry | None:
        """Sweep expired, then destructively pop (single-use)."""
```
  Single-process only — document in the module docstring (Rust parity; the Rust store is an in-actor HashMap).
- `POST /oauth/par`: parse the **raw body** with `urllib.parse.parse_qsl` (`request.body()`), then in order: undecodable body → 400 `invalid_request` "Invalid PAR request body encoding"; duplicate key → 400 "Duplicate parameter in PAR request"; missing `client_id` → 400 "Missing client_id in PAR request"; missing `response_type` → 400 "Missing response_type in PAR request"; client auth via the existing `ClientService.authenticate` (Basic wins over body; public clients pass with bare client_id; failures → its usual 401 `invalid_client`). Strip `client_secret`/`client_assertion`/`client_assertion_type` from the stored params (divergence 5). Success: **201** `{"request_uri": ..., "expires_in": 60}` with `Cache-Control: no-store`.
- `GET /oauth/authorize`: when `request_uri` is present (before client/redirect validation): `entry = app.state.par_store.take(request_uri)`; `None` → 400 JSON `{"error":"invalid_request","error_description":"Unknown or expired request_uri"}` (never a redirect); `entry.client_id != client_id` → **401** `{"error":"invalid_client","error_description":"request_uri client_id mismatch"}` (entry already consumed — Rust parity). Merge with PAR precedence for exactly: `redirect_uri, scope, code_challenge, code_challenge_method, nonce, resource, state, authorization_details, claims, acr_values`. `client_id` and `response_type` always come from the query string.
- Discovery adds: `pushed_authorization_request_endpoint: {issuer}/oauth/par`, `require_pushed_authorization_requests: false`, `request_uri_parameter_supported: true`, `request_parameter_supported: false` (divergence 8).

- [ ] **Step 1: Failing tests** — port the five `compliance_wave3.rs` tests by name (`test_rfc9126_par_public_client_returns_request_uri` — 201, urn prefix, expires_in==60; `..._missing_response_type_is_rejected`; `..._duplicate_param_is_rejected` (raw body `"client_id=client1&response_type=code&scope=read&scope=write"` via `content=`); `..._confidential_client_no_secret_rejected` (401); `..._confidential_client_with_basic_auth_succeeds`) **plus** the authorize-side coverage Rust lacks: `test_par_request_uri_full_flow` (push with PKCE params → GET authorize with only `request_uri`+`client_id`+`response_type` while logged in → 302 with code; token exchange succeeds using the pushed challenge's verifier), `test_par_request_uri_is_single_use` (second authorize → 400 "Unknown or expired request_uri"), `test_par_request_uri_client_mismatch_consumes_entry` (wrong client_id → 401; correct client afterwards → 400), `test_par_request_uri_expires` (monkeypatch `time.monotonic` forward 61s), `test_discovery_advertises_par`.

- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 9126 pushed authorization requests"`

---

### Task 13: RS256 signing, key rotation, JWKS

**Files:**
- Create: `src/oauth2_server/keys.py`, `src/oauth2_server/routes/admin/keys.py`
- Modify: `src/oauth2_server/security.py`, `src/oauth2_server/services/tokens.py`, `src/oauth2_server/routes/token.py` (id_token path), `src/oauth2_server/routes/wellknown.py` (jwks + discovery), `src/oauth2_server/config.py`, `src/oauth2_server/app.py`
- Test: `tests/test_keys.py`, `tests/test_jwks_rs256.py` (new)

**Interfaces:**
- Config: `id_token_private_key_pem: str | None` (env `OAUTH2_ID_TOKEN_PRIVATE_KEY_PEM`, apply `.replace("\\n", "\n")` in a validator), `id_token_kid: str | None` (env `OAUTH2_ID_TOKEN_KID`), `id_token_alg: str` (env `OAUTH2_ID_TOKEN_ALG`; default `"RS256"` when the PEM is set else `"HS256"` — model_validator), `key_rotation_grace_hours: int = 24`.
- `keys.py` (port of `key_set.rs`):
```python
class SigningKey(BaseModel):
    kid: str
    algorithm: str                      # "HS256" | "RS256"
    key_material: bytes                 # HS256: secret bytes; RS256: PKCS#8 PEM bytes
    is_current: bool = True
    created_at: datetime
    expires_at: datetime | None = None
    def is_active(self) -> bool: ...

class KeySet:
    def current_for_alg(self, alg: str) -> SigningKey | None
    def find(self, kid: str) -> SigningKey | None       # active keys only
    def active_keys(self) -> list[SigningKey]
    def add(self, key: SigningKey) -> None
    def rotate(self, new_key: SigningKey, grace_secs: int) -> None
    def prune_expired(self) -> list[str]

def generate_signing_key(algorithm: str, kid: str) -> SigningKey
    # HS256: secrets.token_bytes(48); RS256: cryptography 2048-bit PKCS#8 PEM
def jwk_from_rs256_key(key: SigningKey) -> dict
    # {"kid","kty":"RSA","use":"sig","alg":"RS256","n","e"} — base64url no-pad big-endian
def seed_keyset(config) -> KeySet
    # always HS256 kid="hs256-initial" from jwt_secret; plus RS256
    # kid=config.id_token_kid or "rs256-initial" when the PEM is set
```
- `security.py`: `encode_access_token(claims, secret, *, key: SigningKey | None = None)` — with a key, sign with its alg/material and set header `kid` + `typ="at+JWT"`; without, legacy HS256 path. `decode_access_token(token, secret, issuer, *, keyset: KeySet | None = None)` — header `kid` found in keyset → verify with that key (alg from the key); else HS256 fallback; typ check from Task 3 retained; `verify_aud=False` (divergence 1). `encode_id_token(claims, secret, *, config)` signs RS256 with the config PEM + `kid` header when `config.id_token_alg == "RS256"` (missing PEM → 500 `server_error` "RS256 configured but private key is missing").
- `TokenService` takes the keyset (`TokenService(storage, config, keyset=None)`) and signs JWT access tokens with `keyset.current_for_alg("RS256") or keyset.current_for_alg("HS256")` (refresh tokens remain opaque `token_urlsafe(32)` — Phase 1 design, unchanged). `app.state.keyset = seed_keyset(config)` in `create_app`; routes pass it through.
- `GET /.well-known/jwks.json`: all **active** RS256 keys as JWKs; `Cache-Control: public, max-age=3600`; fallback single JWK from the config PEM when the keyset has zero RS256 keys and `id_token_alg == "RS256"`; HS256-only → `{"keys": []}` (existing behavior).
- Admin: `POST /admin/api/keys/rotate` (body `{"algorithm"?: "HS256"|"RS256" case-insensitive — default **RS256**, "grace_period_hours"?: int}`; unknown alg → 400 `{"error":"invalid_request","error_description":"Unknown algorithm: <v>"}`; kid `f"{alg.lower()}-{int(time.time())}"`; rotate + prune; 200 `{kid, algorithm, created_at, grace_period_hours, warning: "Key rotation is in-memory only. Rotated keys will be lost on restart. DB persistence is not yet implemented."}`), `GET /admin/api/keys` (`{"keys":[{kid, algorithm, is_current, created_at, expires_at}]}` — no material).
- Discovery: `id_token_signing_alg_values_supported` = `["RS256"]` when `id_token_alg == "RS256"` else `["HS256"]`.
- Logout (Task 11) RS256 hint verification: derive the public key from the config PEM via `cryptography` (do not feed a private PEM to PyJWT's RSA verify path directly — extract `.public_key()`).

- [ ] **Step 1: Failing tests** — keyset units ported from `key_set.rs` mod tests (`test_current_for_alg_filters_by_algorithm`, `test_find_by_kid`, `test_rotate_marks_old_key_non_current`, `test_prune_expired_removes_old_keys`, `test_active_keys_excludes_expired`); integration (generate a test RSA PEM once in a module-scoped fixture — 2048-bit gen is ~100ms): `test_jwks_publishes_rs256_key_shape` (keys[0] has kid/kty/use/alg/n/e and n/e round-trip to the real public numbers), `test_jwks_empty_for_hs256_only`, `test_access_token_signed_rs256_with_kid_matching_jwks`, `test_id_token_rs256_verifiable_via_jwks` (build the public key from the JWK, `jwt.decode(id_token, ..., algorithms=["RS256"], audience="client1")`), `test_rotate_keeps_old_key_in_jwks_during_grace` (rotate → both kids in JWKS; old token still validates via `decode_access_token` with keyset), `test_rotate_response_shape_and_warning`, `test_admin_keys_list_hides_material`, `test_pre_rotation_token_still_introspects_active` (DB row authoritative).

- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): RS256 signing, in-memory key rotation, JWKS publication"`

---

### Task 14: Login + device-verify UI parity

**Files:**
- Create: `src/oauth2_server/templates/login.html`
- Modify: `src/oauth2_server/routes/login.py`, `src/oauth2_server/routes/device.py`, `pyproject.toml` (`[tool.hatch.build.targets.wheel]` include templates as package data if needed)
- Test: `tests/test_login_ui.py` (new); update any Phase 1 test asserting the old 401-JSON login failure

**Interfaces:**
- `GET /auth/login` → 200 `text/html`: minimal self-contained page (no CDN) with username/password form POSTing `/auth/login`, and a `<!--SERVER_ERROR-->` placeholder replaced when `?error=` present: `invalid_credentials` → "Invalid username or password. Please try again."; `login_required` → "Please log in to continue."; `too_many_attempts` → "Too many login attempts. Please wait a few minutes and try again."; anything else → "An error occurred. Please try again." (html-escaped). Template loaded via `importlib.resources` with an inline-string fallback.
- `POST /auth/login` failure → **303** `Location: /auth/login?error=invalid_credentials` (was 401 JSON); success → **303** to validated `return_to` else `/` (was 302). `login_session` helper updated accordingly.
- `GET /oauth/device/verify` → session required (else store `return_to` and 302 `/auth/login`); 200 HTML form (user_code input **html-escaped** when prefilled from `?user_code=`, approve/deny submit buttons). POST stays JSON (divergence 6).

- [ ] **Step 1: Failing tests** — `test_login_page_renders_form`, `test_login_page_shows_error_banner` (each error key maps to its message; unknown key → generic), `test_login_error_key_is_escaped` (`?error=<script>` → no raw `<script>` in body), `test_failed_login_redirects_with_error` (303 + Location), `test_device_verify_page_requires_session` (302 to login), `test_device_verify_page_escapes_user_code` (`?user_code="><script>alert(1)</script>` → escaped; normal `WDJB-MJHT` preserved — port of the Rust device.rs unit tests).

- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite PASS (fix any test relying on 401/302 login semantics).** **Step 5: Commit** — `git commit -m "feat(python): login page + device verify UI parity"`

---

### Task 15: Phase 2 acceptance — extended compliance suite, gate, docs

**Files:**
- Modify: `tests/test_rfc_compliance.py`, `README.md`, `docs/PHASE2-BACKLOG.md`
- Test: the full gate

**Interfaces:** none new — this task pins the phase.

- [ ] **Step 1: Extend `tests/test_rfc_compliance.py`** with Phase 2 pins (thin wrappers acceptable where a dedicated test file already covers the behavior — the point is one diffable file mirroring the Rust compliance surface): `test_refresh_token_expires_after_ttl`, `test_prompt_none_expired_max_age_login_required`, `test_rfc9126_par_round_trip`, `test_oidc_logout_redirects_with_exact_state`, `test_backchannel_logout_token_shape`, `test_jwks_rs256_shape`, `test_admin_rbac_bearer_allowlist`, `test_denylist_ip_blocked`.

- [ ] **Step 2: Run `bash scripts/gate.sh`** — ruff, format check, full pytest: all green.

- [ ] **Step 3: Update docs:**
  - `README.md`: Phase 2 feature list (admin API + RBAC, denylist, audit, logout, PAR, RS256/JWKS), new env vars (`OAUTH2_ADMIN_CLIENT_IDS`, `OAUTH2_ADMIN_EMAILS`, `OAUTH2_SEED_*`, `OAUTH2_ID_TOKEN_*`), single-process caveats for ParStore/KeySet/RecentEventsStore.
  - `docs/PHASE2-BACKLOG.md`: mark items 1–11 done with commit refs; append the numbered divergences from Global Constraints to "Accepted divergences"; leave item 12 (rate limiting) + subject-denylist enforcement + PAR/keys persistence as the seeded "Phase 3 candidates" list.

- [ ] **Step 4: Commit** — `git commit -m "test(python): Phase 2 compliance pins + docs"`

---

## Self-Review (completed)

- **Spec coverage:** backlog #1 → Task 1; #2 → Task 2; #3 → Task 4; #4 → Task 5; #5 → Task 3; #6 → Task 6; #7 → Task 3; #8 → Task 4; #9 → Task 2; #10 → Task 3; #11 → Task 1; #12 explicitly deferred (Phase 3). Deferred-features list: admin API → Tasks 6–9; denylist → Tasks 6, 10; audit log → Tasks 7, 10; session/login UI parity → Task 14; OIDC logout + id_token_hint → Task 11; prompt/max_age → Task 5; PAR → Task 12; key rotation/RS256 JWKS → Task 13. Admin SPA is intentionally out of scope (JSON API only — the SPA is a static template the Rust repo owns).
- **Placeholder scan:** ellipses appear only inside test skeletons whose asserts are fully specified by the named Rust source tests (per Phase 1 house style) or in interface signatures whose bodies are specified in the Interfaces block; no TBDs.
- **Type consistency:** `AdminActor` produced in Task 7 consumed by Tasks 8–10; `record_audit(storage, events, entry)` signature consistent across 7–10; `ListQuery`/`page_envelope` from Task 6 used by 8–10, 13; `SigningKey`/`KeySet` names match between keys.py and security.py call sites; `hash_password_async` (Task 3) used by Tasks 2 & 8 (Task 2 notes the ordering reconciliation).
- **Sequencing:** Tasks 1–5 are independent hardening but share `token.py`/`authorize.py` — execute in order. 6→7→8/9/10 strictly ordered. 11→13 note the RS256 hint dependency (11 lands HS256-only hint verification; 13 upgrades it). 14–15 last.
