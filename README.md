# python-oauth2-server

Python port of [rust-oauth2-server](https://github.com/ianlintner/rust-oauth2-server) — an OAuth2/OIDC authorization server.

- Same DB schema: `migrations/sql/` is vendored verbatim from the Rust repo (source of truth); both servers can share one Postgres.
- RFC compliance tests ported 1:1 from the Rust suite act as the spec.
- Stack: FastAPI, uvicorn+uvloop, Pydantic v2, SQLAlchemy async (raw SQL), PyJWT, argon2-cffi, cryptography (RS256/JWKS).

Plan: `docs/plans/2026-07-19-python-oauth2-port.md` (Phase 1), `docs/plans/2026-07-19-python-oauth2-port-phase-2.md` (Phase 2).

## Phase 2 features

Phase 2 closes the Phase 1 review backlog (see `docs/PHASE2-BACKLOG.md`) and ports the
remaining Rust feature set:

- **Admin JSON API + RBAC** (`/admin/api/*`) — clients/users/tokens/devices CRUD, dashboard
  summary, capabilities, and a recent-events feed, all behind a dual-mode guard that accepts
  either an authenticated admin session (`role=admin` or an allowlisted email) or a bearer
  token with `admin` scope from an allowlisted `client_id`.
- **Denylist + audit log** — a global `DenylistGuard` ASGI middleware blocks requests by
  source IP (fail-open on storage errors); every admin mutation and revocation writes a
  best-effort `audit_log` entry.
- **Full OIDC RP-initiated logout** — `GET /oauth/logout` supports `id_token_hint`,
  `post_logout_redirect_uri` validation, front-channel iframe logout, and back-channel
  `logout+JWT` delivery via `httpx`; `GET /oauth/check_session` for session-status iframes.
  `dynamic_registration_enabled` gates `/connect/register` (default off).
- **PAR (RFC 9126)** — `POST /oauth/par` pushes authorization parameters and returns a
  short-lived, single-use `request_uri` that `GET /oauth/authorize` can consume.
- **RS256 key rotation + JWKS** — when `OAUTH2_ID_TOKEN_PRIVATE_KEY_PEM` is configured, access
  and ID tokens are signed RS256 and published at `/.well-known/jwks.json`;
  `POST /admin/api/keys/rotate` rotates in a new key while keeping the old one available in
  the JWKS for `key_rotation_grace_hours` (default 24) so in-flight tokens keep verifying.
- **Login + device-verify UI** — minimal server-rendered HTML for `/auth/login` and the
  `GET /oauth/device/verify` user-code entry page (the `POST` endpoint stays JSON, a
  deliberate divergence from Rust — see "Accepted divergences" in `docs/PHASE2-BACKLOG.md`).
- Hardening carried over from the Phase 1 backlog: refresh-token TTL enforcement (+
  `id_token` re-mint on refresh/device-code grants), a migration advisory lock so multiple
  workers can boot against a fresh DB safely, HKDF-derived session-cookie signing key,
  async (non-blocking) argon2 password verification, `at+JWT` typ enforcement on access
  tokens, and a single grant-type allow-list applied consistently across every grant.

### New environment variables (Phase 2)

All are `OAUTH2_`-prefixed (see `src/oauth2_server/config.py` for the full `Config` model):

| Variable | Default | Purpose |
|---|---|---|
| `OAUTH2_ADMIN_CLIENT_IDS` | unset (empty) | Comma-separated `client_id` allowlist for the bearer-token admin-API path. Fails closed — an empty/unset list denies every bearer token, even one with `admin` scope. |
| `OAUTH2_ADMIN_EMAILS` | unset (empty) | Comma-separated, case-insensitive email allowlist that grants admin-API access to a session even when the user's `role` isn't `admin`. |
| `OAUTH2_SEED_USERNAME` | `admin` | Username for the optional startup-seeded admin user. |
| `OAUTH2_SEED_PASSWORD` | unset | **Admin seeding only runs when this is explicitly set** — a deliberate divergence from Rust, which ships an insecure default password rejected only in production mode. |
| `OAUTH2_SEED_EMAIL` | `admin@example.com` | Email for the seeded admin user. |
| `OAUTH2_ID_TOKEN_PRIVATE_KEY_PEM` | unset | PEM-encoded RSA private key. When set, access + ID tokens are signed RS256 instead of HS256 and JWKS publishes a public key. Literal `\n` sequences in a single-line env value are unescaped automatically. |
| `OAUTH2_ID_TOKEN_KID` | unset | `kid` for the configured RS256 key; required alongside the PEM to appear in JWKS/token headers. |
| `OAUTH2_ID_TOKEN_ALG` | `RS256` if a PEM is set, else `HS256` | Explicit override for the signing algorithm; normalized to upper-case. |
| `OAUTH2_KEY_ROTATION_GRACE_HOURS` | `24` | How long a rotated-out RS256 key stays published in JWKS after `POST /admin/api/keys/rotate`, so tokens signed just before rotation still verify. |
| `OAUTH2_DYNAMIC_REGISTRATION_ENABLED` | `false` | Gates `POST /connect/register`. Off by default, unlike Rust. |

### Single-process state caveats

Three Phase 2 subsystems are in-process, in-memory singletons hung off `app.state`
(mirroring the Rust server's in-memory actors) and are **not** shared across worker
processes or server instances:

- **`ParStore`** (`services/par.py`) — pushed-authorization-request state (RFC 9126). A
  `request_uri` pushed on one worker cannot be consumed by `GET /oauth/authorize` on
  another.
- **`KeySet`** (`keys.py`) — the RS256 signing-key set, including rotation history. Rotating
  keys via `POST /admin/api/keys/rotate` on one worker does not propagate to sibling workers,
  and the `signing_keys` DB table is intentionally unused (orphaned, matching Rust) — key
  material is never persisted.
- **`RecentEventsStore`** (`services/events.py`) — the bounded ring buffer backing
  `GET /admin/api/events`. Each worker only sees the events it personally handled.

**Practical consequence:** run `OAUTH2_WORKERS=1`, or front a multi-worker/multi-instance
deployment with a sticky-session load balancer that pins a given client to one process, until
Phase 3 adds persistence for these three stores (see `docs/PHASE2-BACKLOG.md` → "Phase 3
candidates").

## Running

```bash
OAUTH2_JWT_SECRET=<32+ char secret> uv run python -m oauth2_server
```

Tuned via `src/oauth2_server/__main__.py`: uvicorn with `loop="uvloop"`,
`http="httptools"`, and one worker process per CPU core (override with
`OAUTH2_WORKERS`). Each worker is spawned from the
`oauth2_server.app:build` factory (`uvicorn.run(..., factory=True)`), which
builds its own `Config`/`SqlStorage` from `OAUTH2_*` env vars and runs the
(idempotent, backfill-aware) migration runner on startup.

SQLAlchemy pool sizing on Postgres is controlled by `OAUTH2_DATABASE_MAX_CONNECTIONS`
(default 10; wired to `pool_size` + `pool_pre_ping=True`). Not applied to SQLite,
which uses `NullPool` and doesn't accept pool-sizing kwargs.

### Alternative runner: granian

[`granian`](https://github.com/emmett-framework/granian) is a Rust-based ASGI
server and can be used instead of uvicorn:

```bash
uv add granian  # not a default dependency
uv run granian --interface asgi oauth2_server.app:build
```

## Cross-server parity smoke

Proves the Python and Rust servers can share one Postgres database — the
Rust server's Flyway migrations create the schema, the Python migration
runner backfills its own version-tracking table without issuing DDL, and a
client registered via one server authenticates through the other.

```bash
# 1. Start Postgres
docker compose -f docker-compose.dev.yml up -d
# ... wait for `docker inspect --format='{{.State.Health.Status}}' oauth2_dev_postgres` == healthy

# 2. Apply the Rust server's migrations (Flyway — same tool used by
#    docker-compose.e2e.yml in the Rust repo)
docker run --rm --network host \
  -v <rust-repo>/migrations/sql:/flyway/sql \
  flyway/flyway:10-alpine \
  -url=jdbc:postgresql://localhost:5455/oauth2 -user=oauth2 -password=oauth2 \
  -schemas=public -connectRetries=5 migrate
# => Successfully applied 21 migrations to schema "public", now at version v21

# 3. Run the Rust server against it (from the Rust worktree) and register a client
OAUTH2_DATABASE_URL=postgres://oauth2:oauth2@localhost:5455/oauth2 \
OAUTH2_JWT_SECRET=parity-smoke-secret-0123456789abcdef-0123 \
OAUTH2_PUBLIC_URL=http://localhost:8080 \
OAUTH2_ALLOW_INSECURE_DEFAULTS=1 \
OAUTH2_DYNAMIC_REGISTRATION_ENABLED=true \
cargo run --bin rust_oauth2_server &

curl -s -X POST http://localhost:8080/connect/register \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris": ["http://localhost:9999/callback"], "grant_types": ["client_credentials"], "token_endpoint_auth_method": "client_secret_basic", "scope": "read", "client_name": "parity-smoke-client"}'
# => {"client_id": "client_7b810119-...", "client_secret": "pfJBep2vLZ4kFToDbGnW48pNrd0xJxap", ...}

kill %1   # stop the Rust server

# 4. Start the Python server against the same DB (asyncpg driver prefix)
OAUTH2_DATABASE_URL=postgresql+asyncpg://oauth2:oauth2@localhost:5455/oauth2 \
OAUTH2_JWT_SECRET=parity-smoke-secret-0123456789abcdef-0123 \
OAUTH2_PUBLIC_URL=http://localhost:8080 \
OAUTH2_ALLOW_INSECURE_DEFAULTS=1 \
OAUTH2_WORKERS=1 \
uv run python -m oauth2_server &

# migration runner backfills py_schema_version (no DDL) — verified via:
docker exec oauth2_dev_postgres psql -U oauth2 -d oauth2 -c \
  "SELECT COUNT(*) FROM py_schema_version;"    # => 21
docker exec oauth2_dev_postgres psql -U oauth2 -d oauth2 -c \
  "SELECT COUNT(*) FROM flyway_schema_history;"  # => 21, unchanged — confirms the Python
                                                  #    backfill issued no DDL against the schema

# client_credentials grant against the Rust-registered client, on Python:
curl -s -X POST http://localhost:8080/oauth/token \
  -H "Authorization: Basic $(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)" \
  -d "grant_type=client_credentials" -d "scope=read"
# => 200 {"access_token": "eyJhbGci...", "token_type": "Bearer", "expires_in": 3600, "scope": "read"}

kill %1   # stop the Python server

# 5. Restart Rust, introspect the Python-issued token
OAUTH2_DATABASE_URL=postgres://oauth2:oauth2@localhost:5455/oauth2 \
OAUTH2_JWT_SECRET=parity-smoke-secret-0123456789abcdef-0123 \
OAUTH2_PUBLIC_URL=http://localhost:8080 \
OAUTH2_ALLOW_INSECURE_DEFAULTS=1 \
cargo run --bin rust_oauth2_server &

curl -s -X POST http://localhost:8080/oauth/introspect \
  -H "Authorization: Basic $(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)" \
  -d "token=$PY_ACCESS_TOKEN"
# => {"active": true, "scope": "read", "client_id": "client_7b810119-...",
#     "token_type": "Bearer", "exp": ..., "iat": ..., "nbf": ...,
#     "sub": "client_7b810119-...", "aud": "client_7b810119-...", "jti": "...", "iss": "http://localhost:8080"}

kill %1
docker compose -f docker-compose.dev.yml down
```

**Result: pass end to end.** All three assertions succeeded (client registration
on Rust, `client_credentials` grant on Python, introspection on Rust returning
`active: true`).

**Bug found and fixed during the smoke:** `SqlStorage` always serialized
model fields with `model.model_dump(mode="json")`, which turns `datetime`
fields into ISO strings. That's correct for SQLite's `TEXT` columns but broke
inserts against real Postgres — `asyncpg` requires native `datetime` objects
for `TIMESTAMPTZ` columns and raises `DataError` on strings. This had never
surfaced because the test suite and prior tasks only ran against SQLite.
Fixed in `src/oauth2_server/storage/sql.py` by adding a `SqlStorage._dump()`
helper that dumps with `mode="json"` on SQLite and `mode="python"` (native
types, datetimes included) on Postgres.

## Benchmark

`scripts/bench.sh` benchmarks `POST /oauth/token` (client_credentials) and
`POST /oauth/introspect`, preferring `oha`/`wrk` if installed and falling back
to `scripts/bench.py` (asyncio+httpx closed-loop, 64 concurrency, 15s/endpoint)
otherwise:

```bash
BASE_URL=http://localhost:8080 CLIENT_ID=... CLIENT_SECRET=... scripts/bench.sh
```

**Baseline** (Python server, SQLite, single worker — `oha`/`wrk` were not
available in this environment, so the `scripts/bench.py` fallback ran instead;
64 concurrency, 15s/endpoint, Apple Silicon dev machine, unoptimized dev run
— no target thresholds in Phase 1, this is the number Phase 3's distributed
work improves on):

| Endpoint | Req/s | p50 | p95 | p99 |
|---|---|---|---|---|
| `POST /oauth/token` (client_credentials) | 233.7 | 182.8 ms | 666.4 ms | 1284.4 ms |
| `POST /oauth/introspect` | 767.8 | 76.6 ms | 149.3 ms | 205.7 ms |

`/oauth/token` is slower mainly because it issues a JWT and writes a new row
to SQLite on every request (SQLite serializes writes), while
`/oauth/introspect` only does a JWT decode plus a read-only row lookup.
