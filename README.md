# python-oauth2-server

Python port of [rust-oauth2-server](https://github.com/ianlintner/rust-oauth2-server) — an OAuth2/OIDC authorization server.

- Same DB schema: `migrations/sql/` is vendored verbatim from the Rust repo (source of truth); both servers can share one Postgres.
- RFC compliance tests ported 1:1 from the Rust suite act as the spec.
- Stack: FastAPI, uvicorn+uvloop, Pydantic v2, SQLAlchemy async (raw SQL), PyJWT, argon2-cffi, cryptography (RS256/JWKS).

Plan: `docs/plans/2026-07-19-python-oauth2-port.md` (Phase 1), `docs/plans/2026-07-19-python-oauth2-port-phase-2.md` (Phase 2), `docs/plans/2026-07-20-python-oauth2-port-phase-3a.md` (Phase 3a), `docs/plans/2026-07-20-python-oauth2-port-phase-3b.md` (Phase 3b), `docs/plans/2026-07-20-python-oauth2-port-phase-3c.md` (Phase 3c).

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

## Phase 3a hardening

Phase 3a (see `docs/plans/2026-07-20-python-oauth2-port-phase-3a.md` and `docs/PHASE2-BACKLOG.md` →
"Accepted divergences" 10–13) closes most of the Phase 2 review backlog:

- **Login rate limiting** — `POST /auth/login` is gated by an in-memory, single-process fixed-window
  limiter keyed on both source IP and username (either blocked → blocked); a blocked attempt returns
  303 with `error=too_many_attempts` and a `Retry-After` header without touching credential
  verification. Endpoint-level rate limiting (`/oauth/token`, `/oauth/device/verify`) is **not** covered
  yet — deferred to Phase 3c.
- **Subject-kind denylist enforcement** — the `username`/`email` denylist kinds are now consulted at
  login, and `client_id` at client authentication (`ClientService.authenticate`) and
  `GET /oauth/authorize`; a hit gets the identical generic error as an unknown user/client (no oracle).
  `user_id` stays unwired (no pre-auth call site keys on it).
- **Rotation-safe id_tokens** — RS256 id_tokens sign with the keyset's current key instead of the
  static env PEM, closing the rotation trap where a rotated deployment breaks RP id_token verification
  once the original key ages out of JWKS.
- Admin API polish: PUT validation + disable-cascade parity, a 409 on duplicate `client_id` create,
  clamped negative paging bounds, `Cache-Control: no-store` on all `/admin/api/*` responses, escaped
  `LIKE` search wildcards, and uniform audit logging for single-token revoke / device expire / key
  rotation.

### New environment variables (Phase 3a)

| Variable | Default | Purpose |
|---|---|---|
| `OAUTH2_LOGIN_RATE_LIMIT_ATTEMPTS` | `10` | Max `POST /auth/login` attempts allowed per window, per IP and per username (either exhausted → blocked). |
| `OAUTH2_LOGIN_RATE_LIMIT_WINDOW_SECS` | `900` | Fixed-window duration (seconds) for the login rate limiter. |

## Phase 3b: DPoP, RAR, Token Exchange

Phase 3b (see `docs/plans/2026-07-20-python-oauth2-port-phase-3b.md` and `docs/PHASE2-BACKLOG.md` →
"Accepted divergences" 14–19) ports the three protocol extensions from the Rust server, fixing
several documented Rust spec violations along the way:

- **DPoP (RFC 9449)** — `POST /oauth/token` and `POST /oauth/introspect` accept an optional
  `DPoP` proof header. A valid ES256/RS256/PS256-family proof binds the issued access token to
  the caller's key (`cnf.jkt` claim, `token_type: "DPoP"` in the response); clients flagged
  `dpop_nonce_required` must first complete a `use_dpop_nonce` challenge/response round trip
  (`DPoP-Nonce` response header) before a proof is accepted. Introspection of a `cnf`-bound token
  requires a matching proof or returns `{"active": false}` — never an error, so cross-endpoint or
  wrong-key proofs can't be used to probe token state.
- **Rich Authorization Requests — RAR (RFC 9396)** — `authorization_details` is accepted at
  `GET /oauth/authorize` (and via PAR), `POST /oauth/token`, and validated against a configured
  type allowlist (`rar_types_supported`, default `["openid"]`); violations are rejected before a
  code is minted or a token is issued (`invalid_authorization_details`). Validated details are
  echoed in the token response and introspection, and embedded in the JWT access token — three
  gaps the Rust server has (see divergence 15/17 below).
- **Token Exchange (RFC 8693)** — a new grant,
  `urn:ietf:params:oauth:grant-type:token-exchange`, lets a confidential client exchange a
  `subject_token` it holds for a new access token scoped to itself; `subject_token_type` and
  `requested_token_type` are validated against the single supported access-token URN (Rust parses
  and ignores both — divergence 18); the delegation claim `act={"sub": <exchanging client_id>}` is
  embedded in every exchanged JWT, not just the HTTP response body (divergence 19).

### New environment variables (Phase 3b)

| Variable | Default | Purpose |
|---|---|---|
| `OAUTH2_DPOP_NONCE_SECRET` | unset (random per-process) | HMAC secret for the stateless DPoP nonce issuer (`services/dpop_nonce.py`). Decoded trying base64url-no-pad → standard base64 → hex (64 chars) in that order; an unset or undecodable value falls back to a random 32-byte per-process secret with a logged warning — set this explicitly in any multi-process/multi-instance deployment so nonces issued by one worker verify on another. |
| `OAUTH2_DPOP_NONCE_LIFETIME_SECS` | `300` | Bucket width (seconds) for nonce issuance/verification; the current and immediately-previous bucket are both accepted, clamped to `>= 1`. |
| `OAUTH2_RAR_TYPES_SUPPORTED` | `openid` | Comma-separated `authorization_details[].type` allowlist enforced at authorize/PAR/token and advertised as `authorization_details_types_supported` in discovery. |

### Single-process state caveat: DPoP replay store

Same caveat as the Phase 2 stores above applies to the DPoP proof **replay store**
(`services/dpop.py::DpopReplayStore`, `app.state.dpop_replay`): it is an in-process, in-memory
dict of seen `jti` values with a bounded TTL, not shared across workers or instances. A proof
replayed against a *different* worker than the one that first saw it will NOT be caught. Run
`OAUTH2_WORKERS=1` or a sticky-session load balancer, matching the existing `ParStore`/`KeySet`/
`RecentEventsStore` guidance, until Phase 3 adds shared persistence for all four stores.

## Phase 3c: Observability, Rate Limiting, Events, Social Login

Phase 3c (see `docs/plans/2026-07-20-python-oauth2-port-phase-3c.md` and `docs/PHASE2-BACKLOG.md` →
"Accepted divergences" 22–26) ports the operational subsystems from the Rust server:

- **Prometheus metrics + health/readiness** — `GET /metrics` exposes a dedicated
  `prometheus_client.CollectorRegistry` (`oauth2_server_*`-prefixed families, byte-for-byte name
  parity with the Rust exposition, content-type pinned to `text/plain; version=0.0.4` with no
  charset — divergence 22) via an ASGI timing middleware; `GET /health` returns a static liveness
  payload; `GET /ready` runs `SqlStorage.healthcheck()` (`SELECT 1`) and returns 503 plain text on
  failure.
- **Rate limiting** — three independent, in-memory token-bucket mechanisms
  (`services/limiter.py::TokenBucketLimiter`): a global per-IP `RateLimitMiddleware` (off by
  default), an always-on `invalid_client` penalty bucket on `POST /oauth/token` (5
  requests/window by default — replaces the 401 with a 429 once exhausted), and a resilience
  middleware (circuit breaker + concurrency limiter, off by default) that returns 503 on
  consecutive 5xx responses or back-pressure. All three fail **open** on a backend error.
- **Event bus + ingest** — an in-process `EventBus` (`services/events_bus.py`) fans pydantic
  `EventEnvelope`s out to pluggable backends (`console`/`in_memory`, always alongside the
  existing `RecentEventsStore` bridge) from 9 real emit sites (token issue/revoke, authorization
  code issue/validate, client auth). `POST /events/ingest` accepts external events behind a
  bearer token (fails **closed** with 503 if unconfigured) with `Idempotency-Key` dedup;
  `GET /events/health` reports per-plugin health.
- **Social login** — `GET /auth/login/{google|microsoft|github|azure}` +
  `GET /auth/callback/{provider}` implement the authorization-code flow against each provider
  (Google adds PKCE S256), find-or-create a local `User` keyed `provider:<id>`, and establish a
  session. `okta`/`auth0` stay 503 stubs (Rust parity, divergence 25). A provider is "configured"
  iff both its `_client_id` and `_client_secret` are set.

### New environment variables (Phase 3c)

All are `OAUTH2_`-prefixed (see `src/oauth2_server/config.py` for the full `Config` model).

**Rate limiting / resilience:**

| Variable | Default | Purpose |
|---|---|---|
| `OAUTH2_RATE_LIMIT_ENABLED` | `false` | Master switch for the global per-IP `RateLimitMiddleware`. |
| `OAUTH2_RATE_LIMIT_MAX_REQUESTS` | `100` | Token-bucket capacity for the global limiter. |
| `OAUTH2_RATE_LIMIT_WINDOW_SECS` | `60` | Token-bucket refill window (seconds) for the global limiter. |
| `OAUTH2_RATE_LIMIT_INVALID_CLIENT_MAX_REQUESTS` | `5` | Capacity of the always-on `invalid_client` penalty bucket on `POST /oauth/token`, keyed per `client_id`. Set to `0` to disable it entirely. |
| `OAUTH2_SERVER_TRUST_PROXY_HEADERS` | `false` | When `true`, the global rate limiter keys on the first `X-Forwarded-For` entry instead of the socket peer address. Note the `OAUTH2_SERVER_*` prefix (not `OAUTH2_RATE_LIMIT_*`) — Rust scopes this under `[server]`, not `[rate_limit]`. |
| `OAUTH2_RESILIENCE_ENABLED` | `false` | Master switch for the circuit-breaker + concurrency-limiter middleware. |
| `OAUTH2_RESILIENCE_MAX_CONCURRENT` | `1000` | In-flight request cap before the concurrency limiter starts rejecting with 503. |
| `OAUTH2_RESILIENCE_CB_FAILURE_THRESHOLD` | `5` | Consecutive 5xx responses before the circuit breaker opens. |
| `OAUTH2_RESILIENCE_CB_SUCCESS_THRESHOLD` | `2` | Consecutive successes in half-open state before the breaker closes again. |
| `OAUTH2_RESILIENCE_CB_OPEN_SECS` | `30` | How long the breaker stays open before probing (half-open). |
| `OAUTH2_RESILIENCE_CB_HALF_OPEN_MAX_PROBES` | `3` | Concurrent probe requests allowed while half-open. |

**Events:**

| Variable | Default | Purpose |
|---|---|---|
| `OAUTH2_EVENTS_ENABLED` | `true` | Master switch for the event bus (`app.state.event_bus`) and the `/events/*` routes. |
| `OAUTH2_EVENTS_PUBLIC_INGEST` | `false` | When `true`, `POST /events/ingest` skips the bearer check entirely. |
| `OAUTH2_EVENTS_INGEST_BEARER_TOKEN` | unset | Bearer token required on `POST /events/ingest` (compared with `hmac.compare_digest`). Unset + public ingest off → the endpoint fails **closed** with 503 `event_ingest_auth_not_configured`, never silently open. |
| `OAUTH2_EVENTS_BACKEND` | `in_memory` | `console`, `in_memory`, or `both`. Only these two backends are ported — Redis Streams/Kafka/RabbitMQ are out of scope (see `docs/PHASE2-BACKLOG.md`). An unrecognized value falls back to `in_memory` with a logged warning. |
| `OAUTH2_EVENTS_FILTER_MODE` | `allow_all` | `allow_all`, `include_only`, or `exclude`, paired with `OAUTH2_EVENTS_TYPES`. |
| `OAUTH2_EVENTS_TYPES` | unset (empty) | Comma-separated event-type list consulted when `OAUTH2_EVENTS_FILTER_MODE` is `include_only`/`exclude`. |

**Social login** (one block per provider; a provider is "configured" iff both `_CLIENT_ID` and
`_CLIENT_SECRET` are set — the Rust config-file `enabled` flag has no analogue here):

| Variable | Default | Purpose |
|---|---|---|
| `OAUTH2_GOOGLE_CLIENT_ID` / `OAUTH2_GOOGLE_CLIENT_SECRET` / `OAUTH2_GOOGLE_REDIRECT_URI` | unset | Google OAuth app credentials. PKCE S256 is always used. Redirect defaults to an issuer-based URL when unset. |
| `OAUTH2_MICROSOFT_CLIENT_ID` / `OAUTH2_MICROSOFT_CLIENT_SECRET` / `OAUTH2_MICROSOFT_REDIRECT_URI` | unset | Microsoft (Entra ID / Graph) app credentials. |
| `OAUTH2_MICROSOFT_TENANT_ID` | `common` | Tenant segment in the Microsoft authorize/token URLs. |
| `OAUTH2_GITHUB_CLIENT_ID` / `OAUTH2_GITHUB_CLIENT_SECRET` / `OAUTH2_GITHUB_REDIRECT_URI` | unset | GitHub OAuth App credentials. Email resolves via the verified-primary entry in `/user/emails`, never the `/user` response's own `email` field. |
| `OAUTH2_AZURE_CLIENT_ID` / `OAUTH2_AZURE_CLIENT_SECRET` / `OAUTH2_AZURE_REDIRECT_URI` | unset | Optional, independent Azure app credentials; when any is unset, Azure falls back **whole-hog** to the Microsoft credentials above (Rust parity: `config.azure.or(config.microsoft)`) — but always uses its own `OAUTH2_AZURE_TENANT_ID`. |
| `OAUTH2_AZURE_TENANT_ID` | `common` | Tenant segment used for the Azure login/callback flow, independent of the Microsoft tenant. |
| `OAUTH2_OKTA_CLIENT_ID` / `OAUTH2_OKTA_CLIENT_SECRET` / `OAUTH2_OKTA_REDIRECT_URI` | unset | Accepted for forward-compat only — `GET /auth/login/okta` always 503s ("Okta login not yet implemented", Rust parity stub). |
| `OAUTH2_AUTH0_CLIENT_ID` / `OAUTH2_AUTH0_CLIENT_SECRET` / `OAUTH2_AUTH0_REDIRECT_URI` | unset | Accepted for forward-compat only — `GET /auth/login/auth0` always 503s ("Auth0 login not yet implemented", Rust parity stub). |

### Single-process state caveats (Phase 3c additions)

Same caveat pattern as the Phase 2/3b stores above: each of the following lives on `app.state`
as an in-process, in-memory singleton, **not** shared across worker processes or server
instances — run `OAUTH2_WORKERS=1` or a sticky-session load balancer until these gain shared
persistence:

- **`TokenBucketLimiter`** (`services/limiter.py`, `app.state.rate_limiter` +
  `app.state.invalid_client_limiter`) — the global per-IP bucket and the `invalid_client` penalty
  bucket are both per-process dicts of buckets; a client hitting different workers effectively
  gets `N ×` the configured budget.
- **`IdempotencyStore`** (`services/events_bus.py`, `app.state.event_idempotency`) — TTL-pruned
  dedup dict for `POST /events/ingest`'s `Idempotency-Key`; a duplicate submitted to a different
  worker than the one that saw the original is not caught.
- **`RecentEventsStore`** (`services/events.py`, `app.state.events`) — unchanged from Phase 2; now
  also fed by the event bus's `RecentEventsPlugin`, still per-worker.
- **Per-provider `CircuitBreaker`** (`services/social.py`, `app.state.social_breakers`) — one
  breaker instance per social provider, guarding only the userinfo fetch; state (open/closed/
  half-open) does not propagate across workers.
- **`DpopReplayStore`** (`services/dpop.py`, `app.state.dpop_replay`) — carried over from Phase 3b,
  listed again here for completeness; see the Phase 3b section above.

### Metrics registered but not wired (parity-only)

Matching the Rust server, this port registers a superset of metric families it never actually
increments in most code paths (dashboard/scrape parity only). The following 12 families are
registered and bootstrap-seeded — a cold `/metrics` scrape carries their `# HELP`/`# TYPE` lines
and a zero-valued series — but no request path increments them: `oauth2_server_db_queries_total`,
`oauth2_server_db_query_duration_seconds`, `oauth2_server_oauth_clients_total`,
`oauth2_server_oauth_active_tokens`, `oauth2_server_errors_total`,
`oauth2_server_http_client_requests_total`, `oauth2_server_http_client_request_duration_seconds`,
`oauth2_server_events_published_total`, `oauth2_server_events_publish_duration_seconds`,
`oauth2_server_redis_client_operations_total`,
`oauth2_server_redis_client_operation_duration_seconds`, `oauth2_server_bulkhead_rejected_total`
(bulkheads themselves are config-file-only in Rust and were not ported at all — see
`docs/PHASE2-BACKLOG.md`). By contrast, `oauth2_server_rate_limit_rejected_total` /
`oauth2_server_rate_limit_remaining` (divergence 24 exception) and
`oauth2_server_circuit_breaker_state` / `oauth2_server_circuit_breaker_trips_total` /
`oauth2_server_back_pressure_rejected_total` / `oauth2_server_concurrent_requests_in_flight` ARE
wired, by the rate-limit and resilience middleware respectively.

### Security note: admin-by-email and social login

`OAUTH2_ADMIN_EMAILS` grants admin-API access to any session whose `email` matches the
allowlist, case-insensitively — **including sessions established via social login**. Because of
this, self-service social login only provisions a session when the provider has asserted (and,
for GitHub, verified) an email address: Google requires `verified_email: true` in the userinfo
response, GitHub requires a `primary: true, verified: true` entry from `/user/emails` (an
unverified or absent primary email is treated as "no email found" and the callback 400s rather
than provisioning a session), and Microsoft/Azure trust Graph's `userPrincipalName` as-is (Graph
does not expose a verification flag for it). Operators who list any address in
`OAUTH2_ADMIN_EMAILS` that a user could plausibly self-assert through an identity provider should
confirm that provider actually verifies email ownership before granting the OAuth app access to
production.

## Phase 3d: MongoDB Backend

Phase 3d (see `docs/plans/2026-07-20-python-oauth2-port-phase-3d.md` and `docs/PHASE2-BACKLOG.md` →
"Accepted divergences" 28–31) adds a second `Storage` implementation, `MongoStorage`
(`src/oauth2_server/storage/mongo.py`, motor async driver), satisfying the exact same `Storage`
protocol as the default SQL backend — "same data model, second engine."

**Backend selection** is automatic and scheme-based: `storage/factory.py::create_storage(config)`
dispatches on `OAUTH2_DATABASE_URL`'s scheme. `mongodb://` or `mongodb+srv://` selects
`MongoStorage`; anything else (`sqlite+aiosqlite://`, `postgresql+asyncpg://`, ...) falls through
to the existing SQL backend unchanged. `mongodb+srv://` (DNS-SRV discovery, e.g. for MongoDB
Atlas) is supported here — divergence 31; the Rust server hard-rejects it to dodge a
hickory-proto DNS-resolver advisory that doesn't apply to this driver stack.

**Install:** `motor` is an optional dependency, not a default one — the default SQLite/Postgres
deployment path never imports it. Install it with the `mongo` extra:

```bash
pip install "oauth2-server[mongo]"
# or, from this repo with uv:
uv sync --extra mongo
```

Constructing `create_storage()` against a `mongodb://` URL without the extra installed raises a
`RuntimeError` naming the missing package and the install command above, rather than an opaque
`ImportError`.

**Database name** comes from the URL path — `mongodb://host:27017/my_db` binds to `my_db`;
a URL with no path (or `/`) falls back to `oauth2`.

**Cross-server parity:** documents are the JSON-mode serialization of the same `oauth2_server.
models` Pydantic models the SQL backend uses — same field names, the same JSON-array-as-string
convention (`Client.redirect_uris` etc. stay JSON strings, never BSON arrays), and the same
RFC 3339-string datetime convention (never BSON dates) — so a single MongoDB database can be
shared across a Python server and the Rust reference server's own Mongo backend, the same
single-database cross-server parity guarantee Phase 1 established for Postgres.

**Fixed gaps vs. the Rust Mongo backend** (divergences 28–30 — this port does not copy Rust's
Mongo stub gaps):

- `revoke_token_family` / `revoke_tokens_by_user_id` are actually implemented (`update_many` +
  `modified_count`), where Rust's trait defaults silently no-op on Mongo — meaning on Rust,
  RFC 9700 §4.13.2 refresh-token-replay cascade revocation and OIDC-logout token revocation
  simply don't work when Mongo is the backend. Fixed here.
- Denylist + audit-log storage (`denylist`/`audit_log` collections) are fully implemented and
  `supports_denylist()`/`supports_audit_log()` return `True` — Rust stubs both as no-ops
  returning `False`, silently disabling the admin denylist/audit features on Mongo.
- `mark_authorization_code_used` / `mark_device_authorization_used` use an atomic
  `find_one_and_update({..., used: false}, {$set: {used: true}})` single-claim (matching the SQL
  backend's `... AND used = false` guard) instead of Rust's non-atomic `update_one`, closing a
  double-spend race.

**Caveats (deliberate, Cosmos-DB-compatibility / Rust-parity choices — not bugs):**

- **App-side full-collection scans for every list/page method.** `list_all_*`/`list_*_page`/
  `list_denylist`/`list_audit_log` all do a `find({})` full scan, then sort/filter/paginate in
  Python — there is no server-side `$sort`/`$skip`/`$limit` pipeline. This is O(collection size)
  per call and matches the Rust Mongo backend's own choice (made for Azure Cosmos DB for MongoDB
  compatibility, whose aggregation-pipeline support is more limited than real MongoDB's).
- **No TTL indexes.** Expired tokens, authorization codes, device authorizations, and denylist
  entries are never automatically deleted — they accumulate in their collections until an
  operator prunes them manually (or a future migration adds `expireAfterSeconds` indexes). The
  SQL backend has the same gap (no scheduled cleanup job either), so this isn't a Mongo-specific
  regression, just worth calling out since MongoDB TTL indexes are the idiomatic fix and aren't
  wired up.
- **`list_all_tokens` truncates to 200; `list_all_device_authorizations` truncates to 500** —
  both are newest-first (`created_at` desc) caps matching the SQL backend's `LIMIT`, ported for
  Rust parity, not a Mongo-specific restriction.
- **Denylist upsert is non-atomic.** `add_denylist_entry`'s "keep the original row's `id` on a
  `(kind, value)` conflict" behavior is a read-then-write (`find_one` then `replace_one(upsert=
  True)`), not a single atomic operation — a benign race under concurrent admin writes to the
  same `(kind, value)` pair (admin-only, low-traffic surface). Rust's own Mongo backend has the
  same non-atomicity.

**Testing:** the full `MongoStorage` contract suite (`tests/test_mongo_storage.py`,
`tests/test_mongo_admin.py`), the app-level end-to-end suite (`tests/test_mongo_e2e.py` — full
HTTP flows including the refresh-replay family-cascade proof above and a real `DenylistGuard` 403),
and the compliance pin (`tests/test_rfc_compliance.py::test_mongo_backend_storage_contract`) all
self-skip unless `RUN_TESTCONTAINERS=1` is set (and `motor`+`testcontainers` are installed — both
are dev dependencies), starting a real `mongo:7.0` container via `testcontainers`:

```bash
RUN_TESTCONTAINERS=1 uv run pytest tests/test_mongo_storage.py tests/test_mongo_admin.py \
  tests/test_mongo_e2e.py tests/test_rfc_compliance.py -q
```

`bash scripts/gate.sh` (the default CI gate) never requires Docker — it runs SQLite-only, and
every Mongo-gated test self-skips without the env var. CI runs the Mongo suite in a separate,
parallel `db-tests` job (`.github/workflows/ci.yml`) that does require Docker (available on
GitHub-hosted `ubuntu-latest` runners).

A documentation-grade, manually-runnable cross-backend HTTP smoke — `docker run` a real mongod,
start the Python server against it, register a client, run client_credentials + introspect +
revoke over curl — lives in `scripts/mongo_parity_smoke.sh`:

```bash
bash scripts/mongo_parity_smoke.sh
```

```
== 1. Start mongod ==
mongod started on port 27017, database 'oauth2_smoke'
== 2. Start the Python server against MongoStorage ==
waiting for the server to become ready...
== 3. Register a client (RFC 7591, persisted into MongoStorage) ==
{"client_id": "client_...", "client_secret": "...", ...}
registered client_id=client_...
== 4. client_credentials grant ==
{"access_token": "eyJhbGci...", "token_type": "Bearer", "expires_in": 3600, "scope": "read"}
== 5. Introspect the client_credentials access token ==
{"active": true, "scope": "read", "client_id": "client_...", ...}
== 6. Revoke the client_credentials token, re-introspect ==
{"active": false}

== Result: PASS ==
```

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
