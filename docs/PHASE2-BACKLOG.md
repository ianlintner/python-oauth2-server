# Phase 2 Backlog — from Phase 1 reviews

Accumulated findings from per-task and final whole-branch reviews (Phase 1, branch port/phase-1).
None are merge-blocking; ordered by priority.

Phase 2 (branch `port/phase-2`, plan `docs/plans/2026-07-19-python-oauth2-port-phase-2.md`) closed
items 1–11 below across Tasks 1–14; see `.superpowers/sdd/progress.md` for the full per-task ledger.
Item 12 was explicitly deferred to Phase 3 from the start (see the Phase 2 plan's self-review).

## Important (top of Phase 2) — DONE
1. **Refresh-token expiry** — refresh grant never expires tokens (`routes/token.py` refresh branch);
   introspection uses the access-token `expires_at`, so a refresh token introspects inactive after 1h
   yet still redeems. Add a refresh TTL (config `refresh_token_ttl_secs` exists, unused for expiry).
   **Done:** Task 1 (commits `0cebdfb..a530e85`) — expiry computed as `created_at + refresh_token_ttl_secs`
   per the Global Constraints (no new column); pinned by
   `tests/test_rfc_compliance.py::test_refresh_token_expires_after_ttl`.
2. **Multi-worker migration race** — every worker runs `run_migrations` at startup; fresh-DB concurrent
   DDL can race. Add `pg_advisory_lock` or migrate-once entrypoint. (Rust-owns-schema deployments unaffected.)
   **Done:** Task 2 (commit `791c328`) — `pg_advisory_lock` around the migration runner, wired through
   the app `lifespan`.

## Minor — DONE
3. Scope policy inconsistency: client_credentials intersects requested scope; other grants reject with
   `invalid_scope`. Pick one policy.
   **Done:** Task 4 (commit `cad7a50`) — unified on reject-with-`invalid_scope` everywhere.
4. `prompt=none` + expired `max_age` (or `prompt="none login"`) falls through to the login UI instead of
   `error=login_required` (OIDC Core §3.1.2.6).
   **Done:** Task 5 (commits `e6344dd..14b7b90`) — pinned by
   `tests/test_rfc_compliance.py::test_prompt_none_expired_max_age_login_required` (and the pre-existing
   `test_prompt_none_with_expired_max_age_returns_login_required` in the same file).
5. Session cookie signing key is `jwt_secret` verbatim — HKDF-derive a separate key.
   **Done:** Task 3 (commit `d1976dd`) — HKDF-derived session key, distinct from `jwt_secret`.
6. `storage/sql.py`: `expire_device_authorization` writes ISO string (breaks on asyncpg); it and
   `set_token_family` are currently dead code — fix or drop.
   **Done:** Task 6 (commits `6966a10..24b53d9`), landed alongside the admin storage-layer expansion.
7. Argon2 verify runs on the event loop in login — wrap in `anyio.to_thread`.
   **Done:** Task 3 (commit `d1976dd`) — `hash_password_async`/verify off-loaded via `anyio.to_thread`.
8. Grant-type allow-list only enforced for client_credentials; extend to auth-code/refresh/device + authorize.
   **Done:** Task 4 (commit `cad7a50`) — one allow-list helper applied to every grant type.
9. Migrate `@app.on_event("startup")` → lifespan; replace deprecated ORJSONResponse default-class pattern.
   **Done:** Task 2 (commit `791c328`) — `lifespan` context manager (ORJSONResponse default-class
   migration was deferred; FastAPI's own deprecation warning for it is now a known, harmless residual —
   see "Phase 3 candidates").
10. `decode_access_token` doesn't validate the JOSE `typ` header (RFC 9068 hardening).
    **Done:** Task 3 (commit `d1976dd`) — `at+JWT` typ enforced on decode; pinned by
    `test_rfc_compliance.py::test_rfc9068_access_token_has_typ_at_jwt`.
11. No ID-token re-mint on refresh rotation when `openid` scope present.
    **Done:** Task 1 (commits `0cebdfb..a530e85`) — fresh `id_token` minted on refresh and device-code
    grants when `openid` scope is present (no `nonce` re-issued, per OIDC Core §12.2).
12. Rate limiting on /oauth/device/verify and token endpoints — explicitly deferred to Phase 3 from the
    start of the Phase 2 plan; not attempted in Phase 2. See "Phase 3 candidates".

## Accepted divergences (documented, keep)

From Phase 1:
- DCR rejection error is `invalid_client_metadata` (RFC 7591 §3.2.2) where the Rust admin handler uses
  `invalid_request` — noted in tests/test_rfc_compliance.py docstring.

From Phase 2 (`docs/plans/2026-07-19-python-oauth2-port-phase-2.md` → "Global Constraints"):
1. `decode_access_token` keeps `verify_aud=False` and Python passes explicit audiences where needed —
   does **not** copy the Rust jsonwebtoken-v10 stateless-path `InvalidAudience` bug.
2. Invalid/expired/wrong-`iss` `id_token_hint` on logout stays a 400 (`invalid_request` "invalid
   id_token_hint") — Rust silently ignores broken hints; strict is safer and pinned by the existing
   Phase 1 test.
3. Admin token revoke by row id actually resolves the row and revokes it (Rust's is a silent no-op
   because it passes the row id to a value-matching UPDATE).
4. `DenylistGuard` uses `request.client.host` only — no unconditional `X-Forwarded-For` trust (Rust
   trusts it, spoofably).
5. PAR strips `client_secret`/`client_assertion`/`client_assertion_type` before storing the pushed
   params (Rust stores raw credentials in memory).
6. `POST /oauth/device/verify` keeps its Phase 1 JSON responses; only the `GET` page is HTML (Rust
   returns HTML for both).
7. Admin seeding only runs when `OAUTH2_SEED_PASSWORD` is explicitly set (Rust ships an insecure
   default rejected only in production mode).
8. Discovery advertises `request_parameter_supported: false` (JAR is not ported; Rust has JAR and
   advertises `true`). **Superseded by Phase 4b** — JAR (`request=`) is now ported
   (`services/jar.py::process_jar`) and discovery advertises `request_parameter_supported: true`;
   see divergence 41 below.
9. Dashboard summary does not swallow storage errors into zeros; a broken backend 500s.

From Phase 3a (`docs/plans/2026-07-20-python-oauth2-port-phase-3a.md` → "Global Constraints"):
10. Subject-kind denylist entries are ENFORCED (login username/email, client-auth client_id) — Rust
    defines `check_subject_denylisted` but never wires it. Task 2 (commits `53ca096`, `195f9f9`).
11. id_tokens are signed with the keyset's current RS256 key (kid header) instead of the static env
    PEM — fixes the documented Rust rotation trap where rotated deployments break RP id_token
    verification. Task 4 (commits `29e53d3`, `393673b`).
12. Admin single-token revoke, device expire, and key rotation are audited (Rust audits none of them).
    Task 5 (commits `e2a75ca`, `e91ba6d`).
13. Login rate-limiter success resets only the per-username rate-limit key — the per-IP window
    survives a successful login. Rust (and the original Phase 3a Task 1 brief) resets both keys on
    success; this is a deliberate strengthening: one valid credential must not let an attacker reset the
    per-IP throttle mid credential-stuffing run. Task 1 (commit `e5d794d`).

From Phase 3b (`docs/plans/2026-07-20-python-oauth2-port-phase-3b.md` → "Global Constraints"):
14. The DPoP replay store (`services/dpop.py::DpopReplayStore`) is mandatory app state
    (`app.state.dpop_replay`) — there is no silent per-request fallback store that no-ops replay
    protection the way Rust does (it constructs a throwaway store when `app_data` is missing, so a
    misconfigured deployment loses replay protection silently instead of failing to start).
    Task 1 (commits `bf176d0`, `b170b15`).
15. `authorization_details` is validated, not merely JSON-parsed: it must be a JSON array of objects,
    each with a `type` member in the configured allowlist (`rar_types_supported`, default `["openid"]`
    — discovery parity) → violations get 400/redirect `invalid_authorization_details` (RFC 9396 §5).
    Rust accepts any JSON shape with no type enforcement at all (its own audit lists this as backlog
    gap #20). Task 5 (commit `305834a`).
16. At authorization_code redemption, the CONSENTED (auth-code-stored) `authorization_details` wins; a
    conflicting token-request value is rejected with 400 `invalid_authorization_details` (RFC 9396
    §6.1) rather than silently replacing the consented value. Rust lets the token request replace the
    consented value — privilege-escalation-shaped, since the value the user consented to at
    `/oauth/authorize` is not what ends up on the issued token. Task 5 (commit `305834a`).
17. `authorization_details` is echoed in the token response body (RFC 9396 §7.1) and included in
    introspection (§9.2) for active tokens that carry it — Rust does neither. Task 5 (commit
    `305834a`).
18. Token exchange (RFC 8693) validates `subject_token_type` (required, must be
    `urn:ietf:params:oauth:token-type:access_token`) and `requested_token_type` (absent or the same
    access-token URN) → 400 `invalid_request` otherwise. Rust parses both fields and then ignores them
    (`#[allow(dead_code)]`), so an `id_token`/SAML `subject_token_type` silently behaves like an access
    token. Task 6 (commit `1226433`).
19. The `act` claim (`{"sub": <exchanging client_id>}`) is embedded in the issued JWT access token for
    every token-exchange grant, in addition to the response body (RFC 8693 §4.1). Rust only ever puts
    `act` in the response JSON — impersonation is never recorded on the token itself, so a downstream
    resource server decoding the JWT directly (rather than trusting the token-endpoint response) has no
    way to see it was issued via delegation. The response-body `act` member keeps Rust's conditional
    shape (present only when `actor_token` was supplied on that request) for response-format parity.
    Task 6 (commit `1226433`).
20. Client authentication runs BEFORE DPoP proof validation on `POST /oauth/token`
    (`ClientService(storage).authenticate(...)` at the top of `routes/token.py::token`, DPoP header
    read/validated only after it succeeds) — a request with both a bad client secret and a malformed/bad
    DPoP proof gets 401 `invalid_client` and the proof's `jti` is never parsed, let alone burned in the
    replay store. Rust validates the DPoP proof first (`handlers/oauth.rs::token`), so the same request
    there would 400 `invalid_dpop_proof` and could consume replay-store state before client auth ever
    runs. The Python ordering is deliberately DoS-hardening: an unauthenticated caller can't spend replay-
    store entries (or the signature-verification cost of a proof) against a client it doesn't hold
    credentials for.
21. DPoP `htu` is compared against a URL built from `config.issuer` (e.g.
    `config.issuer.rstrip("/") + "/oauth/token"` in `routes/token.py`, same pattern in
    `routes/introspect.py`), not from the incoming request's `Host`/`Forwarded` headers. Rust rebuilds
    the comparison URL from `connection_info()` (scheme/host honoring `Forwarded`/`X-Forwarded-*` per
    actix config) plus the request path. Behind a reverse proxy, `OAUTH2_ISSUER` must be set to the
    externally-visible URL (matching what clients put in their proof's `htu`) or every DPoP-bound request
    will fail `htu` matching — there is no header-reconstruction fallback.

## Phase 3 candidates

Seeded from item 12 above, the still-open minor findings in `.superpowers/sdd/progress.md`, and gaps
noted during Phase 2 implementation. Phase 3a (branch `claude/rust-oauth2-port-phase-3a`, plan
`docs/plans/2026-07-20-python-oauth2-port-phase-3a.md`, Tasks 1–7; see `.superpowers/sdd/progress.md`
"3a Task N" lines for the full per-task ledger) closed most of the items below; the ones still open
after 3a are called out explicitly and carried forward to 3b/3c.

- **Rate limiting** (former item 12) — `/oauth/device/verify` and the token endpoints have no
  rate/attempt limiting.
  **Done (3a) — login only:** Task 1 (commits `f5be8dd`, `e5d794d`) — `FixedWindowLimiter` (per-IP and
  per-username, fixed window) gates `POST /auth/login`; pinned by
  `tests/test_rfc_compliance.py::test_login_rate_limited_after_repeated_failures`. **Still open:**
  `/oauth/token` and `/oauth/device/verify` have no rate/attempt limiting — needs the Rust
  `oauth2-ratelimit` crate researched before porting; deferred to Phase 3c.
- **Subject-kind denylist enforcement is unwired** — `check_subject_denylisted(storage, kind, value)`
  (`src/oauth2_server/middleware.py`) is fully implemented and unit-tested
  (`tests/test_denylist_middleware.py`) but no route calls it; only the IP-based `DenylistGuard`
  middleware is wired into the request path. Login/registration/token issuance don't consult the
  `username`/`email` denylist kinds at all today.
  **Done (3a):** Task 2 (commits `53ca096`, `195f9f9`) — `username`/`email` consulted at login,
  `client_id` consulted at client auth (`ClientService.authenticate`) and `GET /oauth/authorize`; a hit
  gets the identical generic error as "unknown"/"bad credentials" (no oracle). `user_id` stays
  deliberately unwired — nothing authenticates a subject by `user_id` pre-auth. Pinned by
  `tests/test_rfc_compliance.py::test_denylisted_username_blocked_at_login`. New minor(open) surfaced
  during review: client-auth denylist check has a timing asymmetry vs. the unknown-client path, and the
  fail-open behavior lacks an end-to-end test — carried to 3b/3c.
- **Multi-instance persistence for `ParStore` / `KeySet` / `RecentEventsStore`** — all three are
  in-process singletons on `app.state` (see README "Single-process state caveats"); Phase 3 should back
  them with shared storage (DB or Redis) so PAR pushes, key rotation, and the admin events feed work
  correctly behind more than one worker/instance. Note the `signing_keys` table already exists in the
  schema but is intentionally orphaned by both servers today. **Still open** — deliberately out of scope
  for 3a (see the Task 7 self-review); carried to 3b/3c.
- No Postgres integration tests anywhere in the suite (pre-existing gap, noted again at Task 6); the
  whole suite runs against SQLite only, aside from the manual cross-server parity smoke in the README.
  **Still open.**
- `revoke_tokens_by_user_id` (storage layer) has no direct unit test — only indirect coverage via the
  admin bulk-revoke and logout routes that call it. **Still open.**
- `tests/test_admin_tokens.py::test_bulk_revoke_writes_audit_entries` asserts a substring of the audit
  action name rather than a parsed revoked-token count. **Still open.**
- Denylist upsert quirk: `POST /admin/api/denylist` on an existing `(kind, value)` pair returns the
  *new* POST-generated id while the row keeps its original id — a ported Rust quirk, not fixed in
  Python; worth deciding whether to keep parity or fix in Phase 3. **Still open** — deliberately kept as
  Rust parity in 3a (see the Task 7 self-review).
- The denylist-blocked 403 response bypasses the security-headers middleware on `/oauth/*` routes
  (headers are applied after the denylist short-circuit).
  **Done (3a):** Task 6 (commit `56b1b30`) stamped `_SECURITY_HEADERS` directly onto `DenylistGuard`'s
  403 for `/oauth*` paths (it's the outermost middleware layer, so the short-circuit never reaches
  `app.py`'s `security_headers` middleware); pinned by
  `tests/test_denylist_middleware.py::test_middleware_blocked_oauth_response_carries_security_headers`.
  Task 7 review carry-over then widened the same condition to also cover `/admin/api*`, pinned by
  `test_middleware_blocked_admin_api_response_carries_security_headers` (this commit).
- Admin audit entries' `created_by` field could reuse `actor.actor_email` more consistently across
  admin routes (currently set ad hoc per handler). **Still open.**
- `GET /oauth/check_session` inherits `X-Frame-Options: DENY` from the global security-headers
  middleware — currently harmless (no session-management consumer embeds it in an iframe yet), but a
  latent trap if/when that's added; the OP iframe needs to be frameable by the RP. **Still open** —
  deliberately out of scope for 3a (see the Task 7 self-review).
- The disabled-dynamic-registration 403 body shape was never verified against the Rust handler's exact
  shape (Python's choice is secure but unpinned as an intentional-parity assertion). **Still open.**
- PAR entries are consumed (deleted) before login on `GET /oauth/authorize`, matching a Rust parity
  quirk rather than a deliberate Python design choice; `authorize` also still lacks duplicate-query-param
  rejection (Rust has it) and its error pages don't set `Cache-Control: no-store`.
  **Done (3a) — the latter two:** Task 6 (commit `56b1b30`) added duplicate-query-param rejection (any
  repeated `GET /oauth/authorize` query key → 400 `invalid_request` before any other processing,
  including PAR resolution — pinned by `tests/test_authorize.py::test_duplicate_query_parameter_rejected`
  and `tests/test_rfc_compliance.py::test_authorize_rejects_duplicate_query_params`); the no-store header
  on authorize's JSON error responses was verified already present via the existing `/oauth*`
  security-headers middleware coverage (`tests/test_authorize.py::test_authorize_error_response_has_no_store_cache_control`),
  no code change needed. Task 7 review carry-over added
  `tests/test_par.py::test_par_request_uri_duplicate_query_param_does_not_consume_entry`, pinning that a
  duplicated `request_uri` key 400s *without* consuming the PAR entry. **Still open:** PAR entries are
  still consumed before login (Rust parity quirk) — deliberately kept in 3a (see the Task 7 self-review).
- `device.py`'s scope-check inlines a `set(...).issubset(...)` instead of reusing the
  `scope_is_subset` helper in `services/auth.py` (pre-existing inconsistency, cosmetic). **Still open.**
- `anyio` is used directly (`anyio.to_thread` for argon2 off-loading) but is currently only a transitive
  dependency (via `httpx`/`starlette`) — consider pinning it explicitly in `pyproject.toml`.
  **Done (3a):** Task 6 (commit `56b1b30`) — `anyio>=4` added to `pyproject.toml` runtime dependencies.
- **RS256 rotation trap** — id_tokens always sign with the env PEM (never the keyset); after an admin
  RS256 rotation + grace expiry, the initial key drops out of JWKS while the JWKS fallback only fires
  when zero RS256 keys remain — RPs verifying id_tokens via JWKS break silently. Needs either
  keyset-signed id_tokens or the initial PEM key pinned unexpirable.
  **Done (3a):** Task 4 (commits `29e53d3`, `393673b`) — RS256 id_tokens now sign with the keyset's
  current key (kid header from that key) instead of the static env PEM (divergence 11); logout's RS256
  hint verification resolves the hint's `kid` against the keyset (falling back to trying each active
  RS256 key). Pinned by `tests/test_rfc_compliance.py::test_id_token_kid_matches_jwks_after_rotation`
  and `tests/test_jwks_rs256.py::test_id_token_signed_with_current_keyset_key_after_rotation`.
- **Admin sessions have no server-side revocation** — they are client-held signed cookies (role/email
  stamped at login) with no server-side revocation; disable/demote/delete does not terminate a live
  admin session; needs server-side session store or short-TTL re-validation against storage. **Still
  open** — deliberately out of scope for 3a (see the Task 7 self-review).
- **Admin token revoke by id can silently no-op for older rows** — admin `POST /tokens/{id}/revoke`
  resolves via `list_all_tokens` (`LIMIT 200`) — rows older than the newest 200 silently no-op (and
  `GET /tokens/{id}` 404s for them while the paged list can show them); needs a `get_token_by_id`
  storage method.
  **Done (3a):** Task 3 (commit `b3c6081`) — added `get_token_by_id` to the storage Protocol/`SqlStorage`;
  `GET /admin/api/tokens/{id}` and `POST /admin/api/tokens/{id}/revoke` resolve via it instead of
  scanning the newest-200 list.
- **Back-channel logout is awaited inline** — each registered RP's logout_token POST is awaited
  sequentially with a 10s timeout (`routes/logout.py`); N unreachable RPs stall the caller's logout up
  to 10s each. Move dispatch to a background task or bounded gather.
  **Done (3a):** Task 6 (commit `56b1b30`) — dispatch is now `asyncio.gather` over per-client send
  coroutines with `return_exceptions=True`, bounded by a `Semaphore(5)`; pinned by
  `test_backchannel_logout_delivers_to_multiple_clients_concurrently`.
- **Seed-admin password has no strength floor** — `OAUTH2_SEED_PASSWORD` accepts any length in
  `bootstrap.py` while the admin API enforces 8+ characters for user passwords; align the policy.
  **Done (3a):** Task 6 (commit `56b1b30`) — `seed_admin_user` now logs a warning and skips seeding
  (returns `False`) for passwords shorter than 8 characters, matching the admin API floor.
- **Admin PUT handlers skip type validation and the disable cascade** — `PUT /admin/api/users/{id}` and
  `PUT /admin/api/clients/{id}` feed raw JSON into `model_copy(update=...)` (e.g. `{"enabled":"yes"}`
  persists a string, which asyncpg would reject with a 500), and PUT `enabled:false` does not revoke
  tokens while `POST .../enabled` does. Add Pydantic body models and unify the cascade.
  **Done (3a):** Task 5 (commits `e2a75ca`, `e91ba6d`) — both PUT handlers now take all-optional Pydantic
  body models (invalid types → 400 `invalid_request`); PUT `enabled: false` triggers the same
  best-effort token revocation as `POST .../enabled`.
- **Admin client create with a duplicate caller-supplied `client_id`** hits the unique constraint and
  returns a 500; users-create returns a clean 409 — align to 409.
  **Done (3a):** Task 5 (commits `e2a75ca`, `e91ba6d`) — `POST /admin/api/clients` pre-checks via
  `get_client` and returns 409 `already_exists` for a duplicate `client_id`.
- **Negative `limit`/`offset` unvalidated on admin list endpoints** — `limit=-1` becomes `LIMIT -1`
  (unbounded, cap bypass) on SQLite and a 500 on Postgres; add `ge=0` bounds to the query params.
  **Done (3a):** Task 5 (commits `e2a75ca`, `e91ba6d`) — negative `limit`/`offset` are clamped to the
  default/0 in `ListQuery` bounds handling.
- **Audit coverage non-uniform** — admin single-token revoke (`POST /tokens/{id}/revoke`), device
  expire, and key rotation write no audit entries while bulk revokes and CRUD do (Rust parity, but
  worth unifying).
  **Done (3a) (divergence 12):** Task 5 (commits `e2a75ca`, `e91ba6d`) — single-token revoke now audits
  `token.revoke`, device expire audits `device.expire`, and key rotation audits `key.rotate`.
- **Unknown-kid JWT fallback pins HS256 trust to `jwt_secret` forever** — `decode_access_token` falls
  back to the static secret rather than trying active keyset HS256 keys, so HS256 rotation is a no-op
  for stateless decode (impact negligible today — the DB row is authoritative everywhere).
  **Done (3a):** Task 4 (commits `29e53d3`, `393673b`) — before the static-secret fallback,
  `decode_access_token` now tries each active HS256 keyset key on an unresolvable/missing `kid`; pinned
  by `test_hs256_rotation_decodes_with_active_keys`.
- **No Cache-Control headers on `/admin/api/*` responses** — the security-headers middleware only
  covers `/oauth*`; session-authenticated admin GETs are heuristically cacheable.
  **Done (3a):** Task 5 (commits `e2a75ca`, `e91ba6d`) — the app-level `security_headers` middleware now
  also matches `/admin/api` paths; pinned by `test_admin_api_responses_have_no_store`.
- **LIKE search wildcards unescaped in admin search** — `%`/`_` in the search term act as wildcards
  (parameters are bound, so injection-safe; cosmetic result pollution only).
  **Done (3a):** Task 5 (commits `e2a75ca`, `e91ba6d`) — `%`/`_` in `search` are escaped (`ESCAPE '\'`)
  so they match literally; strengthened with wildcard-decoy tests.

### Known DPoP/RAR gaps (Rust parity, deliberate)

Phase 3b (`docs/plans/2026-07-20-python-oauth2-port-phase-3b.md` → "Global Constraints", "Rust gaps
deliberately KEPT") ports DPoP (RFC 9449), RAR (RFC 9396), and token exchange (RFC 8693) while
deliberately KEEPING the following Rust gaps rather than fixing them — recorded here as candidates
for a future Phase 3c/3d hardening pass, not as bugs introduced by the port:

- **No `ath` claim** — the access-token-hash confirmation claim (RFC 9449 §4.3, recommended for
  resource-server-side proof binding at protected resources other than this AS) is never computed or
  required on any DPoP proof.
  **Done (4c):** Task 4 (commit `cd1ec3f`, divergence 50) — `ath` is computed and REQUIRED on
  every proof presented at `/oauth/userinfo`; token/introspect proofs still ignore it.
- **No resource-side DPoP at userinfo** — `GET /oauth/userinfo` accepts a plain `Bearer` token even
  when the underlying access token is `cnf`-bound; only `/oauth/token` (binding) and
  `/oauth/introspect` (binding enforcement) are DPoP-aware.
  **Done (4c):** Task 4 (commit `cd1ec3f`, divergences 51/49) — `/oauth/userinfo` accepts
  `Authorization: DPoP` and enforces `cnf.jkt` (and `cnf.x5t#S256`); unbound tokens keep Bearer.
- **No `dpop_jkt` at authorize/PAR** — RFC 9449 §10 lets a client pre-declare the DPoP key it intends
  to use via a `dpop_jkt` authorization parameter, checked against the actual proof at redemption.
  Neither `GET /oauth/authorize` nor `POST /oauth/par` accept or store it.
  **Done (4c):** Task 5 (commit `9671dd2`, divergence 52) — accepted at authorize (query/PAR/JAR),
  bound and enforced at redemption. **Phase 4d:** persisted in the `authorization_codes.dpop_jkt`
  column (Rust migration `V22`), so it is no longer single-process.
- **Device grant never cnf-bound** — a DPoP proof presented on `POST /oauth/token` with
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` is accepted and validated but its `cnf`
  is discarded; the issued token is always a plain Bearer token. Pinned by
  `tests/test_dpop_token.py::test_device_grant_never_binds_cnf`.
- **Refresh grant carries the old token's `cnf` forward without a fresh proof** — `routes/token.py`'s
  `_salvage_old_cnf` decodes the OLD access token (unverified) and copies its `cnf` onto the new one;
  RFC 9449 doesn't mandate a fresh proof per refresh, but not requiring one means a stolen refresh
  token alone (no DPoP key needed) is enough to keep minting DPoP-labeled tokens. Pinned by
  `tests/test_dpop_token.py::test_refresh_carries_cnf_forward`.
  **Done (4c):** (partly) Task 5 (commit `9671dd2`, divergence 54) — a PUBLIC client must now present
  a fresh proof with the same key, checked before the old token is revoked. CONFIDENTIAL clients
  keep the salvage (their secret is the second factor), so the gap persists for them by design.
- **No `DPoP-Nonce` header on success responses** — RFC 9449 §8 allows (and many deployments use) an
  authorization server that rotates the nonce on every response, including successful ones, so a
  client always has a fresh nonce ready for its next request. This server only ever sends
  `DPoP-Nonce` on the `use_dpop_nonce` 400 challenge; a client must always expect (and handle) one
  challenge/retry round trip per proof, never a proactively-refreshed nonce on a 200.
  **Done (4c):** Task 5 (commit `9671dd2`, divergence 53) — a successful token/userinfo response
  carries a fresh `DPoP-Nonce` when the client has `dpop_nonce_required` and sent a valid proof.
- **Opaque-token mode silently drops `cnf`/`authorization_details` from both the JWT and the response
  body** — `access_tokens_opaque` is a Python-only mode with no equivalent in Rust; an opaque access
  token is a bare random string with nowhere to carry either claim, so `TokenService.issue` drops both
  before building the `TokenResponse`, and the response-body echoes (RAR §7.1) disappear along with the
  JWT claims for these two. Pinned by `tests/test_dpop_token.py::test_opaque_mode_drops_cnf_silently`
  and `tests/test_rar.py::test_opaque_mode_drops_authorization_details`. **`act` is the exception**: the
  token-exchange handler (`routes/token.py`) computes `act` locally and sets
  `body["act"] = act` unconditionally (gated only on `actor_token` having been supplied, not on opaque
  mode) — so in opaque mode the response-body `act` member still survives; only the JWT claim embedding
  (`TokenService.issue`'s `bound_act`) is dropped.
- **Flat `act` on exchange chains** — if a token issued by one token-exchange call is itself later
  used as the `subject_token` of a second exchange, the resulting `act` claim is overwritten with the
  second exchanging client rather than nested per RFC 8693 §4.1's `act.act` delegation-chain shape.
  Noted at Task 6 review (`.superpowers/sdd/progress.md` "3b Task 6" minor(open)) — no test currently
  exercises a two-hop exchange chain.
  **Done (4c):** Task 6 (commit `66d174e`, divergence 55) — `act` now nests per RFC 8693 §4.1; the
  same client re-exchanging collapses instead of nesting, and chains deeper than 10 are
  `invalid_request`.
- **Introspection via a refresh-token value skips the `cnf` binding check** — `POST /oauth/introspect`
  decodes the PRESENTED `token` value for its unverified-claims `cnf` lookup (`routes/introspect.py`);
  when that value is an opaque refresh token rather than the JWT access token, `jwt.decode` fails, so
  `cnf`/`jkt` come back empty and the whole DPoP-binding-required block is skipped even though the
  underlying access token IS cnf-bound. Sibling of the refresh-grant `cnf`-carry gap above (a
  refresh-token holder can already mint a fresh bound access token via the refresh grant without a
  proof) — already called out inline in `routes/introspect.py`, recorded here for the doc-level ledger.
- **RFC 9728 OAuth protected-resource metadata not ported** — Rust discovery advertises
  `dpop_signing_alg_values_supported` on both `/.well-known/openid-configuration` AND a
  `/.well-known/oauth-protected-resource` document (research-dpop.md); this port has no
  protected-resource metadata endpoint at all. Relatedly, token exchange (`routes/token.py`) never reads
  or validates a `resource` request parameter — RFC 8707 (Resource Indicators) is entirely absent
  server-wide, not just from token exchange.
  **Done (4a):** `GET /.well-known/oauth-protected-resource` is now implemented, and `resource`
  (RFC 8707) is validated and bound to the issued access token's `aud` on every grant — see the
  README "Phase 4a" section and divergences 32–33 above. The JAR/`request` parameter remains
  unported, tracked for Phase 4b.

### Known Phase 3c gaps (deliberate)

Phase 3c (`docs/plans/2026-07-20-python-oauth2-port-phase-3c.md` → "Global Constraints", "Rust
gaps deliberately KEPT" and "Kept-out-of-scope") ports Prometheus metrics, rate
limiting/resilience, the event bus, and social login while deliberately KEEPING the following
gaps rather than fixing/porting them — recorded here as candidates for a future hardening pass,
not as bugs introduced by the port:

- **Redis Streams / Kafka / RabbitMQ event backends not ported** — Rust's `oauth2-events` crate
  feature-gates additional publish backends beyond `console`/`in_memory`; only those two (plus
  the always-appended `RecentEventsPlugin` bridge) are implemented here.
  `OAUTH2_EVENTS_BACKEND` accepts only `console`/`in_memory`/`both`; anything else falls back to
  `in_memory` with a logged warning rather than erroring.
- **Bulkheads not ported** — Rust's per-resource bulkhead limiter (`bulkhead_rejected_total`
  metric family) is configured entirely from a config file with no env-var surface in the Rust
  server either; it was out of scope for this env-var-only Python port from the start and stays
  registered-but-unwired (see divergence 24 above).
- **OTel span export not ported** — the Rust server's OpenTelemetry tracing/span-export
  integration has no Python equivalent; structured logging with trace ids would be the natural
  next step but is a large separate effort, noted as a Phase 3d/later candidate rather than
  attempted here.
- **Most parity-only metric families stay unwired** — see divergence 24 and the README "Metrics
  registered but not wired" table for the full 12-family list (`db_*`, `oauth_clients_total`,
  `oauth_active_tokens`, `errors_total`, `http_client_*`, `events_published_*`, `redis_client_*`,
  `bulkhead_rejected_total`).
- **RFC 8628 `slow_down` not implemented** — the device authorization grant's polling endpoint
  (`grant_type=urn:ietf:params:oauth:grant-type:device_code`) never returns `slow_down`; a
  client polling faster than `interval` only ever sees `authorization_pending`, never the
  `slow_down` escalation §3.5 describes for repeated over-fast polling — matching a gap already
  present in the Rust server (not introduced or fixed by Phase 3c).
  **Done (4a) (divergence 35):** `services/device_poll.py::DevicePollTracker` now enforces
  `slow_down`, growing the required interval by 5 s per violation — see the README "Phase 4a"
  section.
- **No social account-linking by email** — a social login always provisions/matches on
  `username = "{provider}:{provider_user_id}"`; there is no lookup-or-merge against an existing
  local (password-based) account that happens to share the same verified email address. Logging
  in with Google and then with GitHub using the same email address creates two independent
  `User` rows.
  **Done (4c):** (opt-in) Task 7 (commits `aa8b469`, `c4c3861`, `12e7ea5`, divergence 56) — with
  `OAUTH2_SOCIAL_LINK_BY_VERIFIED_EMAIL=true`, a provider-verified email links to a single
  matching, non-admin, enabled local account. Default false. Provider-to-provider convergence
  follows from the same rule rather than being special-cased: with the flag ON, the first login
  provisions a `github:<id>` row carrying the verified email, and a later Google login asserting
  that same verified email matches that single row and signs into it — so two providers converge
  on one account. With the flag OFF, each provider keeps its own independent
  `{provider}:{provider_user_id}` row.
- **No `id_token`/nonce validation for social providers** — identity is established purely via
  each provider's authenticated userinfo REST endpoint (Google `/oauth2/v2/userinfo`, Microsoft/
  Azure Graph `/me`, GitHub `/user` + `/user/emails`), never by validating a provider-issued
  OIDC `id_token`'s signature/`nonce`/`aud` — matching Rust, which takes the same
  REST-userinfo-only approach.
- **`http_client_requests_total`/`http_client_request_duration_seconds` unwired for social
  outbound calls** — the social login provider HTTP calls (token exchange, userinfo fetch) do
  not increment the parity-only `http_client_*` metric families listed above, even though those
  families exist specifically to describe outbound HTTP client traffic; they remain
  registered-and-seeded only (see divergence 24).

From Phase 3c (`docs/plans/2026-07-20-python-oauth2-port-phase-3c.md` → "Global Constraints"):
22. `/metrics` content-type is pinned to the literal `text/plain; version=0.0.4`, with the
    `charset=utf-8` suffix `prometheus_client`'s own `CONTENT_TYPE_LATEST` normally appends
    stripped off — exact byte-parity with the Rust exposition's content-type header.
    Task 1 (commits `4e724c8`, `c50dec8`). Related: the three metric families whose Rust names
    lack a `_total` suffix despite being monotonic counters — `oauth_authorization_codes_issued`,
    `oauth_failed_authentications`, and `http_requests_total_by_route` (the last one already
    HAS `_total`, just not at the end) — are implemented as `prometheus_client` `Gauge`s rather
    than `Counter`s specifically so the emitted name matches Rust byte-for-byte;
    `Counter`'s constructor unconditionally appends a literal `_total` unless the declared name
    already ENDS with `_total`, which would otherwise mangle the first two into
    `..._issued_total`/`..._authentications_total` and double up the third into
    `..._by_route_total`. Each is still only ever `.inc()`'d (never `.dec()`/`.set()` to a
    smaller value), so the *scrape value line* is byte-identical to Rust's `IntCounter` output
    either way — the only observable difference is the `# TYPE` line, which reads
    `# TYPE oauth2_server_<name> gauge` here vs. Rust's `counter`. See
    `services/metrics.py`'s module docstring for the full mechanics.
23. Login rate limiting (`OAUTH2_LOGIN_RATE_LIMIT_*`, Phase 3a) is already env-tunable, where
    Rust's equivalent is hardcoded. Kept as-is; no code change in Phase 3c.
24. The parity-only metric families (`db_*`, `oauth_clients_total`, `oauth_active_tokens`,
    `errors_total`, `http_client_*`, `events_published_*`, `redis_client_*`,
    `bulkhead_rejected_total`) are registered and bootstrap-seeded but not wired at any request
    site — matching Rust's actual behavior (register-for-scrape-parity; see README "Metrics
    registered but not wired"). **Exception:** `rate_limit_rejected_total` /
    `rate_limit_remaining` (limiter middleware) AND `circuit_breaker_state` /
    `circuit_breaker_trips_total` / `back_pressure_rejected_total` /
    `concurrent_requests_in_flight` (resilience middleware) ARE wired in this port — a small
    behavioral improvement over Rust's dashboard-only intent, since both middlewares were built
    fresh in Task 2. Task 1 (commits `4e724c8`, `c50dec8`); Task 2 (commit `712d906`).
25. Okta/Auth0 remain 503 stubs with the same body text as Rust ("Okta login not yet
    implemented" / "Auth0 login not yet implemented"); Azure remains a Microsoft-config alias
    (`config.azure.or(config.microsoft)`, own tenant id). Task 4 (commits `0c3aa20`, `ddfe1b6`).
26. The social callback SETS `auth_time` in the session (Rust omits it for social sessions,
    which breaks OIDC `max_age` re-authentication checks for any user who logged in via a
    social provider) — a correctness fix over Rust, not a parity gap. The callback also clears
    `csrf_token`/`pkce_verifier`/`provider` from the session after a successful exchange (Rust
    leaves them, reusing the same session keys PKCE/CSRF state occupies) — a second, related
    improvement. Task 4 (commits `0c3aa20`, `ddfe1b6`).
27. Social provisioning REQUIRES a verified provider email — Google's userinfo `verified_email`
    must be `true` (`services/social.py`), and GitHub's provisioned email must come from
    `/user/emails` with both `primary` AND `verified` true (an unverified/unconfirmed GitHub
    primary email is rejected even though GitHub's API happily returns one). Rust provisions
    unconditionally off whatever email the provider's userinfo endpoint returns, verified or
    not. Stricter than Rust: some users Rust would silently provision an account for now get a
    400 instead — a deliberate hardening (an attacker-controlled unverified email would let
    someone provision/claim an account for an address they don't actually own), not a bug.
    Task 4 (commit `ddfe1b6`).

From Phase 3d (`docs/plans/2026-07-20-python-oauth2-port-phase-3d.md` → "Global Constraints") —
adds a second `Storage` backend, `MongoStorage` (`storage/mongo.py`, motor), selected by a
`mongodb://`/`mongodb+srv://` scheme on `OAUTH2_DATABASE_URL` via `storage/factory.py::
create_storage`. See the README "Phase 3d: MongoDB Backend" section for the full user-facing
writeup (install, backend selection, caveats).

28. `revoke_token_family` and `revoke_tokens_by_user_id` ARE implemented on `MongoStorage`
    (`update_many` on `token_family`/`user_id`, returning `modified_count`) — Rust's Mongo
    backend leaves both as no-op trait defaults, silently breaking RFC 9700 §4.13.2
    refresh-token-replay cascade revocation and OIDC-logout revocation whenever Mongo is the
    backend. This port does not copy that gap: proven end-to-end (not just at the storage-unit
    level) by `tests/test_mongo_e2e.py::test_mongo_e2e_auth_code_refresh_and_family_cascade`,
    which drives a real authorization_code → refresh → refresh-replay sequence over HTTP against
    `MongoStorage` and asserts a sibling (rotated-in) access token goes inactive on introspection
    after the replay. Task 3 (commit `32faec8`); e2e proof Task 5.
29. Denylist (`denylist` collection) and audit-log (`audit_log` collection) storage methods ARE
    implemented on `MongoStorage`. The `/admin/api/capabilities` endpoint reports
    denylist/audit_log as available on both backends (hardcoded `True`, see
    `routes/admin/dashboard.py`), and the Mongo backend actually implements the denylist/audit
    storage methods — unlike Rust, whose Mongo backend stubs both as no-op trait defaults, silently
    disabling the admin denylist/audit features whenever Mongo is the backend. Kept working here; proven
    end-to-end (real `DenylistGuard` 403, not just a storage-layer lookup) by
    `tests/test_mongo_e2e.py::test_mongo_e2e_denylist_blocks_request`. Task 4 (commits `1801e38`,
    `635599b`); e2e proof Task 5.
30. Single-claim atomicity: `mark_authorization_code_used`/`mark_device_authorization_used` use
    `find_one_and_update({..., used: false}, {$set: {used: true}})` (atomic, returning 1 if
    claimed / 0 if already used) — Rust's Mongo backend does a bare, non-atomic `update_one` with
    no `used: false` predicate anywhere in that code path, leaving a check-then-act double-spend
    race. This matches the SQL backend's existing atomic single-claim guard. Task 3 (commit
    `32faec8`).
31. `mongodb+srv://` (DNS-SRV discovery, e.g. MongoDB Atlas) IS supported and selects
    `MongoStorage` — Rust hard-rejects it (a hickory-proto DNS-resolver security advisory that
    doesn't apply to this driver/motor stack). Task 1 (commit `c08c550`).

From Phase 4a (`docs/plans/2026-09-20-python-oauth2-port-phase-4a.md` → "Global Constraints"):
32. `resource` values are validated (absolute URI, no fragment) and rejected with
    `invalid_target` (RFC 8707 §2) — Rust accepts any string. Task 2 (commits `0667c65`,
    `6bbd22e`).
33. Discovery and protected-resource metadata do NOT advertise
    `tls_client_certificate_bound_access_tokens`, `tls_client_auth`, or
    `self_signed_tls_client_auth` until Phase 4c implements them — Rust advertises all
    three. Likewise `request_parameter_supported`, `response_modes_supported`,
    `response_types_supported: ["code", "code id_token"]`, `acr_values_supported`,
    `request_object_signing_alg_values_supported` stay at their Phase 3 values until 4b.
    Kept as-is; no code change in Phase 4a.
34. RFC 9701: an `Accept: application/token-introspection+jwt` caller gets a signed JWT
    for BOTH active and inactive results — Rust only wraps the active path and returns
    plain JSON `{"active": false}` otherwise. Signing is **security over parity**: Rust
    signs with the server's own secret, which the relying party does not hold and
    therefore cannot verify. The rule here (RFC 9701 §5 + OIDC Core §10.1) is: the
    keyset's current RS256 key with its `kid` whenever one exists — regardless of
    `id_token_alg`, since that key is published in JWKS; else HS256 under the REQUESTING
    CLIENT's own `client_secret` (never `jwt_secret`); else — a public client with no
    RS256 key, so no key it could verify with — `invalid_request` 400 rather than a
    silent downgrade to unauthenticated JSON. Discovery advertises
    `introspection_signing_alg_values_supported: ["RS256", "HS256"]` (RFC 9701 §7).
    Task 4 (commit `b247529`), rule revised in Phase 4a hardening.
35. RFC 8628 §3.5 `slow_down` is implemented (Rust never returns it — recorded as a shared
    gap in "Known Phase 3c gaps"). The required interval grows by 5 s per `slow_down`.
    Task 5 (commit `2c034c3`).
36. A JWT client assertion may omit form `client_id`; the client is then resolved from the
    assertion's `sub` (RFC 7523 §2.2 says `client_id` is unnecessary). Rust requires
    `client_id` in the form. Task 1 (commits `1fc7171`, `4537833`).

From Phase 4b (`docs/plans/2026-09-20-python-oauth2-port-phase-4b.md` → "Global Constraints"):
37. Every redirect-channel error honors `response_mode` (Rust's `prompt=none`/`login_required` path
    ignores `fragment`, and its `acr_values` step-up path ignores both `fragment` and `form_post`).
    `form_post` error responses also carry `Cache-Control: no-store` + `Pragma: no-cache` like the
    success path. Task 1 (commit `1d592f0`).
38. `form_post` attribute escaping also escapes `'` (`&#x27;`) — Rust's `html_escape_attr` does
    not. Task 1 (commit `1d592f0`).
39. Hybrid `code id_token` REQUIRES `nonce` (OIDC Core §3.3.2.11); missing → redirect error
    `invalid_request` / "nonce is required for response_type=code id_token". Rust issues the
    id_token without it. Task 2 (commit `6de85cb`).
40. The hybrid id_token uses the same minter and TTL as the token endpoint's id_token
    (`config.access_token_ttl_secs`) and carries `acr`, `amr`, `auth_time` from the session; Rust
    hardcodes `exp = now + 3600` and omits those claims. Task 2 (commit `6de85cb`).
41. JAR verification failures use error code `invalid_request_object` (RFC 9101 §6.3.1) instead of
    Rust's `invalid_request`; structural/unsupported cases (not a JWT, unsupported auth method, and
    — on the `none` path — `alg` not literally `none` or a non-empty signature) stay
    `invalid_request`, and only signature/claim verification failures (bad HS256/RS256 signature,
    missing/mismatched `iss`/`aud`/`exp`/`client_id`) use `invalid_request_object`. A JAR
    `client_id` claim, when present, MUST equal the query `client_id` (RFC 9101 §6.3 — Rust never
    checks it). This also supersedes divergence 8 above: `request_parameter_supported` is now
    `true`. Task 3 (commits `f3a28ce`, `1049f84`, `9fab2c4`).
42. Login stamps `acr = urn:mace:incommon:iap:bronze` and `amr = ["pwd"]` (social login:
    `amr = ["fed"]`) into the session; `acr_values_supported` is config-driven
    (`OAUTH2_ACR_VALUES_SUPPORTED`, default `["urn:mace:incommon:iap:bronze"]`) and advertises only
    achievable values. Rust advertises silver+bronze but never sets `acr`, so every `acr_values`
    request fails. Task 5 (commit `595ae62`).
43. `request_object_signing_alg_values_supported` advertises `["RS256", "HS256", "none"]` — what is
    implemented — not Rust's `["RS256", "ES256", "HS256"]` (ES256 unimplemented there, `none`
    implemented but unadvertised). Task 7 (this task).
44. `claims` is validated as a JSON object (malformed → 400/redirect `invalid_request` "claims must
    be a JSON object") before being stored verbatim on the code; `claims_parameter_supported` is
    NOT advertised because the stored value is not yet honored at userinfo/token (Rust: stored
    unparsed, never read). Task 6 (commit `0b9da00`).
45. Fragment encoding uses `urllib.parse.urlencode(..., quote_via=quote)` (RFC 3986 unreserved set
    kept, never `+`); Rust percent-escapes all non-alphanumerics. Functionally equivalent after
    decoding. Task 1 (commit `1d592f0`).
46. Hybrid `code id_token` rejects an explicit `response_mode=query` with 400 `invalid_request`
    (OIDC Core §3.3.2.3 MUST NOT deliver an id_token in the query string); Rust accepts it. Task 2
    (commit `7926ca3`).

From Phase 4c (`docs/plans/2026-09-20-python-oauth2-port-phase-4c.md` → "Global Constraints"):
47. `X-Client-Cert-Thumbprint` / `X-SSL-Client-S-DN` are honored ONLY when
    `config.trust_proxy_headers` (`OAUTH2_SERVER_TRUST_PROXY_HEADERS`) is true; otherwise both are
    treated as absent (mTLS clients then fail closed with the "certificate missing" error). Rust
    reads them unconditionally, so anyone reaching the app directly can forge client auth and a
    `cnf` binding. Task 1 (commit `a032f56`).
48. `self_signed_tls_client_auth` verifies the presented thumbprint against the client's registered
    JWKS (a key whose `x5t#S256` member equals the header value); no JWKS or no match →
    `invalid_client` "self_signed_tls_client_auth: certificate does not match a registered JWK"
    (RFC 8705 §2.2). Rust accepts any thumbprint. Task 2 (commit `efed63b`).
49. Certificate-bound (`cnf.x5t#S256`) access tokens are ENFORCED at introspection and userinfo
    (RFC 8705 §3.2): the request must carry a matching `X-Client-Cert-Thumbprint` (subject to
    divergence 47). Rust binds but never enforces. Tasks 3+4 (commits `6985733`, `bc7bf4f`,
    `cd1ec3f`).
50. DPoP proofs presented at userinfo MUST carry `ath` = base64url(SHA-256(access token))
    (RFC 9449 §4.3); token/introspect proofs ignore `ath`. Task 4 (commit `cd1ec3f`).
51. `GET|POST /oauth/userinfo` accepts `Authorization: DPoP <token>` and enforces `cnf.jkt`
    (RFC 9449 §7.1/§7.2): a bound token presented as Bearer, without a proof, with an invalid
    proof, an `ath` mismatch, or a `jkt` mismatch → 401 `WWW-Authenticate: DPoP
    error="invalid_token"` with distinct `error_description`s. Unbound tokens keep Bearer
    behavior. Task 4 (commit `cd1ec3f`).
52. `dpop_jkt` (RFC 9449 §10) is accepted at authorize (query/PAR/JAR overlay), validated as a
    43-char base64url string, bound to the code (originally in an in-process store; Phase 4d moved
    it to the `authorization_codes.dpop_jkt` column, Rust migration `V22`, so it holds across
    instances), and enforced at redemption: missing proof or `jkt` mismatch → `invalid_grant`.
    Task 5 (commit `9671dd2`).
53. `DPoP-Nonce` is set on SUCCESSFUL token and userinfo responses when the client has
    `dpop_nonce_required` and presented a valid proof (RFC 9449 §8). Rust/Python 3b only sent it on
    the `use_dpop_nonce` challenge. Task 5 (commit `9671dd2`).
54. Public-client refresh of a `jkt`-bound token requires a fresh DPoP proof with the SAME key
    (RFC 9449 §5); otherwise `invalid_grant`, checked before the old token is revoked. Confidential
    clients keep the salvage behavior. Task 5 (commit `9671dd2`).
55. RFC 8693 §4.1 `act` chains nest: a subject token already carrying `act` yields
    `{"sub": <exchanging client>, "act": <prior act>}`; the same client re-exchanging collapses
    instead of nesting; chains deeper than 10 → `invalid_request`. Response-body `act` echoes the
    JWT claim (Rust never writes `act` to the JWT). Task 6 (commit `66d174e`).
56. Social login may link to an existing local account by email only when ALL hold:
    `OAUTH2_SOCIAL_LINK_BY_VERIFIED_EMAIL=true` (default false), the provider asserts a verified
    email (Google, GitHub; never Microsoft/Azure), the folded emails match exactly, exactly one
    local row matches, that row is neither `role == "admin"` nor in `config.admin_emails`, and the
    row is enabled. Linking is implicit (no provider-link record; the row's username is untouched).
    Task 7 (commits `aa8b469`, `c4c3861`, `12e7ea5`).
57. Client-supplied JSON/URI parameters are bounded: `claims` ≤ 8192 / depth 10,
    `authorization_details` ≤ 16384 / depth 10, `resource` ≤ 2048 characters; violations use each
    parameter's existing error channel/code with the text "`<name>` exceeds the maximum length of
    N characters" / "… nesting depth of 10"; `RecursionError` is never reachable. Tasks 1+8
    (commit `a032f56` + this task).
58. Admin client create/update validate every `redirect_uris`/logout-URI element with the same rule
    DCR uses (an empty admin `redirect_uris` list stays allowed). The admin API also accepts and
    persists `backchannel_logout_uri`/`frontchannel_logout_uri`/`post_logout_redirect_uris`, which
    were previously settable only through RFC 7591 registration. Task 8 (this task).
59. The stored `claims_request` is honored for the id_token minted at code redemption: `acr`,
    `auth_time`, `email`, `preferred_username` under the `id_token` member, only when the granted
    scope already permits the claim (never widening), `essential` unmet → still succeed,
    `value`/`values` mismatch → omit. `acr`/`auth_time` have no session value at the token endpoint
    and are therefore always absent there. The `userinfo` member is NOT yet honored and
    `claims_parameter_supported` stays unadvertised. Task 8 (this task).
60. Refresh enforces RFC 8707 §2.2: a `resource` not in the old token's `aud` → `invalid_target`
    before any revocation; no `resource` → the old `aud` is carried forward instead of widening to
    `[client_id]`; opaque/non-JWT old tokens keep the previous behavior. Task 8 (this task).

### Known Phase 3d gaps (deliberate/parity, MongoDB backend)

- **App-side full-collection scans for every list/page method.** `list_all_*`/`list_*_page`/
  `list_denylist`/`list_audit_log` all `find({})` the whole collection, then sort/filter/page in
  Python — no server-side `$sort`/`$skip`/`$limit` aggregation pipeline. O(collection size) per
  call; matches the Rust Mongo backend's own choice (Azure Cosmos DB for MongoDB compatibility —
  Cosmos's aggregation-pipeline support is more limited than real MongoDB's).
- **No TTL indexes.** Expired tokens/authorization codes/device authorizations/denylist entries
  are never automatically purged — they accumulate until an operator prunes them manually (or a
  future migration adds `expireAfterSeconds` indexes). The SQL backend has the same gap (no
  scheduled cleanup job either); MongoDB TTL indexes are the idiomatic fix and aren't wired up.
- **`token_family` has no index** — `revoke_token_family`'s `update_many({token_family: ...})`
  is a full collection scan on `tokens` (Rust parity: the Rust Mongo backend's index list doesn't
  cover `token_family` either).
- **Duplicate-key error shape diverges from SQL.** `MongoStorage` catches
  `pymongo.errors.DuplicateKeyError` and raises `invalid_request` "duplicate key" (an
  `OAuthError`, handled cleanly by routes); `SqlStorage`'s equivalent violation surfaces as an
  unhandled `IntegrityError` → 500. In practice this SQL-side 500 path is unreachable through
  normal request flow because every write site pre-checks uniqueness before insert — noted as an
  existing (not newly introduced) asymmetry between the two backends, not a regression.
- **Denylist upsert is non-atomic.** `add_denylist_entry`'s "keep the original row's `id` on a
  `(kind, value)` conflict" is a `find_one` then `replace_one(upsert=True)` — two round trips,
  not one atomic operation. A benign race under concurrent admin writes to the same
  `(kind, value)` pair (admin-only, low-traffic surface). Rust's own Mongo backend has the same
  non-atomicity.
- **No in-memory Mongo fake** — `mongomock-motor` was evaluated as a dev-convenience fast path but
  deliberately NOT adopted (and removed from the dev deps), because it diverges from real MongoDB
  on the two behaviors `MongoStorage` depends on: the unique-index `E11000` error shape
  (duplicate-key detection) and the `$type` query operator (`_normalize_legacy_timestamps`'s
  BSON-date healer). The contract suite (`tests/test_mongo_storage.py`, `tests/test_mongo_admin.py`,
  `tests/test_mongo_e2e.py`) therefore ALWAYS runs against a real `mongo:7.0` via `testcontainers`
  (gated on `RUN_TESTCONTAINERS=1`, run in the CI `db-tests` job); the default `gate` job stays
  SQLite-only and Docker-free.
- **No Postgres-equivalent cross-server parity smoke automated in CI** — `scripts/
  mongo_parity_smoke.sh` (documentation-grade, manually run) proves client_credentials +
  introspect + revoke over real HTTP against a real mongod; it is intentionally NOT wired into
  `scripts/gate.sh` or the CI `db-tests` job (mirrors the existing Postgres cross-server smoke in
  the README, which is also manual-only).

## Phase 4 roadmap

Full detail: `docs/plans/2026-09-20-python-oauth2-port-phase-4a.md` → "Phase 4 design (roadmap)".
Phase 4 closes the remaining Rust-vs-Python gaps (this backlog's divergence 8 and the "Known …
gaps" sections above) plus a few RFC gaps both servers share, in three sub-phases, each its own
branch/PR:

| Sub-phase | Scope |
|---|---|
| **4a** (this phase) | RFC 7523 JWT client auth (`client_secret_jwt`, `private_key_jwt`) + jti replay + `jwks_uri` cache; RFC 8707 resource indicators → `aud`; RFC 9728 protected-resource metadata + status-list stub + discovery/userinfo field parity; RFC 9701 JWT introspection responses; RFC 8628 `slow_down`. |
| **4b** (done) | Authorize front-channel parity: `response_mode` `query`/`form_post`/`fragment`; OIDC hybrid `code id_token`; JAR `request` objects (unsigned public / HS256 / RS256-via-client-JWKS); `acr_values` step-up (RFC 9470) + `claims` request + `acr`/`amr`/`auth_time` claims. |
| **4c** (done) | RFC 8705 mTLS (`tls_client_auth`, `self_signed_tls_client_auth`, `X-Client-Cert-Thumbprint`/`X-SSL-Client-S-DN`, `cnf.x5t#S256` bound AND enforced); DPoP hardening beyond Rust (`ath`, resource-side DPoP at userinfo, `dpop_jkt` at authorize/PAR, `DPoP-Nonce` on 200s, fresh proof on public-client refresh); nested `act` chains; opt-in social account-linking by verified email; the Phase 4b residuals (input caps, admin redirect validation, `claims` in the id_token, refresh `aud` subset). Divergences 47–60. |

Out of scope for all of Phase 4 (unchanged from earlier phases): Redis/Kafka/RabbitMQ event
backends, bulkheads, OTel span export, multi-instance persistence of in-process stores,
admin-session server-side revocation.

**Phase 4d (done)** closed the five items that remained after 4c — divergences 61–64 (52 amended):

61. `mtls_endpoint_aliases` (RFC 8705 §5) is advertised when `OAUTH2_MTLS_ENDPOINT_BASE_URL` is set
    AND `trust_proxy_headers` is on: token, revocation, introspection, userinfo, device
    authorization and PAR endpoints re-based onto that host. Never for browser-facing endpoints.
    Rust advertises none.
62. `/oauth/userinfo` enforces DPoP nonces (RFC 9449 §9) for a DPoP-bound token whose client has
    `dpop_nonce_required`: a missing/stale nonce → 401 `WWW-Authenticate: DPoP error="use_dpop_nonce"`
    with a fresh `DPoP-Nonce`; a forged one → `invalid_token`. (The item previously described as
    "no nonce enforcement at userinfo".)
63. The `userinfo` member of the `claims` request is honored at `/oauth/userinfo`, via the token's
    `token_family` → authorization code (`get_authorization_code_by_token_family`), with the same
    never-widen semantics as divergence 59 (`email`/`preferred_username` only; `value`/`values`
    mismatch omits). `claims_parameter_supported` is now advertised. Tokens without a family/code
    (client_credentials, exchange) simply have no claims request.
64. PKCE is required for confidential clients too (Rust parity): `/oauth/authorize` and PAR without
    `code_challenge` → `invalid_request`; a stored code with no challenge is refused at redemption
    with `invalid_grant`. This is a **breaking change for confidential clients that never sent PKCE**.
52 (amended). `dpop_jkt` is persisted on the code row — Rust migration `V22__add_dpop_jkt_to_auth_codes.sql`
    (vendored here; authored in the Rust repo, the schema owner). `app.state.dpop_code_bindings` and
    `services/dpop_bindings.py` are gone.

Still out of scope: `request_uri`-as-JAR-URL, and the parity-only items listed above.

### Remaining Phase 4b gaps (carried to 4c or later)

- ~~`claims` … not yet honored at `/oauth/userinfo` or `/oauth/token`~~ — **id_token half done
  (4c)**, Task 8 (divergence 59): the stored request is honored for the id_token minted at code
  redemption (scope-gated, never widening; `value`/`values` mismatch omits the claim). The
  `userinfo` member is honored as of **4d** (divergence 63), and `claims_parameter_supported`
  is now advertised.
- ~~PKCE is still required only for public clients~~ — **Done (4d)**, divergence 64.
- `request_uri=` (RFC 9101 §5.2, a JAR fetched from a URL rather than passed inline via
  `request=`) remains unsupported; only PAR's own `request_uri` value is accepted at
  `/oauth/authorize`.
- ~~No size cap on `claims`/`authorization_details`/`resource`; deep nesting can raise
  `RecursionError`~~ — **Done (4c)**, Tasks 1+8 (divergence 57): `services/limits.py` bounds
  length and nesting depth (`claims` 8192/10, `authorization_details` 16384/10, `resource` 2048)
  at every call site, before `json.loads` runs.
- ~~`POST`/`PUT /admin/api/clients` do not validate the submitted `redirect_uris`~~ —
  **Done (4c)**, Task 8 (divergence 58): both now run the shared
  `services/clients.py::is_valid_redirect_uri` over `redirect_uris` and the logout URIs (which
  the admin API also accepts and persists now). An empty `redirect_uris` list stays allowed.

### Residuals from the Phase 4a final review (parked, non-blocking)

- Neither `POST /admin/api/clients` nor dynamic registration enforces a minimum
  `client_secret` length, so an admin-created client can carry a short secret — which is now
  also the HMAC key for that client's RFC 9701 introspection JWTs (divergence 34). PyJWT only
  warns (`InsecureKeyLengthWarning`) and still signs. A generated-secret floor (or rejecting
  short operator-supplied secrets) is a zero-migration Phase 4b/4c item.
- Admin `POST /admin/api/clients` echoes `jwks` as the submitted object while `GET` returns the raw
  stored JSON string (module convention) — shapes disagree between create and detail.
- Admin `PUT` now validates `token_endpoint_auth_method` against the merged row, so a legacy row with
  an unknown method 400s on any update until a valid method is supplied in the same call.
- ~~Refresh without `resource` widens `aud` back to `client_id`~~ — **Done (4c)**, Task 8
  (divergence 60): the old token's `aud` is carried forward and a `resource` outside it is
  `invalid_target` (before any revocation). Still open: `userinfo` validates via the storage row
  and accepts resource-bound tokens regardless of `aud`.
