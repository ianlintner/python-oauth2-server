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
   advertises `true`).
9. Dashboard summary does not swallow storage errors into zeros; a broken backend 500s.

## Phase 3 candidates

Seeded from item 12 above, the still-open minor findings in `.superpowers/sdd/progress.md`, and gaps
noted during Phase 2 implementation:

- **Rate limiting** (former item 12) — `/oauth/device/verify` and the token endpoints have no
  rate/attempt limiting.
- **Subject-kind denylist enforcement is unwired** — `check_subject_denylisted(storage, kind, value)`
  (`src/oauth2_server/middleware.py`) is fully implemented and unit-tested
  (`tests/test_denylist_middleware.py`) but no route calls it; only the IP-based `DenylistGuard`
  middleware is wired into the request path. Login/registration/token issuance don't consult the
  `username`/`email` denylist kinds at all today.
- **Multi-instance persistence for `ParStore` / `KeySet` / `RecentEventsStore`** — all three are
  in-process singletons on `app.state` (see README "Single-process state caveats"); Phase 3 should back
  them with shared storage (DB or Redis) so PAR pushes, key rotation, and the admin events feed work
  correctly behind more than one worker/instance. Note the `signing_keys` table already exists in the
  schema but is intentionally orphaned by both servers today.
- No Postgres integration tests anywhere in the suite (pre-existing gap, noted again at Task 6); the
  whole suite runs against SQLite only, aside from the manual cross-server parity smoke in the README.
- `revoke_tokens_by_user_id` (storage layer) has no direct unit test — only indirect coverage via the
  admin bulk-revoke and logout routes that call it.
- `tests/test_admin_tokens.py::test_bulk_revoke_writes_audit_entries` asserts a substring of the audit
  action name rather than a parsed revoked-token count.
- Denylist upsert quirk: `POST /admin/api/denylist` on an existing `(kind, value)` pair returns the
  *new* POST-generated id while the row keeps its original id — a ported Rust quirk, not fixed in
  Python; worth deciding whether to keep parity or fix in Phase 3.
- The denylist-blocked 403 response bypasses the security-headers middleware on `/oauth/*` routes
  (headers are applied after the denylist short-circuit).
- Admin audit entries' `created_by` field could reuse `actor.actor_email` more consistently across
  admin routes (currently set ad hoc per handler).
- `GET /oauth/check_session` inherits `X-Frame-Options: DENY` from the global security-headers
  middleware — currently harmless (no session-management consumer embeds it in an iframe yet), but a
  latent trap if/when that's added; the OP iframe needs to be frameable by the RP.
- The disabled-dynamic-registration 403 body shape was never verified against the Rust handler's exact
  shape (Python's choice is secure but unpinned as an intentional-parity assertion).
- PAR entries are consumed (deleted) before login on `GET /oauth/authorize`, matching a Rust parity
  quirk rather than a deliberate Python design choice; `authorize` also still lacks duplicate-query-param
  rejection (Rust has it) and its error pages don't set `Cache-Control: no-store`.
- `device.py`'s scope-check inlines a `set(...).issubset(...)` instead of reusing the
  `scope_is_subset` helper in `services/auth.py` (pre-existing inconsistency, cosmetic).
- `anyio` is used directly (`anyio.to_thread` for argon2 off-loading) but is currently only a transitive
  dependency (via `httpx`/`starlette`) — consider pinning it explicitly in `pyproject.toml`.
- **RS256 rotation trap** — id_tokens always sign with the env PEM (never the keyset); after an admin
  RS256 rotation + grace expiry, the initial key drops out of JWKS while the JWKS fallback only fires
  when zero RS256 keys remain — RPs verifying id_tokens via JWKS break silently. Needs either
  keyset-signed id_tokens or the initial PEM key pinned unexpirable.
- **Admin sessions have no server-side revocation** — they are client-held signed cookies (role/email
  stamped at login) with no server-side revocation; disable/demote/delete does not terminate a live
  admin session; needs server-side session store or short-TTL re-validation against storage.
- **Admin token revoke by id can silently no-op for older rows** — admin `POST /tokens/{id}/revoke`
  resolves via `list_all_tokens` (`LIMIT 200`) — rows older than the newest 200 silently no-op (and
  `GET /tokens/{id}` 404s for them while the paged list can show them); needs a `get_token_by_id`
  storage method.
- **Back-channel logout is awaited inline** — each registered RP's logout_token POST is awaited
  sequentially with a 10s timeout (`routes/logout.py`); N unreachable RPs stall the caller's logout up
  to 10s each. Move dispatch to a background task or bounded gather.
- **Seed-admin password has no strength floor** — `OAUTH2_SEED_PASSWORD` accepts any length in
  `bootstrap.py` while the admin API enforces 8+ characters for user passwords; align the policy.
- **Admin PUT handlers skip type validation and the disable cascade** — `PUT /admin/api/users/{id}` and
  `PUT /admin/api/clients/{id}` feed raw JSON into `model_copy(update=...)` (e.g. `{"enabled":"yes"}`
  persists a string, which asyncpg would reject with a 500), and PUT `enabled:false` does not revoke
  tokens while `POST .../enabled` does. Add Pydantic body models and unify the cascade.
- **Admin client create with a duplicate caller-supplied `client_id`** hits the unique constraint and
  returns a 500; users-create returns a clean 409 — align to 409.
- **Negative `limit`/`offset` unvalidated on admin list endpoints** — `limit=-1` becomes `LIMIT -1`
  (unbounded, cap bypass) on SQLite and a 500 on Postgres; add `ge=0` bounds to the query params.
- **Audit coverage non-uniform** — admin single-token revoke (`POST /tokens/{id}/revoke`), device
  expire, and key rotation write no audit entries while bulk revokes and CRUD do (Rust parity, but
  worth unifying).
- **Unknown-kid JWT fallback pins HS256 trust to `jwt_secret` forever** — `decode_access_token` falls
  back to the static secret rather than trying active keyset HS256 keys, so HS256 rotation is a no-op
  for stateless decode (impact negligible today — the DB row is authoritative everywhere).
- **No Cache-Control headers on `/admin/api/*` responses** — the security-headers middleware only
  covers `/oauth*`; session-authenticated admin GETs are heuristically cacheable.
- **LIKE search wildcards unescaped in admin search** — `%`/`_` in the search term act as wildcards
  (parameters are bound, so injection-safe; cosmetic result pollution only).
