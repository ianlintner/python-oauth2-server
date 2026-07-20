# Python OAuth2 Server Port — Phase 3a Implementation Plan (Hardening Carryover)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the Phase 3 candidate list's enforcement/correctness items from `docs/PHASE2-BACKLOG.md`: login rate limiting, subject-denylist wiring, `get_token_by_id`, rotation-safe id_token signing, and the admin-API/logout/authorize polish batch.

**Architecture:** No new subsystems — every task lands inside existing modules. One new service (`services/ratelimit.py`, in-memory fixed-window limiter mirroring Rust's `LoginRateLimiter`). Zero new migrations (schema owned by the Rust repo).

**Tech Stack:** unchanged; adds `anyio` as an explicit dependency (already transitive).

## Global Constraints

- Schema owned by the Rust repo — zero new migrations. `bash scripts/gate.sh` green at every commit. TDD per task.
- Error-body/pagination conventions from Phase 2 hold.
- **Deliberate divergences from Rust introduced here (record in PHASE2-BACKLOG.md "Accepted divergences" when landed):**
  10. Subject-kind denylist entries are ENFORCED (login username/email, client-auth client_id) — Rust defines `check_subject_denylisted` but never wires it.
  11. id_tokens are signed with the keyset's current RS256 key (kid header) instead of the static env PEM — fixes the documented Rust rotation trap where rotated deployments break RP id_token verification.
  12. Admin single-token revoke, device expire, and key rotation are audited (Rust audits none of them).
- Rust-parity references: `.superpowers/sdd/research-logout-sessions.md` (LoginRateLimiter semantics), `.superpowers/sdd/research-keys-rs256.md` (rotation trap), `docs/PHASE2-BACKLOG.md` "Phase 3 candidates" (each item's exact description).

---

### Task 1: Login rate limiting

**Files:**
- Create: `src/oauth2_server/services/ratelimit.py`
- Modify: `src/oauth2_server/routes/login.py`, `src/oauth2_server/config.py`, `src/oauth2_server/app.py`
- Test: `tests/test_ratelimit.py` (new)

**Interfaces:**
- `class FixedWindowLimiter(max_attempts: int, window_secs: int)` — `check(key: str) -> int | None` returns `None` when allowed (and records the attempt) or the retry-after seconds remaining when blocked; `reset(key: str)` clears a key (called on successful login for both keys). Uses `time.monotonic()`; in-memory dict with lazy eviction of expired windows. Single-process (module docstring, same caveat family as ParStore).
- Config: `login_rate_limit_attempts: int = 10`, `login_rate_limit_window_secs: int = 900` (env `OAUTH2_LOGIN_RATE_LIMIT_ATTEMPTS` / `OAUTH2_LOGIN_RATE_LIMIT_WINDOW_SECS`).
- `app.state.login_limiter = FixedWindowLimiter(...)` in `create_app`.
- `POST /auth/login`: BEFORE credential lookup, check keys `f"login:ip:{request.client.host}"` AND `f"login:user:{username}"` (either blocked → blocked): 303 `Location: /auth/login?error=too_many_attempts` with `Retry-After: <secs>` header (the login page already maps that error key to its banner — Rust parity). Attempts recorded on FAILED logins only for the user key, on every attempt for the IP key (mirror Rust: record on attempt, reset both keys on success).

- [ ] **Step 1: Failing tests** — `test_limiter_blocks_after_max_attempts` (unit: 10 allowed, 11th returns retry-after > 0), `test_limiter_window_expires` (monkeypatch monotonic +901 → allowed again), `test_limiter_reset_clears_key`, `test_login_blocked_after_repeated_failures` (10 bad-password POSTs → 11th is 303 with `error=too_many_attempts` and `Retry-After` header, WITHOUT hitting argon2 — assert via a sentinel/monkeypatch that `verify_password_async` was not called on the blocked attempt), `test_login_success_resets_limiter` (9 failures then success then failure → not blocked), `test_login_rate_limit_keys_are_per_username` (failures for user A don't block user B from a different IP — use httpx `client=` to vary source IP).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite PASS + ruff.** **Step 5: Commit** — `git commit -m "feat(python): login rate limiting (fixed window, per-IP and per-username)"`

---

### Task 2: Subject-denylist enforcement

**Files:**
- Modify: `src/oauth2_server/routes/login.py`, `src/oauth2_server/services/clients.py`
- Test: `tests/test_denylist_middleware.py` (extend)

**Interfaces:**
- Login: after user lookup succeeds (username known), consult `check_subject_denylisted(storage, "username", username)` and `("email", user.email)`; a hit → same generic 303 `?error=invalid_credentials` (no oracle: identical to bad-password) — but log a warning with the reason.
- Client auth (`ClientService.authenticate`): after the client row loads, `check_subject_denylisted(storage, "client_id", client.client_id)`; a hit → the standard 401 `invalid_client` error (same as unknown client — no oracle).
- `user_id` kind stays unwired (nothing looks up by user_id pre-auth; document).

- [ ] **Step 1: Failing tests** — `test_denylisted_username_cannot_login` (valid credentials + denylist(username) → 303 invalid_credentials, session NOT established — a follow-up authorize still redirects to login), `test_denylisted_email_cannot_login`, `test_expired_username_entry_does_not_block`, `test_denylisted_client_id_rejected_at_token_endpoint` (client_credentials with valid secret + denylist(client_id) → 401 invalid_client), `test_denylisted_client_id_rejected_at_authorize` (authorize treats it as unknown client → 400 JSON, never redirect).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): enforce subject-kind denylist at login and client auth"`

---

### Task 3: get_token_by_id + admin token detail/revoke correctness

**Files:**
- Modify: `src/oauth2_server/storage/base.py`, `src/oauth2_server/storage/sql.py`, `src/oauth2_server/routes/admin/tokens.py`
- Test: `tests/test_admin_tokens.py`, `tests/test_admin_storage.py` (extend)

**Interfaces:**
- `get_token_by_id(token_id: str) -> Token | None` — `SELECT ... WHERE id = :id` (Protocol + SqlStorage).
- `GET /admin/api/tokens/{id}` and `POST /admin/api/tokens/{id}/revoke` resolve via `get_token_by_id` (no more LIMIT-200 blind spot). Revoke still returns 200 for unknown ids (contract preserved); detail 404 body unchanged.

- [ ] **Step 1: Failing tests** — storage: `test_get_token_by_id_round_trip` + miss → None; API: `test_token_detail_found_beyond_newest_200` and `test_revoke_by_id_works_beyond_newest_200` (seed 201 tokens with staggered created_at, target the oldest: detail 200, revoke actually flips introspection/storage `revoked`).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "fix(python): admin token detail/revoke resolve by id, not newest-200 scan"`

---

### Task 4: Rotation-safe id_token signing + keyset-aware verification

**Files:**
- Modify: `src/oauth2_server/security.py`, `src/oauth2_server/routes/token.py` (`_mint_id_token` call sites pass keyset), `src/oauth2_server/routes/logout.py`, `src/oauth2_server/keys.py` (if a helper is needed)
- Test: `tests/test_jwks_rs256.py`, `tests/test_logout.py` (extend)

**Interfaces:**
- `encode_id_token(...)` (RS256 mode): sign with `keyset.current_for_alg("RS256")` (kid header from that key) when one exists, falling back to the config PEM + `id_token_kid` (pre-rotation behavior unchanged — the seeded key IS the env PEM, so output is identical until a rotation happens). HS256 mode unchanged.
- Logout RS256 hint verification: resolve the hint's `kid` against `keyset.find(kid)` and verify with that key's public half; no kid or unknown kid → try each active RS256 key; still failing → 400 (strict).
- `decode_access_token` unknown-kid fallback: before the static-secret fallback, try each active HS256 keyset key (closes the "HS256 rotation is a no-op" note).

- [ ] **Step 1: Failing tests** — `test_id_token_signed_with_current_keyset_key_after_rotation` (RS256 app → rotate via admin → new auth-code flow's id_token header kid == rotated kid AND verifies against the rotated key's JWK from /.well-known/jwks.json), `test_id_token_pre_rotation_unchanged` (no rotation → kid == seeded kid, verifies via JWKS), `test_logout_accepts_hint_signed_by_rotated_out_key_during_grace` (id_token minted pre-rotation, rotate, logout with that hint during grace → not a 400), `test_hs256_rotation_decodes_with_active_keys` (rotate HS256 → token minted with new key decodes via keyset path).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "fix(python): rotation-safe id_token signing and keyset-aware hint/access verification"`

---

### Task 5: Admin API polish batch

**Files:**
- Modify: `src/oauth2_server/routes/admin/{users,clients,tokens,devices,keys,_util}.py`, `src/oauth2_server/storage/paging.py`, `src/oauth2_server/storage/sql.py`, `src/oauth2_server/app.py`
- Test: `tests/test_admin_users.py`, `tests/test_admin_clients.py`, `tests/test_admin_tokens.py`, `tests/test_admin_misc.py` (extend)

**Interfaces (each item is one bullet in the backlog — implement exactly):**
- PUT `/users/{id}` and `/clients/{id}` get Pydantic body models (all-optional fields, correct types; extra keys ignored) → invalid types 400 `invalid_request` instead of persisting garbage; PUT `enabled: false` triggers the same best-effort token revocation as POST `.../enabled`.
- POST `/admin/api/clients` with a caller-supplied `client_id` that already exists → 409 `{"error":"already_exists","error_description":"client_id already registered"}` (pre-check via `get_client`).
- `ListQuery` bounds: negative `limit`/`offset` → treated as 0/default (clamp in `effective_limit`/offset handling, no 500s; test `limit=-1` returns the default 25 and `offset=-5` acts as 0).
- Security headers middleware extended to also cover `/admin/api` paths (Cache-Control no-store etc.).
- LIKE search escaping: `%`/`_` in `search` escaped (`ESCAPE '\'`) so they match literally.
- Audit uniformity (divergence 12): `POST /tokens/{id}/revoke` audits `token.revoke` (target_kind "token", target_id row id), `POST /device/{code}/expire` audits `device.expire` (target_kind "device"), `POST /keys/rotate` audits `key.rotate` (target_kind "key", metadata {kid, algorithm}).

- [ ] **Step 1: Failing tests** — one per bullet: `test_put_user_rejects_non_bool_enabled` (400, unchanged), `test_put_client_enabled_false_revokes_tokens`, `test_create_client_duplicate_client_id_409`, `test_negative_limit_clamped` + `test_negative_offset_clamped`, `test_admin_api_responses_have_no_store`, `test_search_percent_matches_literally` (client named "100%" found by search "0%" but not by "0x"), `test_single_revoke_device_expire_and_rotate_are_audited`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "fix(python): admin API polish (PUT validation+cascade, 409, paging bounds, no-store, LIKE escape, audit uniformity)"`

---

### Task 6: Misc hardening batch

**Files:**
- Modify: `src/oauth2_server/bootstrap.py`, `pyproject.toml`, `src/oauth2_server/routes/logout.py`, `src/oauth2_server/routes/authorize.py`, `src/oauth2_server/middleware.py`
- Test: `tests/test_storage.py`, `tests/test_logout.py`, `tests/test_authorize.py`, `tests/test_denylist_middleware.py` (extend)

**Interfaces:**
- `seed_admin_user`: password shorter than 8 chars → log a warning and SKIP seeding (return False) — consistent with the admin API floor; test both sides of the boundary.
- `anyio>=4` added to `pyproject.toml` runtime dependencies (`uv sync`).
- Back-channel logout dispatch: `asyncio.gather` over per-client send coroutines with `return_exceptions=True` (bounded by a `Semaphore(5)`), replacing the sequential awaits; per-client exceptions still swallowed. Existing MockTransport test must keep passing; add `test_backchannel_logout_delivers_to_multiple_clients_concurrently` (two clients with backchannel URIs → both receive exactly one POST).
- Authorize duplicate-query-param rejection (Rust parity): any repeated query key on `GET /oauth/authorize` → 400 JSON `invalid_request` "duplicate query parameter" before any other processing (read `request.query_params.multi_items()`).
- Authorize JSON error responses (the 400s for unknown client / bad redirect_uri / PAR errors) carry `Cache-Control: no-store` (they're under `/oauth` so the middleware already applies — VERIFY with a test rather than adding code; only add explicit headers if the test proves a gap, e.g. responses produced by the DenylistGuard short-circuit).
- DenylistGuard 403 responses gain the standard security headers for `/oauth*` paths (apply `_SECURITY_HEADERS` inside the middleware when the path matches).

- [ ] **Step 1: Failing tests** per bullet (seed boundary 7/8 chars; dupe-param 400; two-client backchannel; denylist-403-headers; authorize-error no-store pin).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "fix(python): misc hardening (seed floor, anyio pin, concurrent backchannel, dupe params, denylist headers)"`

---

### Task 7: Phase 3a acceptance

**Files:**
- Modify: `docs/PHASE2-BACKLOG.md`, `README.md`, `tests/test_rfc_compliance.py`

- [ ] **Step 1:** Add compliance pins: `test_login_rate_limited_after_repeated_failures`, `test_denylisted_username_blocked_at_login`, `test_id_token_kid_matches_jwks_after_rotation`, `test_authorize_rejects_duplicate_query_params`.
- [ ] **Step 2:** `bash scripts/gate.sh` green.
- [ ] **Step 3:** Docs: strike the completed items from PHASE2-BACKLOG "Phase 3 candidates" (mark **Done (3a):** with commit refs); append divergences 10–12 to "Accepted divergences"; README notes the new env vars (`OAUTH2_LOGIN_RATE_LIMIT_*`) and that subject-denylist kinds are now enforced.
- [ ] **Step 4: Commit** — `git commit -m "test(python): Phase 3a compliance pins + docs"`

---

## Self-Review (completed)

- **Coverage vs backlog:** rate limiting → T1; subject-denylist → T2; get_token_by_id → T3; RS256 rotation trap + HS256 fallback → T4; PUT validation/cascade, dup client_id, paging bounds, admin no-store, LIKE escape, audit uniformity → T5; seed floor, anyio, backchannel fan-out, dupe query params, denylist-403 headers, authorize no-store verification → T6; pins/docs → T7. Deliberately NOT in 3a (stay in backlog): endpoint (token/device) rate limiting beyond login (needs Rust oauth2-ratelimit research — Phase 3c), ParStore/KeySet/events persistence, admin server-side session revocation, PAR pre-login consumption parity quirk, denylist upsert id quirk, check_session XFO.
- **Placeholder scan:** clean; test names + concrete behaviors specified per task.
- **Type consistency:** `FixedWindowLimiter.check -> int | None` used consistently; `get_token_by_id` name matches across Protocol/impl/routes; audit action codes `token.revoke`/`device.expire`/`key.rotate` used in both T5 code and tests.
