# Python OAuth2 Server Port — Phase 4b Implementation Plan (Authorize Front-Channel Parity)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `GET /oauth/authorize` reaches parity with the Rust handler (`crates/oauth2-actix/src/handlers/oauth.rs::authorize`, lines 629–1160) for the front-channel features Phase 1 left out: `response_mode` (`query`/`form_post`/`fragment`), the OIDC hybrid `code id_token` response type, JAR request objects (RFC 9101 `request=`), `acr_values` step-up (RFC 9470), and `claims` request storage — while fixing, as recorded divergences, the Rust latent bugs the research identified (query-only error encoding on two paths, `acr`/`amr` never written to the session, hybrid `nonce` not enforced, form_post attribute escaping).

**Architecture:** the authorize route keeps its validation order (duplicate keys → PAR → client → redirect_uri → redirect-delivered errors) and gains: a single mode-aware response builder (`services/authorize_response.py`) used by every success and error delivery; a JAR processor (`services/jar.py`) that overlays verified request-object claims onto the merged parameters right after the PAR merge, reusing Phase 4a's `resolve_client_jwks`/`_rsa_key_from_jwks`; a shared id-token minter (`services/id_token.py`) extracted from `routes/token.py::_mint_id_token` so the hybrid path and the token endpoint produce identical claims; and `acr`/`amr` stamped into the session at login. Discovery advertises exactly what ships.

**Tech Stack:** no new dependencies. Authoritative research (Rust line citations, test table, gotchas): `.superpowers/sdd/research-phase-4b.md` (git-ignored; regenerate from the Rust repo if missing).

## Global Constraints

- Schema is owned by the Rust repo — zero SQL migrations (`authorization_codes.claims_request` already exists; `_AUTH_CODE_COLS` derives from the model).
- `bash scripts/gate.sh` green at every commit. TDD per task.
- Validation order and error-channel rules (Rust parity, `research-phase-4b.md` §1.2): steps up to and including `response_mode` validation return **400 JSON** `invalid_request` (a valid mode is needed to know HOW to redirect); everything after (scope, `prompt=none`, step-up, and the new `invalid_target`/RAR errors already delivered by redirect) goes through the mode-aware builder.
- User directive for Phase 4: **security best practice over Rust parity**; every such choice is a numbered divergence below.
- **Deliberate divergences from Rust (record in PHASE2-BACKLOG.md when landed):**
  37. Every redirect-channel error honors `response_mode` (Rust's `prompt=none`/`login_required` path ignores `fragment`, and its `acr_values` path ignores both `fragment` and `form_post`). `form_post` error responses also carry `Cache-Control: no-store` + `Pragma: no-cache` like the success path.
  38. `form_post` attribute escaping also escapes `'` (`&#x27;`) — Rust's `html_escape_attr` does not.
  39. Hybrid `code id_token` REQUIRES `nonce` (OIDC Core §3.3.2.11); missing → redirect error `invalid_request` / "nonce is required for response_type=code id_token". Rust issues the id_token without it.
  40. The hybrid id_token uses the same minter and TTL as the token endpoint's id_token (`config.access_token_ttl_secs`) and carries `acr`, `amr`, `auth_time` from the session; Rust hardcodes `exp = now + 3600` and omits those claims.
  41. JAR verification failures use error code `invalid_request_object` (RFC 9101 §6.3.1) instead of Rust's `invalid_request`; structural/unsupported cases (not a JWT, unsupported auth method) stay `invalid_request`. A JAR `client_id` claim, when present, MUST equal the query `client_id` (RFC 9101 §6.3 — Rust never checks it).
  42. Login stamps `acr = urn:mace:incommon:iap:bronze` and `amr = ["pwd"]` (social login: `amr = ["fed"]`) into the session; `acr_values_supported` is config-driven (`OAUTH2_ACR_VALUES_SUPPORTED`, default `["urn:mace:incommon:iap:bronze"]`) and advertises only achievable values. Rust advertises silver+bronze but never sets `acr`, so every `acr_values` request fails.
  43. `request_object_signing_alg_values_supported` advertises `["RS256", "HS256", "none"]` — what is implemented — not Rust's `["RS256", "ES256", "HS256"]` (ES256 unimplemented there, `none` implemented but unadvertised).
  44. `claims` is validated as a JSON object (malformed → 400/redirect `invalid_request` "claims must be a JSON object") before being stored verbatim on the code; `claims_parameter_supported` is NOT advertised because the stored value is not yet honored at userinfo/token (Rust: stored unparsed, never read).
  45. Fragment encoding uses `urllib.parse.urlencode(..., quote_via=quote)` (RFC 3986 unreserved set kept, never `+`); Rust percent-escapes all non-alphanumerics. Functionally equivalent after decoding.
- **Rust behaviors KEPT:** `response_mode`, `prompt`, `max_age`, `login_hint`, `request` read only from the query string (not PAR); JAR claims win over both query and PAR for the overlaid keys; JAR dispatch on the client's REGISTERED `token_endpoint_auth_method` (`none` → literal `alg=none` + empty signature, no `iss`/`aud`/`exp` checks; `client_secret_*` → HS256 with the client secret; `private_key_jwt` → RS256 via inline `jwks`/`jwks_uri` cache), `aud == f"{issuer}/oauth/authorize"`, `exp` and `iss` required, `iss == client_id`; `require_state` evaluated against the raw query before the JAR overlay; outer `response_type` validation skipped when `request=` is present (the JAR's value is validated instead); hybrid defaults `response_mode` to `fragment`; id_token issued only when the EFFECTIVE scope contains `openid`; `c_hash` = base64url(SHA-256(code)[:16]) without padding, `at_hash` absent; `acr` satisfaction = session `acr` is exactly one of the space-separated requested values; step-up error `insufficient_user_authentication` / "Authentication Context Class does not satisfy acr_values"; success parameter order `code, state, iss, id_token` (query) and `code, iss, state, id_token` (fragment/form_post); `form_post` HTML shape/status 200/`text/html; charset=utf-8`; the four security headers on every authorize response.

## Rust → Python map

| Rust | Python |
|---|---|
| `oauth.rs::form_post_response`, `build_authorize_error_redirect`, success delivery 1111–1160 | `services/authorize_response.py` |
| `oauth.rs::process_jar` 426–561 + overlay 754–816 | `services/jar.py`, `routes/authorize.py` |
| `oauth.rs` hybrid issuance 1071–1109 + `routes/token.py::_mint_id_token` | `services/id_token.py` |
| `oauth.rs` step-up 1019–1044; `login.rs` session writes | `routes/authorize.py`, `sessions.py`, `routes/login.py`, `routes/social.py` |
| `wellknown.rs` discovery fields | `routes/wellknown.py`, `config.py` |

---

### Task 1: Mode-aware response builder (`query` / `fragment` / `form_post`)

**Files:**
- Create: `src/oauth2_server/services/authorize_response.py`
- Modify: `src/oauth2_server/routes/authorize.py`
- Test: `tests/test_response_mode.py` (new)

**Interfaces:**
- `services/authorize_response.py`:
  - `VALID_RESPONSE_MODES = ("query", "form_post", "fragment")`
  - `resolve_response_mode(requested: str | None, *, hybrid: bool) -> str` — returns the requested mode or the default (`"fragment"` if hybrid else `"query"`); raises `OAuthError("invalid_request", "Unsupported response_mode; supported values: query, form_post, fragment", 400)` for anything else.
  - `success_response(mode, redirect_uri, *, code, state, iss, id_token=None)` and `error_response(mode, redirect_uri, *, error, error_description, state, iss)` → Starlette `Response`. Query: 302, params appended preserving an existing query string, `redirect_uri` with a fragment → `OAuthError("invalid_request", "redirect_uri must not contain a fragment", 400)`; order `code, state, iss, id_token` / `error, error_description, state, iss`. Fragment: 302 `{redirect_uri}#{urlencode(params, quote_via=quote)}`; order `code, iss, state, id_token` / `error, error_description, iss, state`. form_post: 200 `text/html; charset=utf-8`, body exactly
    ```html
    <!DOCTYPE html>
    <html><body onload="document.forms[0].submit()">
    <form method="post" action="{escaped redirect_uri}">
    <input type="hidden" name="{k}" value="{v}"/>
    </form></body></html>
    ```
    (one input line per param, joined by `\n`; escaping `&`→`&amp;` first, then `"`→`&quot;`, `<`→`&lt;`, `>`→`&gt;`, `'`→`&#x27;`), same param order as fragment. Every response (all modes, success and error) carries `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `X-Content-Type-Options: nosniff` (divergence 37 for the form_post error case).
- `routes/authorize.py`: read `response_mode` from the QUERY only (never `merged`); resolve it immediately after the `redirect_uri` registration check (step 3) and before any redirect-delivered error; replace `_error_redirect`/the success `RedirectResponse` with the builder; route the `prompt=none` → `login_required` path and every other redirect-delivered error through it. Keep the existing `_error_page` for pre-redirect 400s.

- [ ] **Step 1: Failing tests** — `test_wave5_response_mode_fragment_delivers_code_in_fragment` (302; `#` in Location; `code` and `iss` in the fragment; no `code` in the query), `test_wave5_unsupported_response_mode_is_rejected` (`response_mode=token` → 400 JSON `invalid_request`, no redirect), `test_form_post_success_shape` (200, content-type, exact HTML with escaped `&`/`"`/`'` in a state value, param order, all six headers), `test_form_post_error_carries_no_store` (divergence 37), `test_prompt_none_login_required_honors_fragment` (divergence 37), `test_query_mode_preserves_existing_query_string`, `test_query_mode_rejects_redirect_uri_with_fragment`, `test_fragment_never_contains_plus` (state with a space), unit tests for `resolve_response_mode` defaults.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS** (existing `tests/test_authorize.py` redirect assertions must still hold — query-mode byte layout unchanged). **Step 5: Commit** — `git commit -m "feat(python): response_mode query/fragment/form_post with one mode-aware authorize response builder"`

---

### Task 2: Shared id-token minter + hybrid `code id_token`

**Files:**
- Create: `src/oauth2_server/services/id_token.py`
- Modify: `src/oauth2_server/routes/token.py` (delegate `_mint_id_token`), `src/oauth2_server/routes/authorize.py`, `src/oauth2_server/models.py` (`IdTokenClaims.amr: list[str] | None`, `c_hash` present), `src/oauth2_server/security.py` (move `_half_hash` here as `half_hash`)
- Test: `tests/test_hybrid_flow.py` (new), `tests/test_token_endpoint.py` (id_token parity unchanged)

**Interfaces:**
- `services/id_token.py::mint_id_token(*, config, keyset, client, user, scope, nonce=None, access_token=None, code=None, acr=None, amr=None, auth_time=None) -> str` — builds `IdTokenClaims` (`at_hash` only when `access_token` given, `c_hash` only when `code` given, both via `half_hash`), scope-gated `email`/`preferred_username` exactly as `routes/token.py::_mint_id_token` does today, `exp = iat + config.access_token_ttl_secs`, signs via `encode_id_token`. `routes/token.py::_mint_id_token` becomes a thin wrapper (behavior byte-identical — pinned by the existing id_token tests).
- `routes/authorize.py`: accept `response_type` in `{"code", "code id_token"}` (the unsupported case keeps its current delivery); `hybrid = response_type == "code id_token"`; hybrid requires `nonce` (divergence 39, redirect error); after `issue_code`, when `hybrid and "openid" in auth_code.scope.split()`, mint the id_token with `code=auth_code.code`, `nonce`, and the session's `acr`/`amr`/`auth_time` (Task 5 fills `acr`/`amr`; pass `None` until then) and hand it to the builder's `id_token=`.

- [ ] **Step 1: Failing tests** — `test_wave5_hybrid_code_id_token_delivers_both_in_fragment` (no `response_mode`, `nonce` given → 302 with `code` and `id_token` in the fragment), `test_wave5_hybrid_no_openid_scope_omits_id_token`, `test_hybrid_id_token_has_c_hash_nonce_and_no_at_hash` (decode unverified: `c_hash == half_hash(code)`, `nonce` echoed, no `at_hash`, `aud == client_id`, `exp - iat == access_token_ttl_secs`), `test_hybrid_requires_nonce` (divergence 39), `test_hybrid_id_token_verifies_against_jwks_when_rs256` (RS256 app fixture), `test_hybrid_form_post_carries_id_token`, `test_token_endpoint_id_token_unchanged_after_refactor` (existing at_hash/nonce assertions still pass).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): OIDC hybrid code id_token at authorize via a shared id-token minter"`

---

### Task 3: JAR request objects (RFC 9101) — `none` / HS256 / RS256 + overlay

**Files:**
- Create: `src/oauth2_server/services/jar.py`
- Modify: `src/oauth2_server/routes/authorize.py`, `src/oauth2_server/services/client_assertion.py` (export `rsa_key_from_jwks` if currently private)
- Test: `tests/test_jar.py` (new)

**Interfaces:**
- `services/jar.py`:
  - `JAR_OVERLAY_KEYS = ("redirect_uri", "response_type", "response_mode", "scope", "code_challenge", "code_challenge_method", "nonce", "resource", "state", "authorization_details", "claims", "acr_values")`
  - `async process_jar(client: Client, request_jwt: str, *, authorize_url: str, jwks_cache) -> dict[str, str]` — returns the verified string claims restricted to `JAR_OVERLAY_KEYS`. Structural: 3 dot-separated parts else `OAuthError("invalid_request", "JAR request is not a valid JWT (expected header.payload.signature)")`. Dispatch on `client.token_endpoint_auth_method`: `none` → header `alg` must be literally `"none"` ("JAR from public client must use alg=none; signed JARs require a confidential client authentication method"), signature segment must be empty ("JAR with alg=none must have an empty signature"), payload decoded without verification and without `exp`/`aud`/`iss` requirements; `client_secret_basic`/`client_secret_post`/`client_secret_jwt` → `jwt.decode(..., client.client_secret, algorithms=["HS256"], audience=authorize_url, options={"require": ["exp", "iss"]})`; `private_key_jwt` → `resolve_client_jwks` then RS256 with `kid`-or-first-RSA selection (messages as in Task 1 of Phase 4a with the ` for JAR` suffix Rust uses); other → `invalid_request` "Unsupported token_endpoint_auth_method '{m}' for JAR signing". Verification failures (signature, exp, aud, iss mismatch, `alg` mismatch) → `OAuthError("invalid_request_object", f"JAR {alg} verification failed: {reason}")` / "JAR 'iss' claim must equal client_id" (divergence 41). If the payload has `client_id` and it differs from `client.client_id` → `invalid_request_object` "JAR client_id does not match" (divergence 41). Non-string overlay values are ignored (Rust `as_str()` semantics).
- `routes/authorize.py`: `request` read from the QUERY only; processed right after the PAR merge and the client lookup (the client is needed for the key) and BEFORE the `redirect_uri` registration check; overlay `merged.update(jar_claims)`; `require_state` (if the Client model has it — check; Rust checks it pre-overlay) evaluated against the raw query; skip the outer `response_type` validation when `request=` is present and validate the effective value instead ("Unsupported response_type in JAR; supported values: code, code id_token"); a JAR `response_mode` wins over the query. All JAR errors are 400 JSON (they precede redirect_uri validation).

- [ ] **Step 1: Failing tests** — helpers `make_unsigned_jar(payload)` (`{"alg":"none","typ":"JWT"}` header, empty signature), `make_hs256_jar(payload, secret)`, `make_rs256_jar(payload, private_key, kid)`; `test_wave5_jar_public_client_unsigned_succeeds` (public client, JAR without `iss`/`aud`/`exp`, `response_type=code` in query → 302 with `code` in the QUERY), `test_wave5_jar_confidential_client_hs256_succeeds`, `test_wave5_jar_tampered_hs256_is_rejected` (400 `invalid_request_object`), `test_wave2_c1_public_client_jar_rejects_non_none_alg_header`, `test_wave2_c1_public_client_jar_rejects_nonempty_signature_with_alg_none`, `test_vector_q_jar_state_beats_query_state` (query `state` never appears in Location) + its tampered half, `test_jar_missing_exp_rejected`, `test_jar_wrong_aud_rejected`, `test_jar_iss_mismatch_rejected`, `test_jar_client_id_mismatch_rejected` (divergence 41), `test_jar_overrides_par_values`, `test_jar_response_type_hybrid_validated`, `test_jar_response_mode_wins`, `test_jar_in_par_body_is_ignored`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 9101 JAR request objects (none/HS256/RS256) overlaid onto authorize parameters"`

---

### Task 4: JAR RS256 via `jwks_uri` cache (test vector r)

**Files:**
- Modify: `src/oauth2_server/services/jar.py` (only if Task 3 left gaps), `src/oauth2_server/routes/authorize.py`
- Test: `tests/test_jar.py`

**Interfaces:** the authorize route passes `request.app.state.jwks_cache` into `process_jar`; inline `jwks` beats `jwks_uri`; errors from the cache surface as 400 JSON with the Phase 4a non-echoing messages.

- [ ] **Step 1: Failing tests** — `test_vector_r_jar_private_key_jwt_jwks_cache` (swap `app.state.http_client` for a counting `httpx.MockTransport` serving a JWKS with `Cache-Control: max-age=300`; two RS256 JARs with `kid="jar-key-1"` differing in `state` → both 302, exactly one upstream fetch), `test_jar_rs256_kid_miss_rejected`, `test_jar_rs256_inline_jwks_beats_jwks_uri` (no fetch), `test_jar_rs256_private_jwk_rejected` (reuses Phase 4a's guard).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "test(python): JAR RS256 through the jwks_uri TTL cache (RFC 9700 vector r)"`

---

### Task 5: `acr_values` step-up + session `acr`/`amr`

**Files:**
- Modify: `src/oauth2_server/sessions.py` (login writes `acr`, `amr`), `src/oauth2_server/routes/login.py`, `src/oauth2_server/routes/social.py` (`amr=["fed"]`), `src/oauth2_server/config.py` (`acr_values_supported: list[str]`, env `OAUTH2_ACR_VALUES_SUPPORTED`, default `["urn:mace:incommon:iap:bronze"]`, `NoDecode` list like `rar_types_supported`), `src/oauth2_server/routes/authorize.py`, `src/oauth2_server/routes/token.py` (id_token gets `acr`/`amr`/`auth_time` from the session-less code path — leave as-is unless trivially available; document), `src/oauth2_server/services/id_token.py`
- Test: `tests/test_step_up.py` (new), `tests/test_login_ui.py`

**Interfaces:**
- Password login stores `acr = config.acr_values_supported[0]`, `amr = ["pwd"]`; social login `acr` the same default, `amr = ["fed"]`. Read back via the existing session accessors (add `current_acr(request)`/`current_amr(request)` helpers next to `current_user_id`).
- `routes/authorize.py`: after the login gate and scope validation, if `merged.get("acr_values")`: `required = value.split()`; satisfied iff session `acr` is in `required`; else builder error `insufficient_user_authentication` / "Authentication Context Class does not satisfy acr_values" honoring `response_mode` (divergence 37). Hybrid id_token receives `acr`/`amr`/`auth_time` (divergence 40).

- [ ] **Step 1: Failing tests** — `test_login_stamps_acr_and_amr`, `test_acr_satisfied_proceeds_to_code`, `test_acr_unsatisfied_redirects_insufficient_user_authentication` (state + iss preserved), `test_acr_error_honors_fragment_mode`, `test_acr_error_honors_form_post_mode`, `test_acr_values_from_par_are_enforced`, `test_hybrid_id_token_carries_acr_amr_auth_time`, `test_acr_values_supported_config_default`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 9470 acr_values step-up with acr/amr stamped at login"`

---

### Task 6: `claims` request parameter — validate and store

**Files:**
- Modify: `src/oauth2_server/services/auth.py` (`issue_code(claims_request=)`), `src/oauth2_server/routes/authorize.py`
- Test: `tests/test_authorize.py`

**Interfaces:** `merged.get("claims")`, when present, must parse as a JSON object (`json.loads` → `dict`) else redirect error `invalid_request` / "claims must be a JSON object" (divergence 44); the raw string is stored on `AuthorizationCode.claims_request`. Not honored downstream yet; `claims_parameter_supported` not advertised.

- [ ] **Step 1: Failing tests** — `test_claims_request_stored_on_code` (query), `test_claims_request_from_par_stored`, `test_claims_request_from_jar_stored`, `test_malformed_claims_rejected_via_redirect`, `test_claims_survives_sql_round_trip` (storage-level: save/get code with `claims_request`).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): validate and persist the OIDC claims request parameter on authorization codes"`

---

### Task 7: Discovery deltas + docs + backlog

**Files:**
- Modify: `src/oauth2_server/routes/wellknown.py`, `README.md` (new "## Phase 4b" section before "## Running": features, new env var `OAUTH2_ACR_VALUES_SUPPORTED`, no new single-process state), `docs/PHASE2-BACKLOG.md` (divergences 37–45 under "From Phase 4b"; mark divergence 8 (JAR not ported) and the "Phase 4 roadmap" 4b row as done; note remaining 4b gaps: `claims` not honored downstream, PKCE still public-only, `request_uri`-as-JAR-URL unsupported)
- Test: `tests/test_wellknown.py`

**Interfaces:** discovery → `response_types_supported: ["code", "code id_token"]`, `response_modes_supported: ["query", "form_post", "fragment"]`, `request_parameter_supported: True`, `request_object_signing_alg_values_supported: ["RS256", "HS256", "none"]`, `acr_values_supported: config.acr_values_supported`, `claims_supported` += `c_hash`, `acr`, `amr`, `auth_time`. Remove the stale "JAR is not ported" comment.

- [ ] **Step 1: Failing tests** — `test_wave5_discovery_response_types_includes_code_id_token`, `test_wave5_discovery_response_modes_includes_fragment`, `test_wave5_discovery_request_parameter_supported_is_true`, `test_discovery_request_object_algs_match_implementation`, `test_wave4_rfc9470_acr_values_supported_advertised` (non-empty, equals config), `test_wave4_oidc_claims_request_acr_auth_time_in_claims_supported` (`acr`, `auth_time`, `amr`, `c_hash`).
- [ ] **Step 2: FAIL.** **Step 3: Implement + docs.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): advertise Phase 4b authorize capabilities; README/backlog for divergences 37-45"`
