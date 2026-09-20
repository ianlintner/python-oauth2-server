# Python OAuth2 Server Port — Phase 4a Implementation Plan (Token-Endpoint & Metadata Parity)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

## Phase 4 design (roadmap)

Phases 1–3d ported every Rust feature the plans targeted; the Rust repo has not moved since
(last commit `0d9e12f`, 2026-07-19, whose `return_to` hardening is already mirrored in
`routes/login.py`). What remains is the set of Rust features the earlier plans deliberately
left out (`docs/PHASE2-BACKLOG.md` divergence 8 and the "Known … gaps" sections) plus a few
RFC gaps both servers share. Re-diffing the Rust discovery document
(`crates/oauth2-actix/src/handlers/wellknown.rs`) against `routes/wellknown.py` gives the
authoritative list. Phase 4 closes it in three sub-phases, each a separate branch/PR:

| Sub-phase | Scope | Authoritative Rust tests |
|---|---|---|
| **4a (this plan)** | RFC 7523 JWT client auth (`client_secret_jwt`, `private_key_jwt`) + jti replay + `jwks_uri` cache; RFC 8707 resource indicators → `aud`; RFC 9728 protected-resource metadata + status-list stub + discovery/userinfo field parity; RFC 9701 JWT introspection responses; RFC 8628 `slow_down` | `phase2_rfc_compliance.rs::rfc7523_*`, `::rfc7591_*jwks*`; `rfc9700_compliance.rs::test_vector_{l,m,r}`; `compliance_wave3.rs::rfc8707_*`, `::rfc9701_*`; `compliance_wave4.rs::wave4_rfc9728_*`, `::wave4_token_status_list_*` |
| **4b** | Authorize front-channel parity: `response_mode` `query`/`form_post`/`fragment`; OIDC hybrid `code id_token`; JAR `request` objects (unsigned public / HS256 / RS256-via-client-JWKS); `acr_values` step-up (RFC 9470) + `claims` request + `acr`/`amr`/`auth_time` claims | `compliance_wave5.rs::*`, `rfc9700_compliance.rs::test_vector_{q,r}`, `compliance_wave4.rs::wave4_rfc9470_*`, `::wave4_oidc_claims_*` |
| **4c** | RFC 8705 mTLS (`tls_client_auth`, `self_signed_tls_client_auth`, `X-Client-Cert-Thumbprint`/`X-SSL-Client-S-DN`, `cnf.x5t#S256`); DPoP hardening beyond Rust (`ath`, resource-side DPoP at userinfo, `dpop_jkt` at authorize/PAR, `DPoP-Nonce` on 200s); nested `act` chains; social account-linking by email | `rfc9700_compliance.rs::test_vector_p`, `compliance_wave4.rs::wave4_rfc8705_*`; RFC text for the beyond-Rust items |

Out of scope for all of Phase 4 (unchanged from `PHASE2-BACKLOG.md`): Redis/Kafka/RabbitMQ
event backends, bulkheads, OTel span export, multi-instance persistence of in-process
stores, admin-session server-side revocation.

**Goal (4a):** the token, introspection, revocation and registration endpoints accept every
non-mTLS client authentication method Rust accepts; access tokens can be audience-restricted
with `resource`; the well-known surface (discovery, protected-resource metadata, status list,
userinfo) matches Rust field-for-field except where a field would advertise an unimplemented
capability; introspection can answer as a signed JWT; device polling returns `slow_down`.

**Architecture:** two new pure-logic services (`services/client_assertion.py`,
`services/jwks_cache.py`) plug into `ClientService.authenticate` via a dispatch on the
client's registered `token_endpoint_auth_method`, so every endpoint that already calls
`authenticate` gains JWT auth with no per-route changes. `resource` threads through the
existing `issue_code` → `AuthorizationCode.resource` (column already vendored in `V14`) →
`TokenService.issue(resource=)` → `Claims.new(resource=)` path. Metadata is additive in
`routes/wellknown.py`. RFC 9701 wraps the existing `IntrospectionResponse` dict. `slow_down`
uses a small in-process poll tracker in the same style as `DpopReplayStore`.

**Tech Stack:** no new runtime dependencies (`pyjwt`, `cryptography`, `httpx` already
present). Tests use `httpx.MockTransport` on `app.state.http_client` for `jwks_uri` fetches.

## Global Constraints

- Schema is owned by the Rust repo — zero SQL migrations (`V14__add_resource_to_auth_codes.sql`
  already vendored; `_AUTH_CODE_COLS` derives from the model, so `resource` is already
  persisted on SQL and Mongo).
- `bash scripts/gate.sh` green at every commit. TDD per task: failing test → implement →
  full suite → commit.
- Error bodies stay JSON `{"error", "error_description"}` with `Cache-Control: no-store`
  via the existing `oauth_error` helper. Client-auth failures at `/oauth/token` keep flowing
  through `_invalid_client_response` (401 + RFC 9700 penalty bucket + metric).
- Every new in-process store (JTI replay guard, JWKS cache, device poll tracker) is
  single-process, documented under the README's "Single-process state caveats" pattern.
- **Deliberate divergences from Rust (record in PHASE2-BACKLOG.md when landed):**
  32. `resource` values are validated (absolute URI, no fragment) and rejected with
      `invalid_target` (RFC 8707 §2) — Rust accepts any string.
  33. Discovery and protected-resource metadata do NOT advertise
      `tls_client_certificate_bound_access_tokens`, `tls_client_auth`, or
      `self_signed_tls_client_auth` until Phase 4c implements them — Rust advertises all
      three. Likewise `request_parameter_supported`, `response_modes_supported`,
      `response_types_supported: ["code", "code id_token"]`, `acr_values_supported`,
      `request_object_signing_alg_values_supported` stay at their Phase 3 values until 4b.
  34. RFC 9701: an `Accept: application/token-introspection+jwt` caller gets a signed JWT
      for BOTH active and inactive results — Rust only wraps the active path and returns
      plain JSON `{"active": false}` otherwise. Signing follows divergence 11 (keyset's
      current RS256 key with its `kid` when `id_token_alg == "RS256"`, else HS256
      `jwt_secret`) rather than Rust's static env PEM.
  35. RFC 8628 §3.5 `slow_down` is implemented (Rust never returns it — recorded as a shared
      gap in "Known Phase 3c gaps"). The required interval grows by 5 s per `slow_down`.
  36. A JWT client assertion may omit form `client_id`; the client is then resolved from the
      assertion's `sub` (RFC 7523 §2.2 says `client_id` is unnecessary). Rust requires
      `client_id` in the form.
- **Rust behaviors KEPT:** dispatch strictly on the client's *registered*
  `token_endpoint_auth_method` (a `client_secret_jwt` client presenting Basic auth fails with
  the ordinary invalid-secret path); `aud` must contain exactly the token endpoint URL
  (`{issuer}/oauth/token`) for every endpoint's assertion (Rust passes the token endpoint URL
  everywhere); `client_secret_jwt` requires HS256 and `private_key_jwt` requires RS256 (any
  other `alg` → `invalid_client`); required claims `exp`, `sub`, `iss`, `aud`, `jti`; JTI
  replay key is `(client_id, jti)` with TTL `min(exp - now, 300 s)` and a 100 000-entry cap;
  JWKS cache TTL from `Cache-Control: max-age` clamped to `[30, 86400]`, default 300, 10 s
  fetch timeout; inline `jwks` beats `jwks_uri`; `kid` match first, else first RSA key;
  resource on refresh is passed straight through with no subset check (Rust "Phase 6.3"
  note); protected-resource metadata and status-list bodies byte-for-byte where the
  capability exists; userinfo gains `iss` + `aud` (= token `client_id`).

## Rust → Python map

| Rust | Python |
|---|---|
| `handlers/oauth.rs::authenticate_confidential_client` (dispatch) | `services/clients.py::ClientService.authenticate` |
| `handlers/oauth.rs::validate_jwt_client_assertion`, `enforce_jti_replay` | `services/client_assertion.py` |
| `security/jti_replay.rs::JtiReplayGuard` | `services/client_assertion.py::JtiReplayGuard` |
| `handlers/jwks_cache.rs::JwksCache`, `oauth.rs::resolve_client_jwks` | `services/jwks_cache.py` |
| `handlers/client.rs` jwks validation | `routes/register.py` |
| `actors/token_actor.rs` `resource` → `with_audience` | `models.py::Claims.new(resource=)`, `services/tokens.py` |
| `handlers/wellknown.rs::protected_resource_metadata`, `token_status_list`, `userinfo` | `routes/wellknown.py` |
| `handlers/token.rs` RFC 9701 block | `routes/introspect.py` |
| (none — Rust gap) | `services/device_poll.py`, `routes/token.py` device branch |

---

### Task 1: RFC 7523 JWT client authentication (`client_secret_jwt`, `private_key_jwt`)

**Files:**
- Create: `src/oauth2_server/services/client_assertion.py`, `src/oauth2_server/services/jwks_cache.py`
- Modify: `src/oauth2_server/services/clients.py`, `src/oauth2_server/app.py`,
  `src/oauth2_server/routes/register.py`, `src/oauth2_server/routes/token.py`
  (`_extract_client_id_for_penalty`), `src/oauth2_server/routes/wellknown.py`
- Test: `tests/test_client_assertion.py` (new), `tests/test_registration.py` (update one test),
  `tests/test_wellknown.py`

**Interfaces:**
- `services/client_assertion.py`:
  - `JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`
  - `class JtiReplayGuard(max_entries=100_000)`: `observe(client_id, jti, ttl_secs) -> bool`
    (True = fresh, False = replay). Key `f"{client_id}\0{jti}"`, TTL clamped to 300 s, sweeps
    expired entries on every call, evicts an arbitrary entry at the cap. `time.monotonic()`.
  - `validate_client_assertion(client: Client, assertion: str, token_endpoint_url: str, *, jwks: dict | None, guard: JtiReplayGuard) -> None` — raises `OAuthError("invalid_client", <msg>)`
    with Rust's messages: "Malformed client_assertion JWT", "client_secret_jwt requires HS256
    algorithm", "private_key_jwt requires RS256 algorithm", "Client must register jwks or
    jwks_uri for private_key_jwt", "Client JWKS missing 'keys' array", "No matching kid in
    client JWKS", "No RSA key found in client JWKS", "JWT iss/sub must equal client_id",
    "client_assertion missing required jti claim (RFC 7523 §3)", "client_assertion jti has
    already been used", and `"{method} validation failed: {reason}"` for PyJWT errors.
    Uses `jwt.decode(..., algorithms=[<exactly one>], audience=token_endpoint_url, options={"require": ["exp","sub","iss","aud"]})`;
    RSA keys built with `jwt.algorithms.RSAAlgorithm.from_jwk`.
  - `unverified_assertion_subject(assertion: str) -> str | None` (for divergence 36 and the
    penalty bucket).
- `services/jwks_cache.py`: `class JwksCache(http_client: httpx.AsyncClient)` with
  `async fetch(url) -> dict`; TTL constants `DEFAULT_TTL_SECS=300`, `MIN_TTL_SECS=30`,
  `MAX_TTL_SECS=86_400`; errors → `OAuthError("invalid_client", ...)` with Rust's messages
  (`"Failed to fetch jwks_uri '{url}': {e}"`, `"jwks_uri '{url}' returned HTTP {status}"`,
  `"jwks_uri '{url}' returned invalid JSON: …"`, `"jwks_uri '{url}' JWKS document missing 'keys' array"`).
  `async resolve_client_jwks(client, cache) -> dict | None` (None unless `private_key_jwt`;
  inline `jwks` string parsed first — "Client inline JWKS is not valid JSON" on failure).
- `ClientService.__init__(storage, event_bus, *, issuer: str | None = None, jwks_cache: JwksCache | None = None, jti_guard: JtiReplayGuard | None = None)`.
  Add a classmethod/helper `ClientService.from_app(request.app.state)` that wires all three from
  `app.state.config.issuer`, `app.state.jwks_cache`, `app.state.jti_guard`; switch every
  existing `ClientService(storage, event_bus)` call site in `routes/` to it (token, introspect,
  revoke, par, device_authorization, and any others — grep). Constructor without the kwargs
  keeps working for unit tests (JWT methods then fail with "Client is not configured for JWT
  authentication").
- `authenticate` dispatch after the denylist check: `none` → unchanged; `client_secret_jwt`/
  `private_key_jwt` → require `client_assertion_type == JWT_BEARER_ASSERTION_TYPE`
  ("Missing client_assertion_type" / "Unsupported client_assertion_type"), require
  `client_assertion` ("Missing client_assertion"), resolve JWKS, validate; else → existing
  secret path. Client lookup: `client_id` from Basic/form, else (divergence 36)
  `unverified_assertion_subject(form["client_assertion"])`.
- `app.py`: `app.state.jti_guard = JtiReplayGuard()`; `app.state.jwks_cache = JwksCache(app.state.http_client)` (after the http client is created).
- `routes/register.py`: `_VALID_AUTH_METHODS` += `client_secret_jwt`, `private_key_jwt`;
  reject `private_key_jwt` without `jwks`/`jwks_uri` ("private_key_jwt requires jwks or
  jwks_uri"), reject both present ("jwks and jwks_uri are mutually exclusive") — both via
  `_registration_error` (Python's `invalid_client_metadata` code, existing divergence);
  persist `jwks=json.dumps(reg.jwks) if reg.jwks else ""`, `jwks_uri=reg.jwks_uri or ""`;
  echo `jwks`/`jwks_uri` in the registration response when set.
- `routes/wellknown.py`: `token_endpoint_auth_methods_supported` = `["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"]`;
  add `introspection_endpoint_auth_methods_supported` and
  `revocation_endpoint_auth_methods_supported` = the same list without `none`.

- [ ] **Step 1: Failing tests** (`tests/test_client_assertion.py`; helpers: `make_client_assertion(client_id, key, alg, aud=..., **claim_overrides)` and an RSA keypair → inline JWKS via `jwt.algorithms.RSAAlgorithm.to_jwk`; seed via `reseed_client(client_app, token_endpoint_auth_method="client_secret_jwt", ...)` / `private_key_jwt` + `jwks=`):
  `test_rfc7523_client_secret_jwt_authentication` (client_credentials, 200),
  `test_rfc7523_client_secret_jwt_wrong_secret_fails` (401 `invalid_client`),
  `test_rfc7523_private_key_jwt_authentication` (inline jwks, 200),
  `test_private_key_jwt_kid_mismatch_rejected`,
  `test_client_secret_jwt_rejects_rs256_alg` / `test_private_key_jwt_rejects_hs256_alg`,
  `test_assertion_wrong_audience_rejected`, `test_assertion_iss_sub_mismatch_rejected`,
  `test_assertion_missing_jti_rejected`, `test_assertion_expired_rejected`,
  `test_vector_l_client_assertion_jti_replay` (first 200, replay 401 body contains `invalid_client`),
  `test_assertion_without_form_client_id_resolves_from_sub` (divergence 36),
  `test_missing_client_assertion_type_rejected`, `test_unsupported_client_assertion_type_rejected`,
  `test_jwt_client_presenting_basic_auth_is_rejected` (registered method wins),
  `test_private_key_jwt_jwks_uri_fetched_once_and_cached` (swap `client_app.app.state.http_client` for an `httpx.AsyncClient(transport=httpx.MockTransport(handler))` counting calls; two auths → one fetch),
  `test_private_key_jwt_jwks_uri_http_error_rejected`,
  `test_jwks_cache_ttl_from_cache_control_clamped` (unit: max-age=5 → 30, max-age=999999 → 86400, absent → 300),
  `test_jti_guard_first_observation_fresh_replay_rejected`, `test_jti_guard_different_clients_do_not_collide`, `test_jti_guard_expired_entry_fresh_again` (monkeypatch `time.monotonic`),
  `test_introspection_accepts_client_secret_jwt` (assertion `aud` = token endpoint URL, per Rust),
  `test_rfc7591_private_key_jwt_requires_jwks` (400 mentioning "jwks"; with jwks → 201),
  `test_rfc7591_jwks_and_jwks_uri_mutually_exclusive` (400),
  `test_registration_accepts_client_secret_jwt` (201, echoed method),
  `test_discovery_advertises_jwt_auth_methods` (+ the two new `*_auth_methods_supported` keys).
  Update `tests/test_registration.py::test_invalid_auth_method_rejected` to use `"bogus_method"`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 7523 client_secret_jwt/private_key_jwt client auth with jti replay guard and jwks_uri cache"`

---

### Task 2: RFC 8707 Resource Indicators → `aud`

**Files:**
- Modify: `src/oauth2_server/models.py` (`Claims.new(resource=)`), `src/oauth2_server/services/tokens.py`
  (`issue(resource=)`), `src/oauth2_server/services/auth.py` (`issue_code(resource=)`),
  `src/oauth2_server/routes/authorize.py`, `src/oauth2_server/routes/token.py`,
  `src/oauth2_server/routes/introspect.py`, `src/oauth2_server/routes/wellknown.py`
- Create: `src/oauth2_server/services/resource.py` (`validate_resource(value: str | None) -> str | None`, raises `OAuthError("invalid_target", "resource must be an absolute URI without a fragment", 400)`)
- Test: `tests/test_resource_indicators.py` (new), `tests/test_wellknown.py`

**Interfaces:**
- `Claims.new(..., resource: str | None = None)`: `aud = [resource] if resource else [client_id]`.
- `TokenService.issue(..., resource: str | None = None)` passes through; opaque mode ignores it (nothing to carry).
- `routes/token.py`: `client_credentials`, `refresh_token`, `device_code`, token-exchange read
  `validate_resource(form.get("resource"))` before issuing; `authorization_code` uses
  `auth_code.resource` (stored) and ignores a form value (RFC 8707 §2.2 lets the token request
  narrow it, but Rust uses the stored value — parity). Validation failures → `oauth_error("invalid_target", ...)`.
- `routes/authorize.py`: `validate_resource(merged.get("resource"))` right after the existing
  per-parameter validation block, using the same error-delivery path the route uses for
  `invalid_scope` (redirect with `error=invalid_target` when the redirect_uri is already
  validated, else JSON 400); pass to `issue_code(resource=...)`.
- `routes/introspect.py`: `aud` = the verified access-token claims' `aud` when
  `decode_access_token` succeeds (already attempted for `jti`), else `row.client_id`.
- Discovery: `"resource_indicators_supported": True`.

- [ ] **Step 1: Failing tests**:
  `test_vector_m_resource_to_aud_claim` (client_credentials with `resource=https://api.resource.test`; header `typ == "at+JWT"`; unverified claims `aud == "https://api.resource.test"` (bare string, single-aud serde rule), `client_id == "client1"`, `iss == issuer`),
  `test_rfc8707_resource_indicator_accepted_in_client_credentials` (200, `token_type == "Bearer"`),
  `test_resource_absent_keeps_client_id_aud`,
  `test_resource_on_authorize_is_stored_on_code_and_bound_to_token_aud` (reuse `run_code_flow` from `tests/test_token_endpoint.py` with an extra `resource` query param, or drive the flow inline),
  `test_resource_on_refresh_rebinds_aud`, `test_resource_on_device_grant_binds_aud`,
  `test_relative_resource_rejected_invalid_target`, `test_resource_with_fragment_rejected_invalid_target`,
  `test_authorize_invalid_resource_redirects_with_invalid_target`,
  `test_introspection_aud_reflects_resource`, `test_discovery_advertises_resource_indicators`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 8707 resource indicators bound to access-token aud"`

---

### Task 3: RFC 9728 protected-resource metadata, status-list stub, discovery + userinfo parity

**Files:**
- Modify: `src/oauth2_server/routes/wellknown.py`
- Test: `tests/test_wellknown.py`

**Interfaces:**
- `GET /.well-known/oauth-protected-resource` → 200 JSON, `Cache-Control: public, max-age=3600`:
  `{"resource": base, "authorization_servers": [base], "bearer_methods_supported": ["header"], "dpop_signing_alg_values_supported": ["ES256","RS256"], "token_introspection_endpoint": f"{base}/oauth/introspect", "jwks_uri": f"{base}/.well-known/jwks.json", "scopes_supported": [same list as discovery]}` (no `tls_client_certificate_bound_access_tokens` — divergence 33).
- `GET /.well-known/oauth-authorization-server/status` → 200 `application/json`:
  `{"status_list": {"bits": 1, "lst": "eNrb2FgAAQABAAE"}, "issuer": base, "status_list_uri": f"{base}/.well-known/oauth-authorization-server/status"}`. Route must be registered so it does not shadow / get shadowed by the RFC 8414 path.
- Discovery additions: `token_introspection_endpoint`, `token_revocation_endpoint` (aliases),
  `service_documentation: f"{base}/docs"` (only if the app still serves FastAPI docs — verify; omit otherwise),
  `claims_supported` → `["sub","iss","aud","exp","iat","nonce","at_hash","email","preferred_username"]`.
- Userinfo: response gains `"iss": config.issuer` and `"aud": row.client_id` (token's client), before the scope-gated claims.

- [ ] **Step 1: Failing tests**: `test_wave4_rfc9728_protected_resource_metadata_returns_200`,
  `test_wave4_rfc9728_protected_resource_metadata_has_resource_field`,
  `test_wave4_rfc9728_protected_resource_metadata_has_authorization_servers`,
  `test_protected_resource_metadata_is_cacheable`,
  `test_wave4_token_status_list_returns_200`, `test_wave4_token_status_list_returns_valid_json`
  (asserts the exact body above), `test_discovery_endpoint_aliases`, `test_discovery_claims_supported_parity`,
  `test_userinfo_includes_iss_and_aud` (extend the existing userinfo test in `tests/test_wellknown.py`).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 9728 protected-resource metadata, status-list stub, discovery/userinfo parity"`

---

### Task 4: RFC 9701 JWT introspection responses

**Files:**
- Modify: `src/oauth2_server/routes/introspect.py`, `src/oauth2_server/security.py` (add `encode_introspection_jwt(payload: dict, config, keyset) -> str`)
- Test: `tests/test_introspection_jwt.py` (new)

**Interfaces:**
- In `introspect`, after client auth: `wants_jwt = "application/token-introspection+jwt" in request.headers.get("accept", "")`.
  Every return path that would send a JSON body (`_inactive_response()` and the active body)
  instead calls `_introspection_response(request, body_dict, client)` which, when `wants_jwt`,
  returns `Response(content=<jwt>, media_type="application/token-introspection+jwt", headers={"Cache-Control": "no-store"})`.
  JWT payload: `{"iss": config.issuer, "aud": client.client_id, "iat": now, "token_introspection": body_dict}`;
  header `typ = "token-introspection+jwt"`, `kid` when signing with a keyset key.
  Signing (divergence 34): `keyset.current_for_alg("RS256")` when `config.id_token_alg == "RS256"` and present, else HS256 `config.jwt_secret` (kid-less).
- Auth failures (`invalid_client` etc.) stay JSON — they are not introspection results.

- [ ] **Step 1: Failing tests**: `test_rfc9701_jwt_accept_header_returns_jwt_introspection_response` (200, content-type contains the media type, header `typ`), `test_rfc9701_standard_accept_returns_json_introspection_response`, `test_rfc9701_jwt_payload_contains_token_introspection_claim` (`active is True`, `client_id` matches, `iss`, `aud == "client1"`), `test_rfc9701_inactive_result_is_also_wrapped` (divergence 34), `test_rfc9701_hs256_signature_verifies_with_jwt_secret`, `test_rfc9701_rs256_uses_keyset_kid` (build app with `id_token_alg="RS256"` like `tests/test_jwks_rs256.py` does; `kid` header equals the JWKS key's kid and the JWT verifies against `/.well-known/jwks.json`), `test_rfc9701_response_has_no_store`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 9701 JWT-secured introspection responses"`

---

### Task 5: RFC 8628 `slow_down` on device polling

**Files:**
- Create: `src/oauth2_server/services/device_poll.py`
- Modify: `src/oauth2_server/routes/token.py` (device branch), `src/oauth2_server/app.py`
- Test: `tests/test_device_flow.py`

**Interfaces:**
- `class DevicePollTracker`: `observe(device_code: str, base_interval: int) -> int | None` —
  returns `None` when the poll is allowed (records `now`), or the NEW required interval when
  the poll arrived sooner than the current required interval (which starts at `base_interval`
  and grows by 5 s on each violation, RFC 8628 §3.5). Entries expire after 24 h (sweep on
  call, same `time.monotonic()` pattern as `DpopReplayStore`); `forget(device_code)` on
  redemption/terminal states.
- `routes/token.py` device branch: call the tracker immediately after the `device is None`/
  client mismatch check and before the expiry/denied/used/pending checks; on violation return
  `oauth_error("slow_down", "polling too frequently; increase interval")` and include
  `"interval": <new interval>` in the error body (extra member allowed by RFC 6749 §5.2).
  Call `forget` once the code is redeemed.
- `app.py`: `app.state.device_poll = DevicePollTracker()`.

- [ ] **Step 1: Failing tests**: `test_device_poll_faster_than_interval_returns_slow_down` (two immediate polls → second is 400 `slow_down` with `interval == 10`), `test_device_poll_respecting_interval_returns_authorization_pending` (monkeypatch `time.monotonic` to advance past the interval), `test_slow_down_escalates_required_interval` (third too-fast poll → `interval == 15`), `test_slow_down_does_not_block_approved_redemption_after_wait`, unit tests for `DevicePollTracker`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 8628 slow_down on over-fast device polling"`

---

### Task 6: Docs, backlog, memory

**Files:**
- Modify: `README.md` (new "## Phase 4a: JWT client auth, resource indicators, metadata parity" section before "## Running": feature list, new single-process stores — JTI replay guard, JWKS cache, device poll tracker — and the RFC 9701 / `slow_down` notes), `docs/PHASE2-BACKLOG.md` (divergences 32–36 under a "From Phase 4a" heading; mark the `slow_down` and "RFC 9728 not ported / RFC 8707 absent" gap entries as Done (4a); add a "Phase 4 roadmap" pointer to this plan's table for 4b/4c).

- [ ] **Step 1:** Write the docs. **Step 2:** `bash scripts/gate.sh` PASS. **Step 3: Commit** — `git commit -m "docs(python): Phase 4a README section, backlog divergences 32-36, Phase 4 roadmap"`.
