# Python OAuth2 Server Port — Phase 3b Implementation Plan (DPoP, RAR, Token Exchange)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the three protocol extensions from the Rust server — DPoP (RFC 9449), Rich Authorization Requests (RFC 9396), and Token Exchange (RFC 8693) — fixing the Rust implementation's documented spec violations where they are security-relevant.

**Architecture:** Two new services (`services/dpop.py` proof validation + replay store, `services/dpop_nonce.py` stateless HMAC nonce issuer) plus handler plumbing in the token/introspect/authorize routes. RAR and token exchange are pure handler/claims work — the `authorization_codes.authorization_details` column (V15) and `clients.dpop_nonce_required` (V21) already exist. Zero new migrations.

**Tech Stack:** unchanged — PyJWT (`jwt.algorithms.*.from_jwk` for embedded-JWK verification) + cryptography.

## Global Constraints

- Schema owned by the Rust repo — zero new migrations. `bash scripts/gate.sh` green at every commit. TDD per task.
- Authoritative research: `.superpowers/sdd/research-dpop.md` and `.superpowers/sdd/research-rar-token-exchange.md` — exact error strings, validation order, and Rust gaps live there.
- In-memory stores (DPoP replay) follow the ParStore precedent: single-process, documented.
- **Deliberate divergences from Rust (record in PHASE2-BACKLOG.md when landed):**
  14. The DPoP replay store is mandatory app state — no silent per-request fallback store that no-ops replay protection (Rust constructs a throwaway store when app_data is missing).
  15. RAR is validated: `authorization_details` must be a JSON array of objects, each with a `type` member in the configured allowlist (`rar_types_supported`, default `["openid"]` for discovery parity) → violations get 400 `invalid_authorization_details` (RFC 9396 §5). Rust accepts any JSON shape with no type enforcement (its own audit lists this as backlog gap #20).
  16. At authorization_code redemption the CONSENTED (auth-code-stored) `authorization_details` wins; a conflicting token-request value is rejected with 400 `invalid_authorization_details` (RFC 9396 §6.1). Rust lets the token request replace the consented value (privilege-escalation-shaped).
  17. `authorization_details` is echoed in the token response body (RFC 9396 §7.1) and included in introspection (§9.2) — Rust does neither.
  18. Token exchange validates `subject_token_type` (required, must be `urn:ietf:params:oauth:token-type:access_token`) and `requested_token_type` (absent or the same access-token URN) → 400 `invalid_request` otherwise. Rust parses and ignores both.
  19. The `act` claim (`{"sub": <exchanging client_id>}`) is embedded in the issued JWT as well as the response body (RFC 8693 §4.1). Rust only puts it in the response JSON.
- **Rust gaps deliberately KEPT (parity — record as "known gaps" in the backlog, not divergences):** no `ath` claim; no resource-side DPoP at userinfo (Bearer accepted); no `dpop_jkt` at authorize/PAR; device grant never cnf-bound; refresh carries the old token's cnf forward without a fresh proof; no DPoP-Nonce header on success responses; opaque-token mode silently drops cnf/authorization_details.

---

### Task 1: DPoP proof validation + replay store

**Files:**
- Create: `src/oauth2_server/services/dpop.py`
- Test: `tests/test_dpop.py` (new)

**Interfaces:**
- `DPOP_IAT_SKEW_SECS = 300`; `REPLAY_TTL_SECS = 660`.
- `class DpopReplayStore:` — `check_and_insert(jti: str) -> None` raises `DpopError` ("DPoP proof jti has already been used (replay)") on duplicates; in-memory dict jti→monotonic expiry with dict-wide sweep per call (ParStore precedent); single-process docstring.
- `class DpopError(Exception)`: `.error` (`"invalid_dpop_proof"`) + `.description`.
- `@dataclass class DpopValidated: jkt: str; nonce: str | None`.
- `def jwk_thumbprint(jwk: dict) -> str` — RFC 7638: canonical JSON (sorted, separators=(",", ":")) of minimal members — EC `{crv,kty,x,y}`, RSA `{e,kty,n}`, OKP `{crv,kty,x}` — SHA-256, base64url-no-pad. Unsupported kty → `DpopError` "Unsupported JWK key type".
- `def validate_dpop_proof(proof: str, method: str, url: str, replay_store: DpopReplayStore) -> DpopValidated` — validation order and exact error descriptions from the research digest §key_behaviors: header parse → typ `dpop+jwt` (case-insensitive) → `jwk` header present → thumbprint → signature via the embedded JWK with header alg (allowed: RS256/RS384/RS512/PS256/PS384/PS512/ES256/ES384; build the key via `jwt.algorithms.RSAAlgorithm.from_jwk`/`ECAlgorithm.from_jwk`) with required claims `[htm, htu, iat, jti]`, `verify_aud=False`, no exp requirement → htm case-insensitive match → htu compared after stripping query/fragment and trailing slashes from both sides → `iat` within ±300s → jti replay check. Every failure raises `DpopError` with the Rust description strings.

- [ ] **Step 1: Failing tests** — port the Rust units by name: `test_dpop_invalid_typ` (JOSE typ "JWT" → error description contains "typ"), `test_dpop_jti_replay` (second insert → "replay"), `test_replay_store_accepts_different_jti`, `test_strip_query_removes_query_string`, `test_thumbprint_rsa_and_ec_match_rfc7638` (compute an EC P-256 thumbprint against an independently-computed value in the test), plus the e2e-grade unit Rust lacks: `test_valid_es256_proof_validates` (generate an EC key with cryptography, build a real proof JWT with typ/jwk/htm/htu/iat/jti, assert returned jkt equals the test's own thumbprint computation), `test_wrong_htu_rejected`, `test_stale_iat_rejected`, `test_unsupported_alg_rejected` (HS256 proof), `test_expired_replay_entries_swept`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): DPoP proof validation and replay store (RFC 9449)"`

---

### Task 2: DPoP nonce issuer

**Files:**
- Create: `src/oauth2_server/services/dpop_nonce.py`
- Modify: `src/oauth2_server/config.py`
- Test: `tests/test_dpop_nonce.py` (new)

**Interfaces:**
- Config: `dpop_nonce_secret: str | None = None` (env `OAUTH2_DPOP_NONCE_SECRET`; decoded trying base64url-no-pad → std base64 → hex-when-64-chars; wrong length/undecodable → random per-process 32 bytes, matching Rust's silent fallback but log a warning — small improvement), `dpop_nonce_lifetime_secs: int = 300` (clamped ≥ 1).
- `class DpopNonceIssuer(secret: bytes, lifetime_secs: int)`:
  - `issue() -> str` — base64url-no-pad(8-byte BE bucket_id ‖ HMAC-SHA256(secret, bucket_bytes)[:16]); bucket_id = unix_now // lifetime.
  - `verify(nonce: str) -> None` — raises `DpopNonceError(kind)` where kind ∈ {"stale", "invalid"}: bad base64 → invalid "DPoP nonce is not valid base64url"; wrong length → invalid "DPoP nonce has incorrect length"; tag mismatch (constant-time via `hmac.compare_digest`) → invalid "DPoP nonce signature mismatch"; bucket not in {current, current−1} → stale "DPoP nonce is expired or not yet valid". Typed kinds replace Rust's substring matching (research gotcha).
- `def use_dpop_nonce_response(issuer, description) -> ORJSONResponse` — 400, header `DPoP-Nonce: <issuer.issue()>`, body `{"error": "use_dpop_nonce", "error_description": <description>}`.
- `def enforce_dpop_nonce(validated: DpopValidated, issuer) -> ORJSONResponse | None` — no nonce → use_dpop_nonce "DPoP proof must include a server-issued nonce"; stale → use_dpop_nonce "DPoP nonce is expired; retry with a fresh nonce"; invalid (forged/malformed) → raise `DpopError` (invalid_dpop_proof — a tamperer is NOT handed a fresh nonce).

- [ ] **Step 1: Failing tests** — port by name: `test_missing_nonce_returns_use_dpop_nonce`, `test_valid_nonce_accepted`, `test_forged_nonce_rejected_as_invalid_proof` (flip a bit in byte 10), `test_stale_nonce_returns_use_dpop_nonce` (1-second buckets + monkeypatched clock, no sleeps), `test_use_dpop_nonce_response_includes_header_and_body` (header value passes issuer.verify), `test_previous_bucket_accepted_current_plus_one_rejected`, `test_nonce_from_different_secret_rejected`, `test_malformed_nonce_rejected`, `test_secret_decoding_formats` (base64url/std/hex all accepted; garbage falls back with warning).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): stateless DPoP nonce issuer (use_dpop_nonce challenge)"`

---

### Task 3: Token-endpoint DPoP integration

**Files:**
- Modify: `src/oauth2_server/routes/token.py`, `src/oauth2_server/services/tokens.py`, `src/oauth2_server/models.py` (Claims gains `cnf: dict | None = None`), `src/oauth2_server/app.py` (`app.state.dpop_replay = DpopReplayStore()`, `app.state.dpop_nonce_issuer = DpopNonceIssuer(...)`), `src/oauth2_server/routes/wellknown.py` (discovery)
- Test: `tests/test_dpop_token.py` (new)

**Interfaces:**
- `POST /oauth/token`: when a `DPoP` header is present — non-UTF-8 → 400 `invalid_request` "DPoP header is not valid UTF-8"; validate proof against the request method + URL (issuer-based URL: `config.issuer` + path — document that we use the configured issuer rather than reconstructing from Host, a hardening simplification vs Rust's connection_info); failure → 400 `{"error":"invalid_dpop_proof", ...}`. Then, when the authenticated client has `dpop_nonce_required=True`, run `enforce_dpop_nonce` (its `ORJSONResponse` returned verbatim). A valid proof yields `cnf={"jkt": ...}` applied to the issued access token for authorization_code, client_credentials (and token-exchange in Task 6); `Claims.cnf` serialized into the JWT; `TokenResponse.token_type` becomes `"DPoP"` when cnf is set (response only — the stored Token row stays "Bearer", Rust parity). Refresh grant: decode the OLD access token unverified, carry its `cnf` into the new token (no fresh proof required — documented parity gap). Device grant: cnf never bound (parity). Opaque mode: cnf silently dropped (parity, documented).
- `TokenService.issue(..., cnf: dict | None = None)`.
- Discovery: `dpop_signing_alg_values_supported: ["ES256", "RS256"]` (parity — narrower than the validator, like Rust).

- [ ] **Step 1: Failing tests** — the e2e coverage Rust lacks (research gotcha #1): `test_client_credentials_with_es256_proof_binds_cnf` (real proof → 200; `token_type == "DPoP"`; decoded access token has `cnf.jkt` equal to the test-computed thumbprint), `test_auth_code_flow_with_proof_binds_cnf`, `test_invalid_proof_rejected_400`, `test_nonce_required_client_bootstrap` (client with dpop_nonce_required seeded via storage: first proof without nonce → 400 use_dpop_nonce + DPoP-Nonce header; second proof embedding that nonce → 200), `test_forged_nonce_gets_invalid_dpop_proof_no_fresh_nonce`, `test_refresh_carries_cnf_forward` (refresh without any DPoP header → new access token still has the old jkt), `test_no_proof_issues_plain_bearer` (dpop_nonce_required client without DPoP header → plain Bearer, no error — Rust parity), `test_discovery_advertises_dpop_algs`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): DPoP-bound access tokens at the token endpoint"`

---

### Task 4: Introspection DPoP binding

**Files:**
- Modify: `src/oauth2_server/routes/introspect.py`, `src/oauth2_server/models.py` (IntrospectionResponse gains `cnf`)
- Test: `tests/test_dpop_token.py` (extend)

**Interfaces:**
- After locating an active token, decode its claims (unverified first — the storage row is the validity gate, established pattern): if `cnf.jkt` present, the introspection request MUST carry a valid `DPoP` proof (validated against the introspection URL + POST, same replay store) whose thumbprint equals the token's jkt — missing header / invalid proof / jkt mismatch → 200 `{"active": false}` (never an error body). Success → response includes `cnf`. Non-UTF-8 DPoP header → 400 invalid_request. `token_type` stays the stored "Bearer" (Rust parity, documented quirk).

- [ ] **Step 1: Failing tests** — `test_introspect_jkt_bound_token_requires_proof` (no header → active:false), `test_introspect_with_matching_proof_active_true_and_cnf`, `test_introspect_with_wrong_key_proof_inactive`, `test_introspect_unbound_token_unaffected`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): introspection enforces DPoP jkt binding (RFC 9449 §7.1)"`

---

### Task 5: RAR — validated authorization_details end-to-end

**Files:**
- Modify: `src/oauth2_server/routes/authorize.py`, `src/oauth2_server/routes/token.py`, `src/oauth2_server/routes/introspect.py`, `src/oauth2_server/services/auth.py` (issue_code carries details), `src/oauth2_server/services/tokens.py`, `src/oauth2_server/models.py` (Claims + TokenResponse + IntrospectionResponse gain `authorization_details`), `src/oauth2_server/config.py` (`rar_types_supported: list[str] = ["openid"]`), `src/oauth2_server/routes/wellknown.py`
- Create: `src/oauth2_server/services/rar.py`
- Test: `tests/test_rar.py` (new)

**Interfaces:**
- `services/rar.py`: `validate_authorization_details(raw: str, allowed_types: list[str]) -> list[dict]` — JSON parse → must be a non-empty array of objects, each with a string `type` in `allowed_types` → violations raise `RarError(error="invalid_authorization_details", description=...)` with descriptions: "authorization_details is not valid JSON" (parse), "authorization_details must be a JSON array of objects", "authorization_details entry is missing a type", "authorization_details type '<t>' is not supported".
- Authorize: `authorization_details` accepted as a query param (already merged from PAR — the 10-key whitelist includes it); validate BEFORE minting the code — violations → **error redirect** `invalid_authorization_details` (redirect_uri already validated at that point); valid → stored raw on the auth code row (column exists).
- Token endpoint: form field validated the same way for client_credentials (no consent) → embedded. authorization_code redemption: the STORED value wins; a token-request value that differs from the stored one (string inequality after both present) → 400 `invalid_authorization_details` "authorization_details must not be altered at redemption" (divergence 16); absent stored + present request value → validate + embed. Refresh/device: details dropped (Rust parity, documented).
- `Claims.authorization_details` (list) serialized into JWT access tokens; `TokenResponse.authorization_details` echoed when present (divergence 17); introspection includes it for active tokens (from the JWT claims; opaque-mode tokens have none — parity).
- Discovery: `authorization_details_types_supported: config.rar_types_supported`.

- [ ] **Step 1: Failing tests** — `test_discovery_advertises_rar_types` (port of wave4 pin), `test_authorize_rejects_unknown_rar_type` (redirect carries error=invalid_authorization_details), `test_authorize_rejects_malformed_rar`, `test_full_flow_embeds_details_in_jwt_and_response` (authorize with `[{"type":"openid","actions":["read"]}]` → token response echoes it, decoded JWT claim matches, introspection includes it), `test_redemption_rejects_altered_details` (differing token-request value → 400 invalid_authorization_details; family NOT revoked), `test_client_credentials_details_validated_and_embedded`, `test_refresh_drops_details` (parity pin), `test_par_pushed_details_flow` (details via PAR → same end-to-end result).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 9396 rich authorization requests with type validation"`

---

### Task 6: Token exchange (RFC 8693)

**Files:**
- Modify: `src/oauth2_server/routes/token.py` (new grant branch), `src/oauth2_server/models.py` (Claims gains `act: dict | None`), `src/oauth2_server/routes/wellknown.py` (grant_types_supported)
- Test: `tests/test_token_exchange.py` (new)

**Interfaces:**
- Grant `urn:ietf:params:oauth:grant-type:token-exchange` at `POST /oauth/token`, checks in order:
  1. grant in `client.grant_type_list()` (exact URN) → else 400 `unauthorized_client` (existing message).
  2. Public client → 401 `invalid_client` "Public clients cannot use token-exchange".
  3. `subject_token` required → 400 `invalid_request` "Missing subject_token".
  4. `subject_token_type` required and must equal `urn:ietf:params:oauth:token-type:access_token` → 400 `invalid_request` "unsupported subject_token_type" (divergence 18).
  5. `requested_token_type` absent or the access-token URN → else 400 `invalid_request` "unsupported requested_token_type" (divergence 18).
  6. subject token resolved by storage lookup (`get_token_by_access_token`) — missing → 400 `invalid_grant` "subject_token not found or expired"; revoked/expired → 400 `invalid_grant` "subject_token is expired or revoked".
  7. scope: absent → inherit subject scope; present → must be subset → 400 `invalid_scope` "requested scope exceeds client permissions".
  8. Issue: access token with `user_id` = subject token's user, `client_id` = exchanging client, `with_refresh=False`, no token_family, cnf from THIS request's DPoP proof (Task 3 plumbing), `act={"sub": <exchanging client_id>}` embedded in the JWT AND echoed in the response body when `actor_token` was present (divergence 19 — and matching Rust's response-body act otherwise... no: **always** embed act in the JWT for exchanged tokens, body act only when actor_token present, mirroring Rust's body behavior while fixing the JWT gap; document precisely in the report).
  9. Response 200 no-store: `{"access_token", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer"|"DPoP", "expires_in", "scope"}` (+ `act` per above). No refresh token ever.
- Discovery `grant_types_supported` gains the URN.

- [ ] **Step 1: Failing tests** — port by name: `test_rfc8693_token_exchange_grant_type_in_discovery`, `test_expired_subject_token_is_rejected` (seeded expired token → 400 invalid_grant), `test_valid_subject_token_is_exchanged` (200; plus the body assertions Rust never made: issued_token_type URN, subject's sub in the JWT, exchanging client_id, no refresh_token) — and new: `test_exchange_requires_registered_grant`, `test_public_client_rejected`, `test_missing_subject_token_type_rejected`, `test_unsupported_requested_token_type_rejected`, `test_scope_narrowing_enforced` (superset → invalid_scope; subset → issued with narrowed scope), `test_act_embedded_when_actor_token_present` (JWT act.sub == exchanging client), `test_exchanged_token_introspects_for_exchanging_client_only` (cross-client active:false, Rust parity).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 8693 token exchange grant"`

---

### Task 7: Phase 3b acceptance

**Files:**
- Modify: `tests/test_rfc_compliance.py`, `docs/PHASE2-BACKLOG.md`, `README.md`

- [ ] **Step 1:** Compliance pins: `test_dpop_bound_token_round_trip`, `test_dpop_nonce_challenge_flow`, `test_rar_full_flow_with_type_validation`, `test_token_exchange_round_trip`.
- [ ] **Step 2:** `bash scripts/gate.sh` green.
- [ ] **Step 3:** Docs: README (new env vars `OAUTH2_DPOP_NONCE_SECRET`/`OAUTH2_DPOP_NONCE_LIFETIME_SECS`, `rar_types_supported`, feature list; single-process note for the replay store); PHASE2-BACKLOG — divergences 14–19 appended, kept-gaps list (no ath, no resource-side DPoP, no dpop_jkt at authorize/PAR, device unbound, refresh cnf carry-over, opaque-mode drops) recorded under Phase 3 candidates as "known DPoP/RAR gaps (Rust parity)".
- [ ] **Step 4: Commit** — `git commit -m "test(python): Phase 3b compliance pins + docs"`

---

## Self-Review (completed)

- **Coverage vs research:** every IMPLEMENTED Rust behavior has a task (proof validation T1, nonce T2, token binding + nonce gate + refresh carry T3, introspection T4, RAR acceptance points T5, exchange T6, discovery T3/T5/T6); every Rust GAP is either deliberately kept (Global Constraints list) or fixed as a numbered divergence (14–19).
- **Placeholder scan:** clean — exact error strings sourced from the research digests; test names enumerated per task.
- **Type consistency:** `DpopValidated`/`DpopError` (T1) consumed by T2's `enforce_dpop_nonce` and T3/T4 handlers; `Claims.cnf`/`act`/`authorization_details` land in models.py once (T3/T5/T6 in that order — later tasks extend, don't redefine); `TokenService.issue(..., cnf=...)` signature from T3 reused by T6.
- **Sequencing:** T1→T2→T3→T4 strictly ordered; T5 independent of DPoP but shares token.py — run after T4; T6 needs T3 (cnf) and T5 (models pattern); T7 last.
