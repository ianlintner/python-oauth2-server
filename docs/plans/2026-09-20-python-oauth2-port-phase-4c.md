# Python OAuth2 Server Port — Phase 4c Implementation Plan (mTLS, DPoP Hardening, Delegation Chains, Account Linking, Residuals)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** close the last Rust-parity feature (RFC 8705 mTLS client authentication and certificate-bound tokens) and the beyond-Rust security gaps the Phase 3b/4a/4b backlogs recorded: DPoP `ath` and resource-side enforcement at userinfo, `dpop_jkt` code binding, `DPoP-Nonce` on success, fresh proofs on public-client refresh, nested RFC 8693 `act` chains, verified-email social account linking, and the Phase 4b residuals (input size/depth caps, admin `redirect_uris` validation, honoring the stored `claims` request in id_tokens, RFC 8707 refresh `aud` subset).

**Architecture:** mTLS enters through the existing single client-auth funnel (`ClientService.authenticate` gains an `mtls` tuple extracted in each route, gated on `config.trust_proxy_headers`) so every endpoint gets it at once. One new `security.decode_unverified_claims` helper replaces the three existing ad-hoc unverified decodes and serves the four new readers. One `services/limits.py` helper bounds every client-supplied JSON parameter and the `act` chain depth. `dpop_jkt` bindings live in an in-process store (`app.state.dpop_code_bindings`) in the same style as the PAR/replay/nonce stores — the SQL schema is Rust-owned and this repo authors no migrations, so the binding is recorded as a documented single-process limitation with the Rust-side column (`V22`) named as the follow-up. Social linking adds one storage lookup (`get_user_by_email`) implemented on both backends.

**Tech Stack:** no new dependencies. Authoritative research: `.superpowers/sdd/research-phase-4c.md` (git-ignored; regenerate from the Rust repo if missing) — every Rust line citation and RFC quote referenced below lives there.

## Global Constraints

- Schema is owned by the Rust repo — zero SQL migrations. `Client.tls_client_certificate_subject_dn` and `Client.dpop_nonce_required` already have columns; `AuthorizationCode` has NO `dpop_jkt` column (see Task 5).
- `bash scripts/gate.sh` green at every commit. TDD per task. Error bodies via the existing `oauth_error`/`OAuthError`/`_deliver_error`/`_bad_request` helpers.
- User directive for Phase 4: **security best practice over Rust parity**; every such choice is a numbered divergence (continuing from 46).
- **Deliberate divergences from Rust (record in PHASE2-BACKLOG.md when landed):**
  47. `X-Client-Cert-Thumbprint` / `X-SSL-Client-S-DN` are honored ONLY when `config.trust_proxy_headers` is true; otherwise both are treated as absent (mTLS clients then fail closed with the "certificate missing" error). Rust reads them unconditionally, so anyone reaching the app directly can forge client auth and a `cnf` binding.
  48. `self_signed_tls_client_auth` verifies the presented thumbprint against the client's registered JWKS (a key whose `x5t#S256` member equals the header value); no JWKS or no match → `invalid_client` "self_signed_tls_client_auth: certificate does not match a registered JWK" (RFC 8705 §2.2). Rust accepts any thumbprint.
  49. Certificate-bound (`cnf.x5t#S256`) access tokens are ENFORCED at introspection and userinfo (RFC 8705 §3.2): the request must carry a matching `X-Client-Cert-Thumbprint` (subject to divergence 47). Rust binds but never enforces.
  50. DPoP proofs presented at userinfo MUST carry `ath` = base64url(SHA-256(access token)) (RFC 9449 §4.3); token/introspect proofs ignore `ath`.
  51. `GET|POST /oauth/userinfo` accepts `Authorization: DPoP <token>` and enforces `cnf.jkt` (RFC 9449 §7.1/§7.2): a bound token presented as Bearer, without a proof, with an invalid proof, an `ath` mismatch, or a `jkt` mismatch → 401 `WWW-Authenticate: DPoP error="invalid_token"` with distinct `error_description`s. Unbound tokens keep today's Bearer behavior.
  52. `dpop_jkt` authorization parameter (RFC 9449 §10) accepted at authorize (query/PAR/JAR overlay), validated as a 43-char base64url string, bound to the code in `app.state.dpop_code_bindings` (single-process; a code redeemed on another instance skips the check — documented), and enforced at redemption: missing proof or `jkt` mismatch → `invalid_grant`.
  53. `DPoP-Nonce` is set on successful token and userinfo responses when the client has `dpop_nonce_required` and presented a valid proof (RFC 9449 §8). Rust/Python 3b only sent it on the `use_dpop_nonce` challenge.
  54. Public-client refresh of a `jkt`-bound token requires a fresh DPoP proof with the SAME key (RFC 9449 §5); otherwise `invalid_grant`, checked before the old token is revoked. Confidential clients keep the salvage behavior.
  55. RFC 8693 §4.1 `act` chains nest: a subject token already carrying `act` yields `{"sub": <exchanging client>, "act": <prior act>}`; the same client re-exchanging collapses instead of nesting; chains deeper than 10 → `invalid_request`. Response-body `act` echoes the JWT claim. (Rust never writes `act` to the JWT.)
  56. Social login may link to an existing local account by email only when ALL hold: `OAUTH2_SOCIAL_LINK_BY_VERIFIED_EMAIL=true` (default false), the provider asserts a verified email (Google, GitHub; never Microsoft/Azure), the folded emails match exactly, exactly one local row matches, and that row is neither `role == "admin"` nor in `config.admin_emails`. Linking is implicit (no provider-link record; the row's username is untouched).
  57. Client-supplied JSON/URI parameters are bounded: `claims` ≤ 8192 bytes / depth 10, `authorization_details` ≤ 16384 bytes / depth 10, `resource` ≤ 2048 chars; violations use each parameter's existing error channel/code with the text "`<name>` exceeds the maximum length of N bytes|characters" / "… nesting depth of 10"; `RecursionError` is never reachable.
  58. Admin client create/update validate every `redirect_uris`/logout-URI element with the same rule DCR uses (an empty admin `redirect_uris` list stays allowed).
  59. The stored `claims_request` is honored for the id_token minted at code redemption: `acr`, `auth_time`, `email`, `preferred_username` under the `id_token` member, only when the granted scope already permits the claim (never widening), `essential` unmet → still succeed, `value`/`values` mismatch → omit. The `userinfo` member is NOT yet honored and `claims_parameter_supported` stays unadvertised.
  60. Refresh enforces RFC 8707 §2.2: a `resource` not in the old token's `aud` → `invalid_target` before any revocation; no `resource` → the old `aud` is carried forward instead of widening to `[client_id]`; opaque/non-JWT old tokens keep today's behavior.
- **Rust behaviors KEPT:** dispatch on the REGISTERED `token_endpoint_auth_method`; `tls_client_auth` outcomes and exact error descriptions (certificate missing; empty configured DN → any certificate; byte-exact DN compare; DN mismatch; DN configured but header missing); `cnf` precedence DPoP `jkt` over `x5t#S256`, never both; `x5t#S256` stored verbatim; `token_type` is `"DPoP"` only for `jkt` bindings (fixes the latent `services/tokens.py` bug the moment `x5t#S256` lands); device grant never binds; discovery `tls_client_certificate_bound_access_tokens: true` on both documents; no `mtls_endpoint_aliases`.

## Rust → Python map

| Rust | Python |
|---|---|
| `oauth.rs::authenticate_confidential_client` mTLS branches (174–239), header extraction (1522–1534) | `services/clients.py::ClientService.authenticate(mtls=)`, route-level `mtls_headers(request, config)` helper |
| `oauth.rs` `cnf_claim` precedence (1536–1541), `apply_dpop_token_type` (32–42) | `routes/token.py` shared pre-grant block, `services/tokens.py` |
| `wellknown.rs` mTLS discovery fields (85–93, 124, 305) | `routes/wellknown.py` |
| (beyond Rust) | `services/dpop.py` (`ath`), `routes/wellknown.py::userinfo`, `services/dpop_bindings.py`, `services/limits.py`, `services/claims_request.py`, `services/social.py`, `routes/social.py`, `storage/*::get_user_by_email` |

---

### Task 1: Shared infrastructure — mTLS header plumbing, unverified-claims helper, limits helper, shared redirect-URI validator

**Files:**
- Create: `src/oauth2_server/services/limits.py`, `src/oauth2_server/services/mtls.py`
- Modify: `src/oauth2_server/security.py` (`decode_unverified_claims`), `src/oauth2_server/services/clients.py` (`authenticate(..., mtls=None)`, move `is_valid_redirect_uri` here from `routes/register.py`), `src/oauth2_server/routes/{token,introspect,par,device}.py` (pass `mtls=mtls_headers(request, config)` at every `authenticate` call, incl. revoke), `src/oauth2_server/routes/token.py` (`_salvage_old_cnf` uses the helper), `src/oauth2_server/routes/introspect.py` (same), `src/oauth2_server/routes/register.py` (import the moved validator)
- Test: `tests/test_mtls.py` (new — plumbing/gating only), `tests/test_limits.py` (new)

**Interfaces:**
- `services/mtls.py::mtls_headers(request, config) -> tuple[str | None, str | None]` — `(thumbprint, subject_dn)` from `X-Client-Cert-Thumbprint`/`X-SSL-Client-S-DN`; both `None` unless `config.trust_proxy_headers` (divergence 47); empty strings → `None`.
- `ClientService.authenticate(request_form, authorization_header, *, mtls: tuple[str | None, str | None] | None = None)` — stored for Task 2; this task only threads it (no behavior change yet). Existing `from_app` unchanged.
- `security.decode_unverified_claims(token: str) -> dict` — `jwt.decode(token, options={"verify_signature": False})`, returns `{}` on any `PyJWTError`/non-str; replaces the bodies of `_salvage_old_cnf` and introspect's unverified read (behavior byte-identical; existing tests pin it).
- `services/limits.py`: `class LimitError(Exception)` with `.description`; `check_json_param(raw: str, *, name: str, max_len: int, max_depth: int) -> object` (length on the raw string first, `json.loads` catching `RecursionError` too, iterative depth walk); `check_len(raw: str, *, name: str, max_len: int, unit: str = "characters") -> str`; `check_depth(value: object, *, name: str, max_depth: int) -> None` (reused by Task 6). Messages exactly: "`{name}` exceeds the maximum length of {max_len} {unit}" / "`{name}` exceeds the maximum nesting depth of {max_depth}". NOT yet wired to call sites (Task 8).
- `services/clients.py::is_valid_redirect_uri(uri) -> bool` — moved verbatim from `routes/register.py::_is_valid_redirect_uri`; register keeps a thin alias.

- [ ] **Step 1: Failing tests** — `test_mtls_headers_ignored_without_trust_proxy` / `test_mtls_headers_read_with_trust_proxy` (unit on `mtls_headers`), `test_authenticate_accepts_mtls_kwarg_without_behavior_change` (secret client still authenticates with the tuple passed), limits unit tests: over-length, over-depth (a 50-deep nested array), 100 000-deep string never raises `RecursionError` (returns `LimitError`), exact messages, `check_depth` on a nested dict; `test_decode_unverified_claims_returns_empty_on_garbage`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "refactor(python): mTLS header plumbing (trust-proxy gated), shared unverified-claims decode, JSON limits helper, shared redirect-URI validator"`

---

### Task 2: RFC 8705 client authentication (`tls_client_auth`, `self_signed_tls_client_auth`)

**Files:**
- Modify: `src/oauth2_server/services/clients.py` (`VALID_AUTH_METHODS` += both; new branches in `authenticate`), `src/oauth2_server/models.py` (`ClientRegistration.tls_client_certificate_subject_dn: str | None`, echoed in the registration response), `src/oauth2_server/routes/register.py`, `src/oauth2_server/routes/admin/clients.py` (accept/persist/echo `tls_client_certificate_subject_dn`; method validation already shared)
- Test: `tests/test_mtls.py`, `tests/test_registration.py`, `tests/test_admin_clients.py`

**Interfaces:** in `authenticate`, after the denylist/public checks and beside the JWT dispatch: `tls_client_auth` → thumbprint `None` → `invalid_client` "tls_client_auth requires a TLS client certificate (X-Client-Cert-Thumbprint header missing)"; configured DN empty → authenticated; DN configured: header `None` → "tls_client_auth requires X-SSL-Client-S-DN header when Subject DN is configured"; `!=` (byte-exact) → "tls_client_auth: client certificate Subject DN does not match". `self_signed_tls_client_auth` → thumbprint `None` → "self_signed_tls_client_auth requires a TLS client certificate (X-Client-Cert-Thumbprint header missing)"; else (divergence 48) resolve the client's JWKS via `resolve_client_jwks` (inline or `jwks_uri`) and require a key whose `x5t#S256` equals the thumbprint (constant-time compare) → else "self_signed_tls_client_auth: certificate does not match a registered JWK". A form `client_secret` never substitutes for a certificate on these methods. Registration/admin: `self_signed_tls_client_auth` requires `jwks` or `jwks_uri` ("self_signed_tls_client_auth requires jwks or jwks_uri").

- [ ] **Step 1: Failing tests** — `test_vector_p_mtls_subject_dn_validation` (matching DN → 200 client_credentials; mismatched → 401 `invalid_client`), `test_tls_client_auth_missing_certificate_rejected`, `test_tls_client_auth_empty_dn_accepts_any_certificate`, `test_tls_client_auth_dn_configured_header_missing_rejected`, `test_tls_client_auth_ignores_form_client_secret`, `test_tls_client_auth_rejected_without_trust_proxy` (divergence 47), `test_self_signed_matches_registered_jwk`, `test_self_signed_unknown_thumbprint_rejected`, `test_self_signed_without_jwks_rejected`, `test_mtls_authenticates_at_par_and_introspect`, `test_registration_accepts_tls_client_auth_with_subject_dn`, `test_admin_create_and_update_persist_subject_dn`, `test_registration_self_signed_requires_jwks`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): RFC 8705 tls_client_auth and self_signed_tls_client_auth client authentication"`

---

### Task 3: `cnf: {"x5t#S256"}` binding, enforcement, discovery

**Files:**
- Modify: `src/oauth2_server/routes/token.py` (shared pre-grant block builds `cnf` with Rust precedence; token-exchange too; device never), `src/oauth2_server/services/tokens.py` (`token_type` = `"DPoP"` only when `cnf.get("jkt")`), `src/oauth2_server/routes/introspect.py` (enforce `x5t#S256` beside the `jkt` block → `{"active": false}` on missing/mismatched header, subject to divergence 47), `src/oauth2_server/routes/wellknown.py` (auth-method lists += both mTLS methods on all three lists; `tls_client_certificate_bound_access_tokens: True` on discovery AND protected-resource metadata; delete the divergence-33 comment), docs later
- Test: `tests/test_mtls.py`, `tests/test_wellknown.py`, `tests/test_introspection.py`

- [ ] **Step 1: Failing tests** — `test_cert_bound_token_carries_x5t_s256_cnf` (client_credentials via `tls_client_auth` → JWT `cnf == {"x5t#S256": <header>}`, response `token_type == "Bearer"`), `test_dpop_beats_mtls_when_both_present` (`cnf == {"jkt": ...}` only, `token_type == "DPoP"`), `test_device_grant_never_binds_x5t`, `test_introspection_of_cert_bound_token_requires_matching_thumbprint` (missing → inactive; mismatch → inactive; match → active with `cnf` echoed), `test_wave4_rfc8705_mtls_advertised_in_discovery` (both methods in all three lists, flag true), `test_protected_resource_metadata_advertises_mtls_binding`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): certificate-bound access tokens (cnf x5t#S256) with introspection enforcement and mTLS discovery"`

---

### Task 4: DPoP `ath` + resource-side DPoP at userinfo

**Files:**
- Modify: `src/oauth2_server/services/dpop.py` (`validate_dpop_proof(..., access_token: str | None = None)`; `DpopValidated.ath`), `src/oauth2_server/routes/wellknown.py::userinfo`
- Test: `tests/test_dpop.py` (unit `ath`), `tests/test_userinfo_dpop.py` (new), `tests/test_wellknown.py` (existing Bearer cases unchanged)

**Interfaces:** `validate_dpop_proof(..., access_token=None)`: when given, require `ath` (str) equal to base64url-no-pad(SHA-256(access_token as presented)) via `hmac.compare_digest`, else `DpopError("invalid_dpop_proof", "DPoP proof ath does not match the presented access token")`; when `None`, `ath` ignored. Userinfo: parse `Bearer`/`DPoP` schemes (ASCII case-insensitive); resolve the row; `cnf = decode_unverified_claims(token).get("cnf")`; if `cnf.jkt`: scheme must be `DPoP`, `DPoP` header present, proof valid for `htm=request.method`, `htu=<issuer>/oauth/userinfo`, `access_token=<presented>`, `validated.jkt == cnf.jkt`; any failure → 401 JSON `{"error":"invalid_token","error_description": <distinct>}` with `WWW-Authenticate: DPoP error="invalid_token"`; if `cnf["x5t#S256"]`: require matching `X-Client-Cert-Thumbprint` via `mtls_headers` (divergence 49) else the same 401 shape with `WWW-Authenticate: Bearer error="invalid_token"`; no `cnf` → unchanged. On success with `client.dpop_nonce_required` and a proof present, set `DPoP-Nonce` (Task 5 wires the issuer; leave a hook).

- [ ] **Step 1: Failing tests** — unit: `test_ath_required_when_access_token_given`, `test_ath_mismatch_rejected`, `test_ath_ignored_when_no_access_token`; route: `test_bound_token_as_bearer_rejected_with_dpop_challenge`, `test_bound_token_with_valid_dpop_proof_succeeds_get_and_post`, `test_bound_token_wrong_ath_rejected`, `test_bound_token_wrong_key_rejected`, `test_bound_token_missing_proof_rejected`, `test_unbound_token_bearer_unchanged`, `test_dpop_scheme_case_insensitive`, `test_cert_bound_token_requires_thumbprint_at_userinfo`, `test_userinfo_proof_replay_rejected`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): DPoP ath claim and resource-side DPoP/mTLS enforcement at userinfo"`

---

### Task 5: `dpop_jkt` code binding, `DPoP-Nonce` on success, public-client refresh proof

**Files:**
- Create: `src/oauth2_server/services/dpop_bindings.py` (`DpopCodeBindings`: `bind(code, jkt)`, `take(code) -> str | None`, TTL = `authorization_code_ttl_secs`, monotonic sweep, house style)
- Modify: `src/oauth2_server/routes/authorize.py` (`_PAR_MERGE_KEYS` += `dpop_jkt`; validate 43-char base64url → else redirect `invalid_request` "dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint"; `app.state.dpop_code_bindings.bind(code, jkt)` after `issue_code`), `src/oauth2_server/services/jar.py` (`JAR_OVERLAY_KEYS` += `dpop_jkt`), `src/oauth2_server/app.py`, `src/oauth2_server/routes/token.py` (auth-code branch: `expected = bindings.take(code)`; if expected and (`dpop_validated is None` or `jkt != expected`) → `invalid_grant` "authorization code is bound to a different DPoP key"; refresh branch: divergence 54 check before `revoke_token`; `DPoP-Nonce` on every 2xx when `client.dpop_nonce_required and dpop_validated`), `src/oauth2_server/routes/wellknown.py::userinfo` (nonce hook)
- Test: `tests/test_dpop_token.py` (update `test_refresh_carries_cnf_forward` to the confidential case; add the public case), `tests/test_dpop_jkt.py` (new), `tests/test_dpop_nonce.py`

- [ ] **Step 1: Failing tests** — `test_dpop_jkt_via_query_binds_code_and_matching_proof_redeems`, `test_dpop_jkt_via_par`, `test_dpop_jkt_via_jar_overlay`, `test_dpop_jkt_redemption_without_proof_invalid_grant`, `test_dpop_jkt_redemption_wrong_key_invalid_grant`, `test_dpop_jkt_malformed_rejected_via_redirect`, `test_dpop_jkt_binding_consumed_once`, `test_dpop_nonce_header_on_successful_token_response`, `test_dpop_nonce_absent_when_not_required`, `test_dpop_nonce_on_successful_userinfo`, `test_public_client_refresh_without_proof_invalid_grant`, `test_public_client_refresh_wrong_key_invalid_grant_and_family_survives`, `test_public_client_refresh_with_same_key_succeeds`, `test_confidential_refresh_carries_cnf_forward` (renamed existing).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): dpop_jkt code binding, DPoP-Nonce on success, fresh DPoP proof on public-client refresh"`

---

### Task 6: Nested `act` chains

**Files:**
- Modify: `src/oauth2_server/routes/token.py` (token-exchange branch), `src/oauth2_server/models.py` (`Claims.act` docstring)
- Test: `tests/test_token_exchange.py`

**Interfaces:** `prior = decode_unverified_claims(subject_token).get("act")` if dict; `act = {"sub": client.client_id}`; if `prior` and `prior.get("sub") != client.client_id`: `act["act"] = prior`; `check_depth(act, name="act", max_depth=10)` → `LimitError` → `oauth_error("invalid_request", ...)`. Response-body `act` (still conditional on `actor_token`) echoes the same object.

- [ ] **Step 1: Failing tests** — `test_two_hop_exchange_nests_act`, `test_three_hop_exchange_nests_twice`, `test_same_client_reexchange_collapses`, `test_over_depth_act_chain_rejected`, `test_response_body_act_matches_jwt_claim`, `test_opaque_mode_act_split_unchanged`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): nested RFC 8693 act delegation chains on token exchange"`

---

### Task 7: Social account linking by verified email

**Files:**
- Modify: `src/oauth2_server/services/social.py` (`SocialUserInfo.email_verified: bool`; Google/GitHub `True`, Microsoft/Azure `False`), `src/oauth2_server/config.py` (`social_link_by_verified_email: bool = False`), `src/oauth2_server/storage/base.py` + `sql.py` + `mongo.py` (`get_users_by_email(email) -> list[User]`, case-insensitive on the folded value), `src/oauth2_server/routes/social.py`, `README.md` "Security note: admin-by-email and social login"
- Test: `tests/test_social_login.py`, `tests/test_storage.py`, `tests/test_mongo_storage.py` (contract)

**Interfaces:** after the namespaced-username lookup misses: if `config.social_link_by_verified_email and userinfo.email_verified`: `rows = await storage.get_users_by_email(fold(email))`; link iff `len(rows) == 1` and `rows[0].role != "admin"` and `fold(rows[0].email) not in config.admin_emails`; else provision as today. `fold` = strip + casefold. `amr` stays `["fed"]`.

- [ ] **Step 1: Failing tests** — `test_linking_off_by_default_creates_new_account`, `test_google_verified_matching_email_links`, `test_github_verified_matching_email_links`, `test_microsoft_never_links`, `test_admin_role_candidate_refused`, `test_admin_emails_candidate_refused`, `test_ambiguous_email_refused`, `test_email_folding_case_and_whitespace`, `test_linked_login_amr_is_fed`, storage contract `test_get_users_by_email_case_insensitive` (SQL + Mongo-gated).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): opt-in social account linking by provider-verified email"`

---

### Task 8: Phase 4b residuals + docs + backlog

**Files:**
- Create: `src/oauth2_server/services/claims_request.py` (`select_id_token_claims(claims_request: str | None, *, scope: str) -> dict` → which of `acr`, `auth_time`, `email`, `preferred_username` to include and any `value`/`values` constraints)
- Modify: `src/oauth2_server/routes/authorize.py` + `services/rar.py` + `services/resource.py` (wire `services/limits.py` — divergence 57), `src/oauth2_server/routes/admin/clients.py` (divergence 58 via `is_valid_redirect_uri` on `redirect_uris`, `backchannel_logout_uri`, `frontchannel_logout_uri`, `post_logout_redirect_uris`), `src/oauth2_server/routes/token.py` (auth-code branch: pass the code's `claims_request` selection into `mint_id_token`; refresh branch: `_salvage_old_aud` + divergence 60), `src/oauth2_server/services/tokens.py` (`issue(..., audience: list[str] | None = None)` override), `src/oauth2_server/services/id_token.py` (accept `claims_selection`), `README.md` ("## Phase 4c" before "## Running": features, `OAUTH2_SOCIAL_LINK_BY_VERIFIED_EMAIL`, new single-process store `dpop_code_bindings`, the `self_signed_tls_client_auth` JWKS rule, proxy-header trust requirement), `docs/PHASE2-BACKLOG.md` (divergences 47–60 under "From Phase 4c"; strike closed entries in "Known DPoP/RAR gaps", "Known Phase 3c gaps" (social linking), "Remaining Phase 4b gaps", Phase 4a residuals; mark 4c done in the roadmap; note the Rust-side `V22` `dpop_jkt` column as the follow-up and `mtls_endpoint_aliases`/`claims` userinfo-half as remaining)
- Test: `tests/test_limits.py`, `tests/test_authorize.py`, `tests/test_rar.py`, `tests/test_resource_indicators.py`, `tests/test_admin_clients.py`, `tests/test_claims_request.py` (new), `tests/test_token_endpoint.py`

- [ ] **Step 1: Failing tests** — `test_oversized_claims_rejected_via_redirect`, `test_over_nested_claims_no_500`, `test_oversized_authorization_details_rejected`, `test_over_nested_authorization_details_at_token_endpoint_no_500`, `test_over_long_resource_invalid_target`, `test_admin_create_rejects_fragment_redirect_uri`, `test_admin_update_rejects_bad_logout_uri`, `test_admin_create_allows_empty_redirect_uris`, `test_claims_request_adds_acr_and_auth_time_to_id_token`, `test_claims_request_cannot_widen_scope` (email requested without `email` scope → absent), `test_claims_request_essential_unmet_still_succeeds`, `test_claims_request_value_mismatch_omits_claim`, `test_refresh_with_out_of_set_resource_invalid_target_and_token_survives`, `test_refresh_without_resource_keeps_old_aud`, `test_refresh_with_in_set_resource_narrows`, `test_refresh_opaque_mode_unchanged`.
- [ ] **Step 2: FAIL.** **Step 3: Implement + docs.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): input caps, admin redirect validation, claims-request id_token honoring, refresh aud subset; Phase 4c docs"`
