# Python OAuth2 Server Port — Phase 3c Implementation Plan (Observability, Rate Limiting, Events, Social Login)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the operational subsystems from the Rust server: Prometheus metrics + health/readiness, the three rate-limit mechanisms + resilience middleware, the in-process event bus with ingest, and social login (Google/Microsoft/GitHub/Azure + Okta/Auth0 stubs).

**Architecture:** A dedicated `prometheus_client.CollectorRegistry` on `app.state.metrics` with an ASGI timing middleware; a `RateLimiter` protocol (token-bucket in-memory backend) driving a global middleware + an invalid_client penalty bucket + resilience middleware; a pydantic event model set with an async fire-and-forget bus and plugins; and social-login routers with mocked-provider tests. Adds `prometheus-client`. Zero new migrations (social users reuse the `users` table).

**Tech Stack:** adds `prometheus-client>=0.20`. `httpx` (already a dependency) drives outbound provider calls.

## Global Constraints

- Schema owned by the Rust repo — zero new migrations. `bash scripts/gate.sh` green at every commit. TDD per task.
- Authoritative research: `.superpowers/sdd/research-events-observability.md`, `.superpowers/sdd/research-ratelimit-resilience.md`, `.superpowers/sdd/research-social-login.md`.
- Metric names match Rust exposition byte-for-byte (literal `oauth2_server_` prefix; the two families WITHOUT `_total`: `oauth2_server_oauth_authorization_codes_issued`, `oauth2_server_oauth_failed_authentications`).
- **Deliberate divergences from Rust (record in PHASE2-BACKLOG.md when landed):**
  22. `/metrics` content-type pinned to `text/plain; version=0.0.4` exactly (prometheus_client's default appends `; charset=utf-8` — strip it for parity).
  23. Login rate limiting is already env-tunable (from Phase 3a divergence 13/config) — Rust's is hardcoded. Kept.
  24. The parity-only metric families (`db_*`, `oauth_clients_total`, `oauth_active_tokens`, `rate_limit_*`, `errors_total`, `http_client_*`, `events_published_*`, `redis_client_*`) are registered + bootstrap-seeded but not wired (matching Rust's actual behavior — register-for-scrape-parity, note wiring as a follow-up). EXCEPTION: `rate_limit_rejected_total` and `rate_limit_remaining` ARE wired in this port (small behavioral improvement, since we're building the limiter fresh).
  25. Okta/Auth0 remain 503 stubs with the same body text (Rust parity); Azure remains a Microsoft-config alias.
  26. Social callback SETS `auth_time` in the session (Rust omits it, which breaks `max_age` for social sessions) — a correctness fix; document.
- **Rust gaps deliberately KEPT:** most parity-only metrics unwired (div 24); no email-based account linking (social usernames are `provider:id`); no id_token/nonce validation for social providers (identity from userinfo REST); csrf/pkce session keys reused (we improve: clear them post-callback — note as a divergence too if landed).

---

### Task 1: Prometheus metrics + /metrics, /health, /ready

**Files:**
- Create: `src/oauth2_server/services/metrics.py`, `src/oauth2_server/routes/system.py`
- Modify: `src/oauth2_server/app.py` (metrics middleware + state), `src/oauth2_server/routes/token.py`, `src/oauth2_server/routes/introspect.py`, `src/oauth2_server/routes/authorize.py`, `src/oauth2_server/routes/login.py`, `src/oauth2_server/routes/admin/tokens.py` (increment the wired counters)
- Test: `tests/test_metrics.py` (new)

**Interfaces:**
- `class Metrics:` — constructs a fresh `CollectorRegistry` and declares (literal names, from research §key_behaviors METRICS REGISTRY): `http_requests_total` (Counter, unlabeled), `http_request_duration_seconds` (Histogram, the explicit bucket list), `http_requests_by_class_total` (Counter, label `status_class`), `http_requests_total_by_route` (Counter, labels method/route/status), `http_request_duration_seconds_by_route` (Histogram, default buckets, same labels), `oauth_token_issued_total`, `oauth_token_revoked_total`, `oauth_authorization_codes_issued` (no `_total`), `oauth_failed_authentications` (no `_total`), `oauth_clients_total` (Gauge), `oauth_active_tokens` (Gauge), `db_queries_total`, `db_query_duration_seconds`, `rate_limit_rejected_total` (Counter, label `ip_prefix`), `rate_limit_remaining` (Histogram, buckets [0,1,5,10,25,50,75,100]), `circuit_breaker_state` (Gauge, label circuit), `circuit_breaker_trips_total` (Counter, label circuit), `back_pressure_rejected_total`, `concurrent_requests_in_flight` (Gauge), `bulkhead_rejected_total` (Counter, label bulkhead), `app_info` (Gauge, labels service/version/python_version, set 1), `errors_total` (Counter, label kind), `http_client_requests_total`/`http_client_request_duration_seconds`, `events_published_total`/`events_publish_duration_seconds`, `redis_client_operations_total`/`redis_client_operation_duration_seconds` — all `oauth2_server_`-prefixed. `bootstrap_seed()` touches the parity-only labeled families with a `bootstrap` label so cold scrapes carry TYPE/HELP + a series (Rust parity). `render() -> bytes` = `generate_latest(registry)`.
- ASGI middleware in `app.py`: before dispatch increment `http_requests_total`; after, compute `status_class` (2xx/3xx/4xx/5xx/other), resolve route template (`request.scope.get("route").path` if matched else `"unmatched"` — divergence from Rust's raw-path fallback, bounds cardinality; document), record the four HTTP families and `http_request_duration_seconds`. `/health`,`/ready`,`/metrics` are still counted (Rust parity).
- `routes/system.py`: `GET /metrics` → `Response(app.state.metrics.render(), media_type="text/plain; version=0.0.4")` (no charset — divergence 22); `GET /health` → 200 `{"status":"healthy","service":"oauth2_server","timestamp":<rfc3339>}`; `GET /ready` → `storage` healthcheck (add `SqlStorage.healthcheck()` = `SELECT 1`): 200 `{"status":"ready","checks":{"database":"ok"}}` or 503 plain text on failure.
- Wire the real counters at their Rust sites: `oauth_token_issued_total` on every grant that mints (auth-code/refresh/client-credentials/device/token-exchange), `oauth_token_revoked_total` on /oauth/revoke + admin revoke, `oauth_authorization_codes_issued` on authorize success, `oauth_failed_authentications` at login failures (bad password/unknown/disabled/rate-limited) + token-endpoint bad client auth/bad refresh.

- [ ] **Step 1: Failing tests** — port from `metrics_wiring.rs` + `metrics_paved_path_baseline.rs`: `test_required_metrics_are_registered` (cold scrape has the 12 required family names), `test_app_info_carries_version_label_and_is_one`, `test_metrics_content_type_is_exact` (`text/plain; version=0.0.4`, no charset), `test_http_status_class_counters` (3× 200 + 2× 404 → 2xx and 4xx series > 0, duration `+Inf` bucket > 0), `test_authorize_increments_codes_issued`, `test_login_failures_increment_failed_authentications` (bad password + unknown user), `test_revoke_increments_revoked_counter`, `test_token_issued_counter` (client_credentials → issued > 0), `test_health_and_ready_shapes` (ready 200 JSON; simulate a broken storage → 503).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS.** **Step 5: Commit** — `git commit -m "feat(python): Prometheus metrics, /metrics, /health, /ready"`

---

### Task 2: Rate limiting (global per-IP + invalid_client penalty + resilience)

**Files:**
- Create: `src/oauth2_server/services/limiter.py`, `src/oauth2_server/services/resilience.py`, `src/oauth2_server/middleware_ratelimit.py`
- Modify: `src/oauth2_server/config.py`, `src/oauth2_server/app.py`, `src/oauth2_server/routes/token.py` (invalid_client bucket)
- Test: `tests/test_ratelimit_global.py`, `tests/test_resilience.py` (new)

**Interfaces:**
- `services/limiter.py`: `@dataclass RateLimitResult(allowed, remaining, limit, reset_at, retry_after)`; `class TokenBucketLimiter(max_requests, window_secs)` — `check(key) -> RateLimitResult` (continuous refill `max_requests/window_secs` tokens/sec, one token/request, clamps like Rust; `time.monotonic`; dict-wide sweep of entries idle > 2×window — the ParStore precedent, no background task). Wraps the metric increments for `rate_limit_rejected_total{ip_prefix}` + `rate_limit_remaining` (divergence 24 exception).
- Config: `rate_limit_enabled: bool = False`, `rate_limit_max_requests: int = 100`, `rate_limit_window_secs: int = 60`, `rate_limit_invalid_client_max_requests: int = 5`, `trust_proxy_headers: bool = False`, plus resilience: `resilience_enabled: bool = False`, `resilience_max_concurrent: int = 1000`, `resilience_cb_failure_threshold: int = 5`, `resilience_cb_success_threshold: int = 2`, `resilience_cb_open_secs: int = 30`, `resilience_cb_half_open_max_probes: int = 3` (env `OAUTH2_RATE_LIMIT_*`/`OAUTH2_RESILIENCE_*`/`OAUTH2_SERVER_TRUST_PROXY_HEADERS`).
- Global middleware (`middleware_ratelimit.py`, mounted only when `rate_limit_enabled`, INSIDE DenylistGuard so denylisted IPs don't consume quota — verify order): key = XFF-first-when-`trust_proxy_headers` else `request.client.host`; exempt `/health`,`/ready`,`/metrics` (prefix); allowed → lowercase `x-ratelimit-*` headers; rejected → 429 `{"error":"too_many_requests","error_description":"Rate limit exceeded. Try again later.","retry_after":N}` + `Retry-After`/`X-RateLimit-*`; backend error → fail OPEN.
- invalid_client penalty (in `routes/token.py`, ON by default when `rate_limit_invalid_client_max_requests > 0`): a module-level/app.state `TokenBucketLimiter(invalid_client_max, window_secs)` keyed by `client_id`; AFTER the grant handler, if the error is `invalid_client`, consume a token — when exhausted replace the 401 with 429 `{"error":"too_many_requests","error_description":"Too many failed authentication attempts. Retry after {N}s.","error_uri":null}` (NO Retry-After header — Rust parity); successes and non-invalid_client errors never consume; fail open. NOTE: the current token flow authenticates the client up front and raises — restructure so an `invalid_client` outcome routes through the penalty check before returning.
- `services/resilience.py`: `CircuitBreaker` (consecutive-5xx, Closed/Open/HalfOpen, CAS-free asyncio-lock probe slots), `ConcurrencyLimiter` (asyncio.Semaphore, immediate 503), wired as one middleware (mounted when `resilience_enabled`): circuit open → 503 `{"error":"service_unavailable",...}` Retry-After open_secs; back-pressure full → 503 Retry-After 1; records failure on status ≥ 500 after the handler. Bulkheads: config-file-only in Rust → SKIP (document as a known gap). Update `circuit_breaker_state`/`trips_total`/`back_pressure_rejected_total`/`concurrent_requests_in_flight` metrics.

- [ ] **Step 1: Failing tests** — port the unit suites (`in_memory.rs` token-bucket: rejects after limit, independent keys, result.limit echoes, within-limit allowed; `circuit_breaker.rs`: opens after threshold, success resets, open→half-open after open_secs (monkeypatch monotonic), half-open probe cap, re-open on half-open failure; `back_pressure.rs`: N permits then reject, release frees slot, rejected count) as `services`-level tests; the `rfc9700_rate_limit.rs` HTTP tests (`invalid_client_returns_429_after_budget`, `no_limiter_returns_401` — set max to 0, `buckets_isolated_per_client_id`, `valid_requests_do_not_deplete_bucket`); plus the middleware tests Rust lacks (`global_limit_429_body_and_headers`, `exempt_paths_bypass`, `fail_open_on_backend_error`, `denylisted_ip_does_not_consume_quota`).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): rate limiting (global per-IP, invalid_client penalty) + resilience middleware"`

---

### Task 3: Event bus + ingest + recent-events fan-out

**Files:**
- Create: `src/oauth2_server/services/events_bus.py` (models + bus + plugins), `src/oauth2_server/routes/events.py`
- Modify: `src/oauth2_server/config.py`, `src/oauth2_server/app.py`, the token/authorize/client/refresh mint+revoke sites (emit events), `src/oauth2_server/services/events.py` (RecentEventsStore already exists — bridge plugin)
- Test: `tests/test_events_bus.py` (new)

**Interfaces:**
- Models (pydantic, serde-parity, exclude-none for `idempotency_key`/`traceparent`/`tracestate`, exclude-empty `attributes`): `AuthEvent(id=uuid4hex, event_type, timestamp, severity, user_id, client_id, metadata: dict[str,str], error)`; `EventEnvelope(event, idempotency_key, traceparent, tracestate, correlation_id=uuid4hex, producer="oauth2_server", produced_at, attributes)` with `effective_idempotency_key()`.
- `EventFilter` (allow_all / include_only / exclude); `EventPlugin` protocol (`emit`, `name`, `health_check`); `InMemoryEventLogger(max_events)`, `ConsoleEventLogger`, `RecentEventsPlugin(store)` (serializes the envelope into the existing `RecentEventsStore`).
- `EventBus` — `publish_best_effort(envelope)` = `asyncio.create_task` fan-out over plugins with per-plugin exception logging (hold task refs to avoid GC). `app.state.event_bus` when `events_enabled`.
- `IdempotencyStore(ttl=300, max_entries=100_000)` — in-process dict, TTL prune per call, full clear on overflow (Rust parity); `is_duplicate_and_record(key) -> bool`.
- Config: `events_enabled: bool = True`, `events_public_ingest: bool = False`, `events_ingest_bearer_token: str | None`, `events_backend: str = "in_memory"` (console/in_memory/both → plugin selection; unknown → in_memory + warn; RecentEventsPlugin always appended), `events_filter_mode`/`events_types`. (Redis/Kafka/Rabbit backends OUT of scope — document; in_memory/console only.)
- Emit the 9 real event types at the Rust sites: `token_created` (metadata scope + has_refresh_token), `token_revoked`, `authorization_code_created` (scope + redirect_uri), `authorization_code_validated`, `client_validated` (on client auth, success bool). (`token_validated`/`token_expired`/`authorization_code_expired`/`client_registered` where the corresponding path exists in the port; skip the 4 dead Rust types.)
- `POST /events/ingest`: bearer check via `hmac.compare_digest` unless `events_public_ingest`; auth-required-but-no-token-configured → 503 `{"error":"event_ingest_auth_not_configured"}`; missing/bad bearer → 401 + `WWW-Authenticate: Bearer` + `{"error":"invalid_token",...}`; events disabled → 503 `{"error":"eventing_disabled"}`; `Idempotency-Key` header overrides envelope key; duplicate → 202 `{"status":"duplicate",...}`; else push to RecentEventsStore + publish → 202 `{"status":"accepted",...}`. Always 202 on success.
- `GET /events/health` → `{"enabled":bool,"plugins":[{"name","healthy"}]}`.

- [ ] **Step 1: Failing tests** — port: `test_envelope_roundtrip`, `test_effective_idempotency_key_defaults_and_prefers_explicit`, `test_event_filter_allow_all/include_only/exclude`, `test_in_memory_logger_max_events` (cap 3, push 5 → holds newest 3), `test_bus_publishes_to_in_memory_logger` (publish + `await asyncio.sleep(0)` drains the task), `test_ingest_requires_bearer_by_default` (401 invalid_token), `test_ingest_public_can_be_enabled` (202 accepted), `test_ingest_duplicate_returns_202_duplicate`, `test_ingest_auth_not_configured_503`, `test_events_health_shape`, plus `test_token_created_event_emitted` (client_credentials → the in-memory plugin has a token_created envelope after `asyncio.sleep(0)`).
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): in-process event bus, ingest endpoint, recent-events fan-out"`

---

### Task 4: Social login

**Files:**
- Create: `src/oauth2_server/routes/social.py`, `src/oauth2_server/services/social.py` (provider definitions + userinfo mapping + per-provider circuit breakers)
- Modify: `src/oauth2_server/config.py`, `src/oauth2_server/app.py`
- Test: `tests/test_social_login.py` (new)

**Interfaces:**
- Config per provider (`OAUTH2_{GOOGLE,MICROSOFT,GITHUB,AZURE,OKTA,AUTH0}_CLIENT_ID/_CLIENT_SECRET/_REDIRECT_URI`, `OAUTH2_MICROSOFT_TENANT_ID`/`OAUTH2_AZURE_TENANT_ID` default `common`): a provider is enabled iff both id+secret are set (Rust parity — the `enabled` flag is decorative). Redirect default `http://localhost:8080/auth/callback/{provider}` — but prefer `config.issuer`-based default.
- `services/social.py`: provider registry with per-provider authorize/token/userinfo URLs + PKCE flag (Google only) + userinfo field mapping (Google `id`/`email`; Microsoft/Azure Graph `id`/`userPrincipalName`→email/`displayName`; GitHub `id`(int→str)/`email` with `/user/emails` primary fallback → "No email found" on miss, `User-Agent: python_oauth2_server`). Per-provider `CircuitBreaker` (5 fails/30s/single probe) around userinfo fetch only; `httpx.AsyncClient(timeout=10)`.
- `GET /auth/login/{google|microsoft|github|azure}`: provider not configured → 400 `{"error":"provider_not_configured",...}`; build the authorize URL (random state via `secrets.token_urlsafe`, Google also PKCE S256), store `csrf_token`/`pkce_verifier`/`provider` in session, 302 to the provider.
- `GET /auth/login/{okta|auth0}` → 503 plain body "Okta login not yet implemented" / "Auth0 login not yet implemented" (Rust parity stubs, divergence 25).
- `GET /auth/callback/{provider}`: `state` missing → 403 access_denied "CSRF state parameter is required"; mismatch → 403 "CSRF token mismatch"; session provider ≠ path → 400 "Provider mismatch"; unsupported provider → 400 "Unsupported provider"; exchange the code (Google requires pkce_verifier else 400 session_error); exchange failure → 400 token_exchange_failed; fetch userinfo (via the circuit breaker); find-or-create `User(username=f"{provider}:{provider_user_id}", password_hash=hash(uuid4), email, role="user")`; establish the session (user_id/authenticated/username/email/role AND `auth_time` — divergence 26); clear csrf/pkce/provider from the session (improvement — note); 302 to a safe `return_to` else `/profile`.
- `app.state.http_client` (from Phase 2 logout) reused, or a dedicated social client — pick one; tests swap it with `httpx.MockTransport`.

- [ ] **Step 1: Failing tests** (provider HTTP mocked via `httpx.MockTransport` on the social client) — `test_login_redirects_to_provider_with_state` (Google: 302, Location has state + code_challenge + S256), `test_login_unconfigured_provider_400`, `test_okta_auth0_stub_503`, `test_callback_missing_state_403`, `test_callback_state_mismatch_403`, `test_callback_provider_mismatch_400`, `test_google_full_flow_provisions_user` (mock token + userinfo → user `google:<id>` created, session established, 302 to /profile), `test_github_email_fallback` (primary-email second call), `test_existing_social_user_not_duplicated`, `test_callback_circuit_breaker_opens_after_failures` (5 userinfo 500s → provider_unavailable), `test_callback_safe_return_to_redirect` (open-redirect rejected). Reuse the `is_safe_redirect` unit coverage already in the repo.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): social login (Google/Microsoft/GitHub/Azure) with provider-mocked tests"`

---

### Task 5: Phase 3c acceptance

**Files:**
- Modify: `tests/test_rfc_compliance.py`, `docs/PHASE2-BACKLOG.md`, `README.md`

- [ ] **Step 1:** Compliance pins: `test_metrics_endpoint_exposes_wired_counters`, `test_invalid_client_penalty_returns_429`, `test_event_ingest_bearer_enforced`, `test_social_login_google_round_trip`.
- [ ] **Step 2:** `bash scripts/gate.sh` green.
- [ ] **Step 3:** Docs — README (new env vars: `OAUTH2_RATE_LIMIT_*`, `OAUTH2_RESILIENCE_*`, `OAUTH2_SERVER_TRUST_PROXY_HEADERS`, `OAUTH2_EVENTS_*`, `OAUTH2_{provider}_CLIENT_ID/SECRET`; feature list; single-process notes for the limiter/idempotency/recent-events stores; the parity-only unwired metrics list). PHASE2-BACKLOG — divergences 22–26 appended; known-gaps additions (Redis/Kafka/Rabbit event backends not ported; bulkheads config-file-only not ported; parity-only metrics unwired; RFC 8628 slow_down; no social email-linking / no id_token validation).
- [ ] **Step 4: Commit** — `git commit -m "test(python): Phase 3c compliance pins + docs"`

---

## Self-Review (completed)

- **Coverage vs research:** metrics registry + wired counters + health/ready → T1; the three rate-limit mechanisms + resilience → T2 (invalid_client ON-by-default, global OFF-by-default, resilience OFF-by-default, all matching Rust); event bus + ingest + recent-events + the 9 emitted types → T3; social providers (4 real + 2 stubs) + mapping + CSRF + breakers → T4; pins/docs → T5.
- **Kept-out-of-scope (documented):** Redis/Kafka/Rabbit event backends, bulkheads (config-file-only in Rust), OTel span export (structured logging with trace ids is a large separate effort — note as a Phase 3d/later candidate), most parity-only metric wiring.
- **Placeholder scan:** clean — exact metric names, error strings, and URLs sourced from the research digests; test names enumerated per task.
- **Type consistency:** `Metrics` (T1) consumed by T2's limiter/resilience increments; `RateLimitResult`/`TokenBucketLimiter` (T2) used by both the global middleware and the invalid_client bucket; `EventEnvelope`/`EventBus` (T3) names stable; `CircuitBreaker` appears in both T2 (HTTP resilience) and T4 (per-provider) — distinct classes, same name is fine as they live in different modules (resilience.py vs social.py); note in T4 to avoid import confusion.
- **Sequencing:** T1 first (metrics needed by T2's increments); T2, T3, T4 independent but all touch app.py middleware/state — run in order; T5 last.
