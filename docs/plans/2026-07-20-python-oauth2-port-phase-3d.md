# Python OAuth2 Server Port — Phase 3d Implementation Plan (MongoDB Backend)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a MongoDB `Storage` backend that satisfies the existing `Storage` protocol byte-for-byte with the SQL backend, selected by a `mongodb://` scheme on `OAUTH2_DATABASE_URL` — the "same data model, second engine" proof, fixing the Rust backend's documented stub gaps rather than copying them.

**Architecture:** A `MongoStorage` class (motor async driver) mirroring `SqlStorage`'s protocol, persisting the five core pydantic models as documents with the SAME field names and the SAME JSON-array-as-string + RFC3339-string-datetime conventions the SQL rows use. A storage factory (`create_storage(config)`) dispatches on the URL scheme. Documents store `model_dump(mode="json", exclude_none=True)` so `refresh_token`/`token_family` are omitted when None (unique-index parity). Contract tests run against a real mongod via testcontainers, gated by an env var (mirroring Rust CI), with a mongomock-motor fast path where fidelity allows.

**Tech Stack:** adds `motor>=3.5` (async pymongo) as an optional dependency group `[mongo]`; test deps add `testcontainers[mongodb]` and `mongomock-motor` in the dev group.

## Global Constraints

- Schema is owned by the Rust repo for SQL; Mongo has no migrations — `init()` creates indexes idempotently. Zero SQL migrations.
- The Mongo documents must be serde-compatible with the Rust Mongo backend (same field names, JSON-array-strings, RFC3339-string datetimes, omitted-when-None fields) so both servers can share one Mongo database — the same cross-server parity guarantee Phase 1 established for Postgres.
- `bash scripts/gate.sh` green at every commit (the default suite runs on SQLite — Mongo contract tests self-skip unless `RUN_TESTCONTAINERS=1`, matching Rust). TDD per task.
- Authoritative research: `.superpowers/sdd/research-mongo-backend.md` (exact collection/document shapes, index list, error mapping, the stub gaps).
- **Deliberate divergences from Rust (record in PHASE2-BACKLOG.md when landed):**
  28. `revoke_token_family` and `revoke_tokens_by_user_id` ARE implemented on Mongo (`update_many` on `token_family` / `user_id`, returning `modified_count`) — Rust leaves them as no-op trait defaults, silently breaking refresh-replay cascade revocation and OIDC-logout revocation on Mongo. This port must not copy that gap.
  29. Denylist + audit-log storage methods ARE implemented on Mongo (collections `denylist`, `audit_log`), and `supports_denylist()`/`supports_audit_log()` return True — Rust stubs them as no-ops returning false. (This keeps the admin denylist/audit features working on Mongo.)
  30. Single-claim atomicity: `mark_authorization_code_used`/`mark_device_authorization_used` use `find_one_and_update({_, used: false}, {$set: {used: true}})` returning a rowcount-equivalent (1 if claimed, 0 if already used) — Rust's Mongo path is a non-atomic `update_one` with a double-spend race. This matches the SQL backend's atomic single-claim guard (the whole point of the Phase 1 `... AND used = false` design).
  31. `mongodb+srv://` is SUPPORTED (motor's DNS resolver has no hickory-proto constraint) — Rust hard-rejects it. Both `mongodb://` and `mongodb+srv://` select the Mongo backend.
- **Rust behaviors KEPT:** full-collection-scan list/page with app-side sort/filter/paging (Cosmos compat); `list_all_tokens` truncates to 200; datetimes as RFC3339 strings with tolerant parsing of legacy BSON dates; duplicate-key → `invalid_request` "duplicate key"; app-level `id`/natural-key lookups (never Mongo `_id`).

## Rust → Python map

| Rust | Python |
|---|---|
| `oauth2-storage-mongo/src/lib.rs` | `src/oauth2_server/storage/mongo.py` |
| `oauth2-storage-factory::create_storage` | `src/oauth2_server/storage/factory.py` |
| `chrono_serde.rs` tolerant datetime | model validators in `models.py` (tolerant datetime parse) |

---

### Task 1: Storage factory + backend dispatch

**Files:**
- Create: `src/oauth2_server/storage/factory.py`
- Modify: `src/oauth2_server/app.py` (use the factory), `pyproject.toml` (`[project.optional-dependencies] mongo = ["motor>=3.5"]`; dev group adds `mongomock-motor`, `testcontainers`)
- Test: `tests/test_storage_factory.py` (new)

**Interfaces:**
- `create_storage(config: Config) -> Storage` — dispatches on `config.database_url`: `mongodb://` or `mongodb+srv://` → `MongoStorage(url)` (import lazily; if motor isn't installed → `RuntimeError` "MongoDB backend requested but 'motor' is not installed (pip install oauth2-server[mongo])"); anything else → `SqlStorage(url, MIGRATIONS_DIR, pool_size=config.max_connections)`.
- `app.py`'s `build()` calls `create_storage(config)` instead of constructing `SqlStorage` directly. `create_app` still takes an explicit `storage` (test path unchanged).

- [ ] **Step 1: Failing tests** — `test_factory_returns_sqlstorage_for_sqlite`, `test_factory_returns_sqlstorage_for_postgres_url`, `test_factory_dispatches_mongo_scheme` (monkeypatch/import-guard: assert it attempts `MongoStorage` for `mongodb://localhost/oauth2` — if motor is installed, gets a MongoStorage instance without connecting; if not, the RuntimeError message contains "motor"), `test_factory_mongo_srv_scheme_also_dispatches`.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: Full suite + ruff PASS** (SQLite path unchanged). **Step 5: Commit** — `git commit -m "feat(python): storage factory dispatching on database_url scheme"`

---

### Task 2: Model datetime tolerance + Mongo document round-trip

**Files:**
- Modify: `src/oauth2_server/models.py` (tolerant datetime validators)
- Test: `tests/test_mongo_serde.py` (new — pure unit, no mongod)

**Interfaces:**
- Every model datetime field accepts, on validation: an aware `datetime` (BSON date from the driver), an RFC3339/ISO string, and the extended-JSON forms `{"$date": <ms>}` and `{"$date": {"$numberLong": "<ms>"}}` (port of `chrono_serde`). Add a `field_validator(..., mode="before")` (shared helper `_coerce_datetime`) on the datetime fields of `Client`, `User`, `Token`, `AuthorizationCode`, `DeviceAuthorization`, `DenylistEntry`, `AuditLogEntry`. Naive datetimes are assumed UTC.
- Confirm `model_dump(mode="json", exclude_none=True)` omits `refresh_token`/`token_family` (Token) and the optional auth-code fields when None (they already default None — verify the dump omits, not nulls).

- [ ] **Step 1: Failing tests** — port the Rust serde tests by name: `test_token_omits_refresh_token_when_none` (dump has no `refresh_token` key), `test_token_includes_refresh_token_when_some`, `test_token_omits_token_family_when_none`, and one tolerant-parse test per model: `test_user_parses_bson_date_updated_at` (build a dict with `created_at` as ISO string and `updated_at` as an aware datetime → both round-trip to the same instant), `test_*_parses_extjson_v1_and_v2` (`{"$date": 1714219200000}` and `{"$date": {"$numberLong": "1714219200000"}}` → 1714219200000 ms), for Client/Token/AuthorizationCode/DeviceAuthorization. Client minimal-doc test: `redirect_uris="[]"`, `grant_types="[]"` (JSON strings) parse.
- [ ] **Step 2: FAIL.** **Step 3: Implement.** **Step 4: PASS.** **Step 5: Commit** — `git commit -m "feat(python): tolerant datetime parsing for Mongo document round-trip"`

---

### Task 3: MongoStorage — core CRUD (clients, users, tokens, codes, devices)

**Files:**
- Create: `src/oauth2_server/storage/mongo.py`
- Test: `tests/test_mongo_storage.py` (new — testcontainers-gated)

**Interfaces (motor; document = `model.model_dump(mode="json", exclude_none=True)`; parse back via `Model(**doc)` dropping `_id`):**
- `MongoStorage(url: str)`: parse the DB name from the URL path (default `"oauth2"`); bind collections `clients/users/tokens/authorization_codes/device_authorizations/denylist/audit_log`; `motor.motor_asyncio.AsyncIOMotorClient(url)`.
- `init()`: `command({"ping": 1})`; `_ensure_indexes()` (the exact index list from research §key_behaviors: `clients.client_id` unique, `users.username` unique, `users.email`, `tokens.access_token` unique, `tokens.refresh_token` NON-unique, `authorization_codes.code` unique, `device_authorizations.device_code` unique, `device_authorizations.user_code` unique, `denylist` unique compound `(kind, value)`, created_at desc indexes); `_normalize_legacy_timestamps()` (find `{field: {$type: 9}}` BSON-date docs and rewrite as ISO strings — idempotent).
- `healthcheck()`: `command({"ping": 1})`.
- All CRUD per research §storage_methods: client save/get/update(`replace_one`)/delete/set_enabled/set_secret; user save/get_by_username/get_by_id/update(`$set` explicit fields)/delete/setters; token save/get_by_access/get_by_refresh/get_by_id/revoke(`update_many` `$or`)/revoke_tokens_by_client_id (`update_many {client_id, revoked:false}` → `modified_count`); auth-code save/get/mark_used (**atomic `find_one_and_update`** — divergence 30, return 1/0); device save/get_by_device_code/get_by_user_code/approve/deny/mark_used(**atomic**)/expire (writes `(now-1s).isoformat()` string).
- Duplicate key: catch `pymongo.errors.DuplicateKeyError` → raise the storage layer's `invalid_request`/"duplicate key" equivalent (check how `SqlStorage` signals this — match it so routes behave identically).

- [ ] **Step 1: Failing tests** — `tests/test_mongo_storage.py` with a module-level fixture that starts a mongod via `testcontainers` and self-skips (`pytest.skip`) unless `RUN_TESTCONTAINERS=1` (also skip if motor/testcontainers unimportable). Port the Rust `run_storage_contract` smoke: save/get client; duplicate client_id errors; save/get user; save token with refresh → fetch by access, revoked False → revoke → refetch revoked True; two tokens with refresh_token=None both save (unique-index parity); duplicate access_token errors; save auth-code used False → mark_used → used True; **plus** the atomic-claim test (`mark_authorization_code_used` twice → first returns 1, second returns 0) and the divergence-28 tests (`revoke_token_family` cascades, `revoke_tokens_by_user_id` returns the count). Reuse the assertions from `tests/test_storage.py`/`tests/test_admin_storage.py` where they apply.
- [ ] **Step 2: Run — with RUN_TESTCONTAINERS=1 they FAIL (or ERROR importing MongoStorage); without it they SKIP.** **Step 3: Implement.** **Step 4: Run the mongo suite with RUN_TESTCONTAINERS=1 → PASS; run the full default suite (mongo tests skip) → green + ruff.** **Step 5: Commit** — `git commit -m "feat(python): MongoStorage core CRUD with atomic single-claim"`

---

### Task 4: MongoStorage — list/page, denylist, audit, capability flags

**Files:**
- Modify: `src/oauth2_server/storage/mongo.py`
- Test: `tests/test_mongo_storage.py` (extend), `tests/test_mongo_admin.py` (new — testcontainers-gated)

**Interfaces:**
- `list_all_clients/users/tokens/device_authorizations`: `find({})` full scan → parse → app-side sort by `created_at` desc; `list_all_tokens` truncates to 200 (Rust parity).
- `list_clients_page/users_page/tokens_page/device_authorizations_page`: full scan → app-side sort (whitelisted column, asc/desc), status filter (tokens: active/revoked/expired via the model's validity check), case-insensitive substring search (clients name|client_id, users username|email, tokens client_id|user_id), then `(items[offset:offset+limit], total)` — same `(items, total)` shape and `ListQuery` semantics as `SqlStorage` (default limit 25, cap 200).
- Denylist (divergence 29): `add_denylist_entry` (`replace_one({kind,value}, doc, upsert=True)` keeping the original `id` on conflict — match the SQL upsert semantics), `remove_denylist_entry(id)`, `list_denylist(q)` (full scan, app-side page; expired rows included), `find_denylist_entry(kind, value)` (returns only active — `is_active()` filter in Python). Audit: `write_audit_log`, `list_audit_log(q)` (created_at desc). `supports_denylist()`/`supports_audit_log()` → True.

- [ ] **Step 1: Failing tests** (testcontainers-gated) — port the paging/denylist/audit contract from `tests/test_admin_storage.py` against MongoStorage: pagination envelope (15 clients, slices), search filter, token status filter, denylist add/find/remove/upsert-keeps-id/expired-skipped, audit newest-first + limit/offset, `revoke_tokens_by_client_id` count/idempotency. `supports_*` return True.
- [ ] **Step 2: FAIL (with env var) / SKIP (without).** **Step 3: Implement.** **Step 4: mongo suite PASS with env var; default suite green.** **Step 5: Commit** — `git commit -m "feat(python): MongoStorage list/page, denylist, audit, capability flags"`

---

### Task 5: Cross-backend parity smoke + CI job + acceptance

**Files:**
- Create: `scripts/mongo_parity_smoke.sh`, `.github/workflows` mongo job (or extend the existing gate workflow with a `db-tests` job)
- Modify: `README.md`, `docs/PHASE2-BACKLOG.md`, `tests/test_rfc_compliance.py` (a backend-parametrized pin if feasible, else a mongo-gated compliance smoke)
- Test: the gated mongo suite + a full end-to-end flow against Mongo

**Interfaces:**
- `scripts/mongo_parity_smoke.sh`: `docker run` a mongod (or reuse testcontainers), start the Python server with `OAUTH2_DATABASE_URL=mongodb://localhost:27017/oauth2_smoke`, run a client_credentials + authorization_code + refresh + introspect + revoke sequence over HTTP, assert the refresh-replay family cascade actually revokes (proving divergence 28), and a DPoP-bound token + RAR flow persist/round-trip. Record commands + output in README.
- A CI `db-tests` job: `RUN_TESTCONTAINERS=1 uv run pytest tests/test_mongo_storage.py tests/test_mongo_admin.py` with a mongo service container (or testcontainers-in-CI). The default `gate` job stays SQLite-only and fast.
- `tests/test_rfc_compliance.py`: add `test_mongo_backend_storage_contract` (gated — a thin end-to-end that builds an app on a MongoStorage and runs one full auth-code+refresh flow, skipped without the env var).

- [ ] **Step 1:** Write the gated end-to-end app-level test (build `create_app(config, MongoStorage(url))` against a testcontainers mongod, run a full flow via httpx ASGI). FAIL without impl gaps / SKIP without env.
- [ ] **Step 2:** `bash scripts/gate.sh` green (SQLite); `RUN_TESTCONTAINERS=1 uv run pytest tests/test_mongo_*.py` green.
- [ ] **Step 3:** CI job added; docs: README Mongo section (URL scheme selection, `[mongo]` extra, `+srv` supported, single-database cross-server parity, the app-side-scan/no-TTL caveats); PHASE2-BACKLOG divergences 28–31 + kept-behaviors + known gaps (no TTL indexes → expired rows accumulate; full-scan lists are O(collection); mongomock-motor fidelity caveats).
- [ ] **Step 4: Commit** — `git commit -m "test(python): Mongo backend parity smoke, CI db-tests job, Phase 3d docs"`

---

## Self-Review (completed)

- **Coverage vs research:** factory dispatch → T1; tolerant datetime + omit-None serde → T2; core CRUD + atomic claim + the two un-stubbed revoke methods → T3; list/page + denylist + audit + capability flags → T4; parity smoke + CI + docs → T5. Every Rust stub gap (revoke_token_family, revoke_tokens_by_user_id, denylist, audit) is FIXED (divergences 28–29), not copied; non-atomic claim is HARDENED (divergence 30); +srv SUPPORTED (divergence 31).
- **Placeholder scan:** clean — collection/field names, index list, and error mapping sourced from the research digest; test names enumerated.
- **Type consistency:** `MongoStorage` implements the exact `Storage` protocol from `storage/base.py` (methods listed there — verified against the current protocol: init/healthcheck/client×8/user×10/token×10/authcode×3/device×8/denylist×4/audit×2); `(items, total)` page shape and `ListQuery` reused; `create_storage(config) -> Storage` returns either backend interchangeably.
- **Gating discipline:** the default gate stays SQLite-only and fast; all mongod-dependent tests self-skip without `RUN_TESTCONTAINERS=1`, so `scripts/gate.sh` never requires Docker — matching the Rust CI split. mongomock-motor is a dev convenience where its fidelity is verified (ping, unique-index E11000, `$type` filters are the risk areas — the plan uses a real mongod for the contract suite to be safe).
- **Scope:** this is the last planned phase; after 3d merges, the port covers Phase 1 (core), 2 (admin/logout/PAR/keys), 3a (hardening), 3b (DPoP/RAR/exchange), 3c (observability/ratelimit/events/social), 3d (Mongo) — the full Rust feature set minus the documented deliberately-out-of-scope items (Redis/Kafka/Rabbit event backends, bulkheads, OTel export, JAR).
