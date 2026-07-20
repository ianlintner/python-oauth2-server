# Phase 2 Backlog — from Phase 1 reviews

Accumulated findings from per-task and final whole-branch reviews (Phase 1, branch port/phase-1).
None are merge-blocking; ordered by priority.

## Important (top of Phase 2)
1. **Refresh-token expiry** — refresh grant never expires tokens (`routes/token.py` refresh branch);
   introspection uses the access-token `expires_at`, so a refresh token introspects inactive after 1h
   yet still redeems. Add a refresh TTL (config `refresh_token_ttl_secs` exists, unused for expiry).
2. **Multi-worker migration race** — every worker runs `run_migrations` at startup; fresh-DB concurrent
   DDL can race. Add `pg_advisory_lock` or migrate-once entrypoint. (Rust-owns-schema deployments unaffected.)

## Minor
3. Scope policy inconsistency: client_credentials intersects requested scope; other grants reject with
   `invalid_scope`. Pick one policy.
4. `prompt=none` + expired `max_age` (or `prompt="none login"`) falls through to the login UI instead of
   `error=login_required` (OIDC Core §3.1.2.6).
5. Session cookie signing key is `jwt_secret` verbatim — HKDF-derive a separate key.
6. `storage/sql.py`: `expire_device_authorization` writes ISO string (breaks on asyncpg); it and
   `set_token_family` are currently dead code — fix or drop.
7. Argon2 verify runs on the event loop in login — wrap in `anyio.to_thread`.
8. Grant-type allow-list only enforced for client_credentials; extend to auth-code/refresh/device + authorize.
9. Migrate `@app.on_event("startup")` → lifespan; replace deprecated ORJSONResponse default-class pattern.
10. `decode_access_token` doesn't validate the JOSE `typ` header (RFC 9068 hardening).
11. No ID-token re-mint on refresh rotation when `openid` scope present.
12. Rate limiting on /oauth/device/verify and token endpoints (Phase 3 per plan).

## Accepted divergences (documented, keep)
- DCR rejection error is `invalid_client_metadata` (RFC 7591 §3.2.2) where the Rust admin handler uses
  `invalid_request` — noted in tests/test_rfc_compliance.py docstring.

## In flight elsewhere
- return_to session replay hardening — chip session task_e2854233 (working-tree changes on this branch).
