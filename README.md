# python-oauth2-server

Python port of [rust-oauth2-server](https://github.com/ianlintner/rust-oauth2-server) — an OAuth2/OIDC authorization server.

- Same DB schema: `migrations/sql/` is vendored verbatim from the Rust repo (source of truth); both servers can share one Postgres.
- RFC compliance tests ported 1:1 from the Rust suite act as the spec.
- Stack: FastAPI, uvicorn+uvloop, Pydantic v2, SQLAlchemy async (raw SQL), PyJWT, argon2-cffi.

Plan: `docs/plans/2026-07-19-python-oauth2-port.md`
