"""FastAPI application factory."""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path
from typing import Any, Callable

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from starlette.middleware.sessions import SessionMiddleware

from oauth2_server.bootstrap import seed_admin_user
from oauth2_server.config import Config
from oauth2_server.keys import seed_keyset
from oauth2_server.middleware import _SECURITY_HEADERS, DenylistGuard, MetricsMiddleware
from oauth2_server.routes.admin import admin_router
from oauth2_server.routes.admin.guard import AdminAuthError
from oauth2_server.routes.authorize import router as authorize_router
from oauth2_server.routes.device import router as device_router
from oauth2_server.routes.introspect import router as introspect_router
from oauth2_server.routes.login import router as login_router
from oauth2_server.routes.logout import router as logout_router
from oauth2_server.routes.par import router as par_router
from oauth2_server.routes.register import router as register_router
from oauth2_server.routes.system import router as system_router
from oauth2_server.routes.token import router as token_router
from oauth2_server.routes.wellknown import router as wellknown_router
from oauth2_server.security import derive_session_key
from oauth2_server.services.dpop import DpopReplayStore
from oauth2_server.services.dpop_nonce import DpopNonceIssuer, decode_dpop_nonce_secret
from oauth2_server.services.events import RecentEventsStore
from oauth2_server.services.metrics import Metrics
from oauth2_server.services.par import ParStore
from oauth2_server.services.ratelimit import FixedWindowLimiter
from oauth2_server.storage.base import Storage
from oauth2_server.storage.sql import SqlStorage

# Repo-root/migrations/sql, resolved relative to this package so it works
# both from a source checkout and an installed wheel with the same layout
# (src/oauth2_server/app.py -> parents[2] == repo root).
MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations" / "sql"


def create_app(
    config: Config,
    storage: Storage,
    *,
    lifespan: Callable[[FastAPI], AbstractAsyncContextManager[Any]] | None = None,
) -> FastAPI:
    app = FastAPI(default_response_class=ORJSONResponse, lifespan=lifespan)
    app.state.config = config
    app.state.storage = storage
    app.state.events = RecentEventsStore()
    # Dedicated CollectorRegistry per app instance (services/metrics.py) —
    # never the prometheus_client global default — so tests building
    # multiple apps never collide re-registering the same family names.
    # bootstrap_seed() touches the parity-only labeled families so a cold
    # scrape (before any traffic) still carries their TYPE/HELP + a
    # zero-valued series (Rust parity, research-events-observability.md).
    app.state.metrics = Metrics()
    app.state.metrics.bootstrap_seed()
    app.state.par_store = ParStore()
    app.state.login_limiter = FixedWindowLimiter(
        config.login_rate_limit_attempts, config.login_rate_limit_window_secs
    )
    app.state.keyset = seed_keyset(config)
    # RFC 9449 DPoP: a single shared replay store + nonce issuer per app
    # instance, read directly by routes/token.py (and later introspect).
    # Unlike the Rust `Option<web::Data<...>>` handlers (research-dpop.md
    # gotcha: silently falls back to a fresh throwaway store per request when
    # app_data is missing, disabling replay protection with no error), this
    # state is mandatory — there is no fallback path, so a missing
    # `app.state.dpop_replay`/`dpop_nonce_issuer` is a hard `AttributeError`
    # rather than a silent security downgrade (divergence 14).
    app.state.dpop_replay = DpopReplayStore()
    app.state.dpop_nonce_issuer = DpopNonceIssuer(
        decode_dpop_nonce_secret(config.dpop_nonce_secret), config.dpop_nonce_lifetime_secs
    )
    # Shared client for outbound OIDC back-channel logout POSTs
    # (routes/logout.py). Tests swap this for an `httpx.MockTransport`-backed
    # client to capture/assert the dispatched request without real network
    # I/O. Not closed here — `create_app` has no lifespan of its own in the
    # test path, so it's `build()`'s lifespan that owns closing it.
    app.state.http_client = httpx.AsyncClient(timeout=10)

    # FastAPI dependencies (e.g. require_admin, see routes/admin/guard.py)
    # can't short-circuit a request by returning a Response directly, so the
    # guard raises AdminAuthError carrying a prebuilt Response; this handler
    # unwraps it back into the real HTTP response.
    @app.exception_handler(AdminAuthError)
    async def _admin_auth_error_handler(request: Request, exc: AdminAuthError):
        return exc.response

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/oauth") or path.startswith("/admin/api"):
            response.headers.update(_SECURITY_HEADERS)
        return response

    if config.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.allowed_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.add_middleware(
        SessionMiddleware,
        secret_key=derive_session_key(config.jwt_secret),
        session_cookie="oauth2_session",
        same_site="lax",
        https_only=not config.allow_insecure_defaults,
    )

    # Registered after security_headers/CORS/Session so it becomes the
    # outermost of those three (Starlette runs the most-recently-
    # `add_middleware`d layer first) — every HTTP request, for every route
    # below, passes through DenylistGuard before session/CORS/security-header
    # handling or routing. See middleware.py for behavior.
    app.add_middleware(DenylistGuard)

    # Registered LAST of all — becomes the true outermost layer, wrapping
    # even DenylistGuard, so it counts every request/response that reaches
    # this ASGI app, including ones DenylistGuard short-circuits and scrapes
    # of /metrics itself (Rust MetricsMiddleware parity; see
    # middleware.py's MetricsMiddleware docstring for the full ordering
    # rationale).
    app.add_middleware(MetricsMiddleware)

    app.include_router(token_router, prefix="/oauth")
    app.include_router(introspect_router, prefix="/oauth")
    app.include_router(authorize_router, prefix="/oauth")
    app.include_router(device_router, prefix="/oauth")
    app.include_router(logout_router, prefix="/oauth")
    app.include_router(par_router, prefix="/oauth")
    app.include_router(login_router, prefix="/auth")
    app.include_router(register_router, prefix="/connect")
    app.include_router(wellknown_router)
    app.include_router(admin_router)
    app.include_router(system_router)

    return app


def build() -> FastAPI:
    """Factory entry point for `uvicorn --factory` / `granian --interface asgi`.

    Builds `Config` from `OAUTH2_*` env vars, constructs `SqlStorage`, and runs
    migrations on startup via a lifespan handler (required so each worker
    process — spawned independently by uvicorn's `workers=` option — applies
    migrations, though the runner is idempotent/backfill-only after the first).
    """
    config = Config()
    config.validate_for_production()
    storage = SqlStorage(config.database_url, MIGRATIONS_DIR, pool_size=config.max_connections)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await storage.init()
        await seed_admin_user(storage, config)
        yield
        await app.state.http_client.aclose()

    app = create_app(config, storage, lifespan=lifespan)
    return app
