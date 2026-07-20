"""FastAPI application factory."""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from starlette.middleware.sessions import SessionMiddleware

from oauth2_server.bootstrap import seed_admin_user
from oauth2_server.config import Config
from oauth2_server.middleware import DenylistGuard
from oauth2_server.routes.admin import admin_router
from oauth2_server.routes.admin.guard import AdminAuthError
from oauth2_server.routes.authorize import router as authorize_router
from oauth2_server.routes.device import router as device_router
from oauth2_server.routes.introspect import router as introspect_router
from oauth2_server.routes.login import router as login_router
from oauth2_server.routes.logout import router as logout_router
from oauth2_server.routes.register import router as register_router
from oauth2_server.routes.token import router as token_router
from oauth2_server.routes.wellknown import router as wellknown_router
from oauth2_server.security import derive_session_key
from oauth2_server.services.events import RecentEventsStore
from oauth2_server.storage.base import Storage
from oauth2_server.storage.sql import SqlStorage

# Repo-root/migrations/sql, resolved relative to this package so it works
# both from a source checkout and an installed wheel with the same layout
# (src/oauth2_server/app.py -> parents[2] == repo root).
MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations" / "sql"

_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


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
        if request.url.path.startswith("/oauth"):
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

    # Registered last so it becomes the outermost middleware (Starlette runs
    # the most-recently-`add_middleware`d layer first) — every HTTP request,
    # for every route below, passes through DenylistGuard before session/CORS/
    # security-header handling or routing. See middleware.py for behavior.
    app.add_middleware(DenylistGuard)

    app.include_router(token_router, prefix="/oauth")
    app.include_router(introspect_router, prefix="/oauth")
    app.include_router(authorize_router, prefix="/oauth")
    app.include_router(device_router, prefix="/oauth")
    app.include_router(logout_router, prefix="/oauth")
    app.include_router(login_router, prefix="/auth")
    app.include_router(register_router, prefix="/connect")
    app.include_router(wellknown_router)
    app.include_router(admin_router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

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

    app = create_app(config, storage, lifespan=lifespan)
    return app
