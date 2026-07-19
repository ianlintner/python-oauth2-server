"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from starlette.middleware.sessions import SessionMiddleware

from oauth2_server.config import Config
from oauth2_server.routes.authorize import router as authorize_router
from oauth2_server.routes.introspect import router as introspect_router
from oauth2_server.routes.login import router as login_router
from oauth2_server.routes.token import router as token_router
from oauth2_server.routes.wellknown import router as wellknown_router
from oauth2_server.storage.base import Storage

_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


def create_app(config: Config, storage: Storage) -> FastAPI:
    app = FastAPI(default_response_class=ORJSONResponse)
    app.state.config = config
    app.state.storage = storage

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
        secret_key=config.jwt_secret,
        session_cookie="oauth2_session",
        same_site="lax",
        https_only=not config.allow_insecure_defaults,
    )

    app.include_router(token_router, prefix="/oauth")
    app.include_router(introspect_router, prefix="/oauth")
    app.include_router(authorize_router, prefix="/oauth")
    app.include_router(login_router, prefix="/auth")
    app.include_router(wellknown_router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
