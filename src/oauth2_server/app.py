"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from oauth2_server.config import Config
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

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
