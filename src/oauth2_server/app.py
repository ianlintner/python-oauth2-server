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
from oauth2_server.middleware_ratelimit import RateLimitMiddleware, ResilienceMiddleware
from oauth2_server.routes.admin import admin_router
from oauth2_server.routes.admin.guard import AdminAuthError
from oauth2_server.routes.authorize import router as authorize_router
from oauth2_server.routes.device import router as device_router
from oauth2_server.routes.events import router as events_router
from oauth2_server.routes.introspect import router as introspect_router
from oauth2_server.routes.login import router as login_router
from oauth2_server.routes.logout import router as logout_router
from oauth2_server.routes.par import router as par_router
from oauth2_server.routes.register import router as register_router
from oauth2_server.routes.social import router as social_router
from oauth2_server.routes.system import router as system_router
from oauth2_server.routes.token import router as token_router
from oauth2_server.routes.wellknown import router as wellknown_router
from oauth2_server.security import derive_session_key
from oauth2_server.services.dpop import DpopReplayStore
from oauth2_server.services.dpop_nonce import DpopNonceIssuer, decode_dpop_nonce_secret
from oauth2_server.services.events import RecentEventsStore
from oauth2_server.services.events_bus import IdempotencyStore, build_event_bus
from oauth2_server.services.limiter import TokenBucketLimiter
from oauth2_server.services.metrics import Metrics
from oauth2_server.services.par import ParStore
from oauth2_server.services.ratelimit import FixedWindowLimiter
from oauth2_server.services.resilience import CircuitBreaker, ConcurrencyLimiter
from oauth2_server.services.social import OAUTH_PROVIDERS, SocialCircuitBreaker
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
    # Rate limiting (services/limiter.py) + resilience (services/
    # resilience.py) state — always constructed (cheap, no background
    # tasks/threads) even when the corresponding middleware below isn't
    # mounted, so e.g. tests can manipulate `app.state.circuit_breaker`
    # directly without needing `resilience_enabled=True`. The global per-IP
    # limiter and the two resilience objects are read by
    # `middleware_ratelimit.py`'s `RateLimitMiddleware`/
    # `ResilienceMiddleware`; `invalid_client_limiter` is read directly by
    # `routes/token.py` (RFC 9700 §2.5 penalty bucket, independent of
    # `rate_limit_enabled` — active by default, `None` only when explicitly
    # disabled via `rate_limit_invalid_client_max_requests=0`).
    app.state.rate_limiter = TokenBucketLimiter(
        config.rate_limit_max_requests, config.rate_limit_window_secs
    )
    app.state.invalid_client_limiter = (
        TokenBucketLimiter(
            config.rate_limit_invalid_client_max_requests, config.rate_limit_window_secs
        )
        if config.rate_limit_invalid_client_max_requests > 0
        else None
    )
    app.state.circuit_breaker = CircuitBreaker(
        config.resilience_cb_failure_threshold,
        config.resilience_cb_success_threshold,
        config.resilience_cb_open_secs,
        config.resilience_cb_half_open_max_probes,
    )
    app.state.concurrency_limiter = ConcurrencyLimiter(config.resilience_max_concurrent)
    # One SocialCircuitBreaker per social-login OAuth provider (services/
    # social.py), guarding only each provider's userinfo fetch. Per-app-
    # instance (not module-global) so tests never leak breaker state across
    # apps/test cases, matching the pattern above.
    app.state.social_breakers = {provider: SocialCircuitBreaker() for provider in OAUTH_PROVIDERS}
    # Event bus (services/events_bus.py) — `None` when `events_enabled` is
    # False, matching Rust's "no EventActor registered" state (`app.state.
    # event_bus is None` is what `routes/events.py` and every emit call site
    # check to no-op). `event_idempotency` is cheap to construct
    # unconditionally (no background task) even though it's only ever read
    # from `POST /events/ingest`, which itself short-circuits before
    # touching it whenever the bus is absent.
    app.state.event_bus = (
        build_event_bus(config, app.state.events) if config.events_enabled else None
    )
    app.state.event_idempotency = IdempotencyStore()
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

    # Registered after Session (so it wraps it), and BEFORE DenylistGuard
    # below (so DenylistGuard wraps IT) — only when enabled. This makes
    # DenylistGuard the outer layer relative to rate limiting, matching
    # Rust's `... -> DenylistGuard -> RateLimit -> Session -> ...` order: a
    # denylisted IP's request is rejected by DenylistGuard before it ever
    # reaches RateLimitMiddleware, so denylisted callers never consume
    # rate-limit quota. See middleware_ratelimit.py's module docstring for
    # the full ordering rationale (including where ResilienceMiddleware and
    # the pre-existing MetricsMiddleware fit).
    if config.rate_limit_enabled:
        app.add_middleware(RateLimitMiddleware)

    # Registered after security_headers/CORS/Session/RateLimit so it becomes
    # the outermost of those (Starlette runs the most-recently-
    # `add_middleware`d layer first) — every HTTP request, for every route
    # below, passes through DenylistGuard before session/CORS/security-header
    # handling, rate limiting, or routing. See middleware.py for behavior.
    app.add_middleware(DenylistGuard)

    # Registered after DenylistGuard (so it wraps it) but before
    # MetricsMiddleware below — only when enabled. Matches Rust's
    # `... -> Resilience -> DenylistGuard -> ...` order: resilience's 503
    # fast-fail (circuit open / at capacity) is the cheapest possible path,
    # firing even for requests that would otherwise be denylisted.
    if config.resilience_enabled:
        app.add_middleware(ResilienceMiddleware)

    # Registered LAST of all — becomes the true outermost layer, wrapping
    # even DenylistGuard/RateLimit/Resilience, so it counts every
    # request/response that reaches this ASGI app, including ones
    # DenylistGuard short-circuits and scrapes of /metrics itself (Rust
    # MetricsMiddleware parity; see middleware.py's MetricsMiddleware
    # docstring for the full ordering rationale).
    app.add_middleware(MetricsMiddleware)

    app.include_router(token_router, prefix="/oauth")
    app.include_router(introspect_router, prefix="/oauth")
    app.include_router(authorize_router, prefix="/oauth")
    app.include_router(device_router, prefix="/oauth")
    app.include_router(logout_router, prefix="/oauth")
    app.include_router(par_router, prefix="/oauth")
    app.include_router(login_router, prefix="/auth")
    app.include_router(social_router, prefix="/auth")
    app.include_router(register_router, prefix="/connect")
    app.include_router(wellknown_router)
    app.include_router(admin_router)
    app.include_router(system_router)
    app.include_router(events_router, prefix="/events")

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
