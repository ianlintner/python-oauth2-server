"""GET /auth/login/{provider} + GET /auth/callback/{provider} — social login
(Google/Microsoft/GitHub/Azure), plus Okta/Auth0 as 503 stubs.

Ported from `crates/oauth2-social-login/src/handlers/auth.rs` (see
`.superpowers/sdd/research-social-login.md`). Mounted at `/auth` alongside
`routes/login.py` (which owns the *literal* `/auth/login` path — this
router's `/login/{provider}` and `/callback/{provider}` never collide with
it since `provider` always has a path segment after `/login`).

Session establishment reuses `sessions.py::set_login`. This port's session
convention has no separate Rust `authenticated` flag — `current_user_id`
treats a present `user_id` as authenticated — so `set_login`'s existing
fields (`user_id`, `auth_time`, `role`, `email`, `username`) are sufficient,
and its `request.session.clear()` closes a Rust gap for free: Rust never
clears `csrf_token`/`pkce_verifier`/`provider` after a successful callback
(research doc gotchas), leaving the state value replayable within the same
cookie session; here they're gone the moment login succeeds.
"""

from __future__ import annotations

import logging
import secrets
import uuid

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import ORJSONResponse, PlainTextResponse, RedirectResponse

from oauth2_server.models import User
from oauth2_server.security import hash_password_async
from oauth2_server.services.auth import is_safe_redirect
from oauth2_server.services.social import (
    ALL_PROVIDERS,
    DISPLAY_NAMES,
    OAUTH_PROVIDERS,
    STUB_PROVIDERS,
    ProviderError,
    build_authorize_url,
    exchange_code,
    fetch_userinfo,
    generate_pkce_pair,
    resolve_provider_config,
)
from oauth2_server.sessions import set_login

logger = logging.getLogger(__name__)

router = APIRouter()


def _error(error: str, description: str, status: int) -> ORJSONResponse:
    return ORJSONResponse({"error": error, "error_description": description}, status_code=status)


@router.get("/login/{provider}")
async def social_login(provider: str, request: Request):
    if provider not in ALL_PROVIDERS:
        # No route exists for an unknown provider in the Rust server (fixed
        # literal path table, not a wildcard) — a plain 404 is the closest
        # match here.
        raise HTTPException(status_code=404)

    if provider in STUB_PROVIDERS:
        # Rust parity stub (divergence 25): plain-text 503, no session touch.
        return PlainTextResponse(
            f"{DISPLAY_NAMES[provider]} login not yet implemented", status_code=503
        )

    config = request.app.state.config
    rc = resolve_provider_config(config, provider)
    if rc is None:
        return _error(
            "provider_not_configured", f"{DISPLAY_NAMES[provider]} login not configured", 400
        )

    state = secrets.token_urlsafe(32)
    request.session["csrf_token"] = state
    request.session["provider"] = provider
    # Drop any stale verifier from a previously-abandoned (possibly
    # different-provider) attempt in this same cookie session before
    # conditionally repopulating it below.
    request.session.pop("pkce_verifier", None)

    code_challenge: str | None = None
    if rc.pkce:
        verifier, code_challenge = generate_pkce_pair()
        request.session["pkce_verifier"] = verifier

    return RedirectResponse(build_authorize_url(rc, state, code_challenge), status_code=302)


@router.get("/callback/{provider}")
async def social_callback(provider: str, request: Request):
    params = request.query_params

    state = params.get("state")
    if not state:
        return _error("access_denied", "CSRF state parameter is required", 403)

    session_csrf = request.session.get("csrf_token")
    if session_csrf is None or state != session_csrf:
        return _error("access_denied", "CSRF token mismatch", 403)

    session_provider = request.session.get("provider")
    if session_provider != provider:
        return _error("invalid_request", "Provider mismatch", 400)

    if provider not in OAUTH_PROVIDERS:
        return _error("invalid_request", "Unsupported provider", 400)

    config = request.app.state.config
    rc = resolve_provider_config(config, provider)
    if rc is None:
        return _error(
            "provider_not_configured", f"{DISPLAY_NAMES[provider]} login not configured", 400
        )

    code = params.get("code")
    if not code:
        return _error("invalid_request", "Authorization code is required", 400)

    pkce_verifier = request.session.get("pkce_verifier")
    if rc.pkce and not pkce_verifier:
        return _error("session_error", "PKCE verifier missing from session", 400)

    http_client = request.app.state.http_client
    try:
        access_token = await exchange_code(
            http_client, rc, code, pkce_verifier if rc.pkce else None
        )
    except ProviderError as exc:
        logger.warning("social login token exchange failed for %s: %s", provider, exc)
        return _error("token_exchange_failed", str(exc), 400)

    # Circuit breaker guards ONLY the userinfo fetch below — the token
    # exchange above always runs (Rust parity, research doc key_behaviors).
    breaker = request.app.state.social_breakers[provider]
    if not await breaker.allow():
        return _error(
            "provider_unavailable", f"{DISPLAY_NAMES[provider]} circuit breaker open", 400
        )

    try:
        userinfo = await fetch_userinfo(http_client, rc, access_token)
    except ProviderError as exc:
        await breaker.record_failure()
        logger.warning("social login userinfo fetch failed for %s: %s", provider, exc)
        return _error("provider_error", str(exc), 400)
    await breaker.record_success()

    storage = request.app.state.storage
    username = f"{provider}:{userinfo.provider_user_id}"
    user = await storage.get_user_by_username(username)
    if user is None:
        # Placeholder password: an Argon2id hash of a random UUIDv4, never
        # logged or returned — social users authenticate solely via the
        # provider, this hash just satisfies the User model's required
        # field and keeps the row unusable for password login (Rust
        # parity, research doc storage_methods).
        password_hash = await hash_password_async(uuid.uuid4().hex)
        user = User(
            id=uuid.uuid4().hex,
            username=username,
            password_hash=password_hash,
            email=userinfo.email,
            role="user",
        )
        await storage.save_user(user)

    # Read before set_login() clears the session (mirrors routes/login.py).
    return_to = request.session.get("return_to")
    set_login(request, user)

    target = return_to if is_safe_redirect(return_to) else "/profile"
    return RedirectResponse(target, status_code=302)
