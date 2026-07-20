"""GET/POST /auth/login — HTML login page + username/password session login.

Ported from `crates/oauth2-actix/src/handlers/login.rs` (`login_page` for the
error-banner mapping, `login_submit` for credential verification,
disabled-account rejection, and the safe `return_to` redirect).

Rate limiting mirrors Rust's `LoginRateLimiter`: before any credential
lookup, `app.state.login_limiter` (`services/ratelimit.py::FixedWindowLimiter`)
is checked for both `login:ip:{ip}` and `login:user:{username}` — either key
being over its limit short-circuits straight to the `too_many_attempts`
redirect (with `Retry-After`) without touching storage or Argon2 at all. Both
keys are checked (and thus recorded) on *every* attempt, matching the Rust
comment "Check on every attempt — not just failures — to prevent evasion via
unknown usernames"; unlike Rust (whose token bucket has no reset), a
*successful* login resets both keys here so a user who mistypes their
password a few times isn't left throttled after finally getting it right.
"""

from __future__ import annotations

import html
import importlib.resources
import logging
import time

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from oauth2_server.middleware import check_subject_denylisted
from oauth2_server.security import verify_password_async
from oauth2_server.services.auth import is_safe_redirect
from oauth2_server.sessions import set_login

logger = logging.getLogger(__name__)

router = APIRouter()

# How long a pending `return_to` saved by GET /oauth/authorize (or
# GET /oauth/device/verify) stays valid. After this window a login no longer
# replays the stored redirect target.
RETURN_TO_MAX_AGE_SECS = 600

_SERVER_ERROR_PLACEHOLDER = "<!--SERVER_ERROR-->"

# Rust parity (`login_page` in login.rs): a fixed set of known error keys map
# to a friendly message; anything else (including a caller-supplied garbage
# key) falls through to the generic message. The raw key is never reflected
# into the page — only these fixed, pre-escaped-at-source strings are.
_ERROR_MESSAGES = {
    "invalid_credentials": "Invalid username or password. Please try again.",
    "login_required": "Please log in to continue.",
    "too_many_attempts": "Too many login attempts. Please wait a few minutes and try again.",
}
_GENERIC_ERROR_MESSAGE = "An error occurred. Please try again."

_FALLBACK_LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign in</title>
</head>
<body>
<h1>Sign in</h1>
<!--SERVER_ERROR-->
<form method="post" action="/auth/login">
  <label for="username">Username</label>
  <input type="text" id="username" name="username" autocomplete="username" required>
  <label for="password">Password</label>
  <input type="password" id="password" name="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>
</body>
</html>
"""


def _load_login_template() -> str:
    """Read `templates/login.html` via `importlib.resources` so it works both
    from a source checkout and an installed wheel. Falls back to an inline
    copy if the packaged template is ever missing (e.g. a packaging
    regression) rather than 500ing the login page."""
    try:
        resource = importlib.resources.files("oauth2_server").joinpath("templates", "login.html")
        return resource.read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return _FALLBACK_LOGIN_HTML


def _render_login_page(error: str | None) -> str:
    page = _load_login_template()
    if error is None:
        return page.replace(_SERVER_ERROR_PLACEHOLDER, "")
    message = _ERROR_MESSAGES.get(error, _GENERIC_ERROR_MESSAGE)
    banner = f'<div class="error">{html.escape(message)}</div>'
    return page.replace(_SERVER_ERROR_PLACEHOLDER, banner)


@router.get("/login")
async def login_page(request: Request) -> HTMLResponse:
    error = request.query_params.get("error")
    return HTMLResponse(_render_login_page(error))


@router.post("/login")
async def login(request: Request):
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")

    # Rate-limit by IP and by username to block credential-stuffing, before
    # ever touching storage. Checked in this order (IP first) so an
    # already-exhausted IP short-circuits without also recording an attempt
    # against the username key.
    limiter = request.app.state.login_limiter
    client_host = request.client.host if request.client else "unknown"
    ip_key = f"login:ip:{client_host}"
    user_key = f"login:user:{username}"

    retry_after = limiter.check(ip_key)
    if retry_after is None:
        retry_after = limiter.check(user_key)
    if retry_after is not None:
        return RedirectResponse(
            "/auth/login?error=too_many_attempts",
            status_code=303,
            headers={"Retry-After": str(retry_after)},
        )

    storage = request.app.state.storage
    user = await storage.get_user_by_username(username)

    # Subject-kind denylist (Phase 3a): a hit on either the submitted
    # username or the looked-up user's email blocks the login just like an
    # unknown user or bad password would — same generic redirect below, so
    # a denylisted account is indistinguishable from any other login
    # failure (no oracle). Only meaningful once a user row exists; an
    # unknown username already falls through to the same generic error.
    denylist_reason = None
    denylist_kind = None
    if user is not None:
        denylist_reason = await check_subject_denylisted(storage, "username", username)
        denylist_kind = "username"
        if denylist_reason is None:
            denylist_reason = await check_subject_denylisted(storage, "email", user.email)
            denylist_kind = "email"

    # Generic error for unknown username, disabled account, bad password, and
    # a denylisted username/email alike, to avoid leaking account
    # existence/state.
    if (
        user is None
        or not user.enabled
        or not await verify_password_async(password, user.password_hash)
        or denylist_reason is not None
    ):
        if denylist_reason is not None:
            logger.warning(
                "login blocked: %s is denylisted (reason=%s)", denylist_kind, denylist_reason
            )
        return RedirectResponse("/auth/login?error=invalid_credentials", status_code=303)

    # Successful login — clear only the per-username key. The user proved
    # themselves for their own account, so their earlier typos shouldn't keep
    # throttling them; the per-IP window must expire naturally, or an attacker
    # holding one valid credential could reset the IP throttle at will and
    # keep stuffing other usernames from the same address.
    limiter.reset(user_key)

    # `return_to` was saved to the session by GET /oauth/authorize (or
    # GET /oauth/device/verify) before redirecting here; read it before
    # set_login() clears the session.
    return_to = request.session.get("return_to")
    return_to_ts = request.session.get("return_to_ts")
    set_login(request, user)

    # Only honor return_to when it was stamped by a recent redirect. A stale
    # (or unstamped) value from an abandoned request must not be replayed on
    # a later unrelated login (login-CSRF hardening).
    fresh = isinstance(return_to_ts, int) and time.time() - return_to_ts <= RETURN_TO_MAX_AGE_SECS

    target = return_to if fresh and is_safe_redirect(return_to) else "/"
    # RFC 9700 §4.11: 303 See Other for a POST-triggered redirect, so a
    # client always re-issues the follow-up as GET.
    return RedirectResponse(target, status_code=303)
