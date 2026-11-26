"""GET/POST /auth/login — HTML login page + username/password session login.

Ported from `crates/oauth2-actix/src/handlers/login.rs` (`login_page` for the
error-banner mapping, `login_submit` for credential verification,
disabled-account rejection, and the safe `return_to` redirect).

Rate limiting mirrors Rust's `LoginRateLimiter`: before any credential
lookup, `app.state.login_limiter` (`services/ratelimit.py::FixedWindowLimiter`)
is checked for both `login:ip:{address}` and a per-(address, username) key —
either key being over its limit short-circuits straight to the `too_many_attempts`
redirect (with `Retry-After`) without touching storage or Argon2 at all. Both
keys are checked (and thus recorded) on *every* attempt, matching the Rust
comment "Check on every attempt — not just failures — to prevent evasion via
unknown usernames"; unlike Rust (whose token bucket has no reset), a
*successful* login resets the (address, username) key here so a user who mistypes
their password a few times isn't left throttled after finally getting it
right — the per-IP key deliberately survives success (see
services/ratelimit.py for the credential-stuffing rationale).
"""

from __future__ import annotations

import html
import importlib.resources
import logging
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from oauth2_server.client_address import client_address
from oauth2_server.middleware import check_subject_denylisted
from oauth2_server.security import hash_password, verify_password_async
from oauth2_server.services.auth import RETURN_TO_MAX_AGE_SECS as RETURN_TO_MAX_AGE_SECS  # noqa: F401
from oauth2_server.services.auth import fresh_return_to
from oauth2_server.services.csrf import require_same_origin
from oauth2_server.sessions import set_login
from oauth2_server import clock

logger = logging.getLogger(__name__)

router = APIRouter()

# Hash verified when the submitted username matches no account, so a failed
# login costs the same password-hashing work either way. Generated once at
# import time with the project's hasher from a random, discarded password.
_DECOY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))

# Placeholder email for the denylist lookup when no user row exists (keeps the
# number of storage lookups the same as for an existing user).
_UNKNOWN_USER_EMAIL = "unknown-user@invalid"

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
    rejection = require_same_origin(request)
    if rejection is not None:
        return rejection
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")

    # A multipart submission can carry a file part instead of text. Treat any
    # non-text credential as an empty one that can never succeed, so it takes
    # the same throttled, generic-failure path as any other bad attempt rather
    # than reaching storage or the hasher as a non-string.
    credentials_are_text = isinstance(username, str) and isinstance(password, str)
    if not isinstance(username, str):
        username = ""
    if not isinstance(password, str):
        password = ""  # nosec B105 - blanking a non-text form part, not a credential

    # Throttle per client address and per (client address, username) pair,
    # before ever touching storage. The address comes from the shared
    # `client_address` helper, so it honours `trust_proxy_headers` the same
    # way the global limiter does. Neither key is shared across addresses
    # for a given username, so attempts from other addresses never consume
    # this caller's budget. Checked address-first so an already-exhausted
    # address short-circuits without recording an attempt on the pair key.
    limiter = request.app.state.login_limiter
    client_host = client_address(request, request.app.state.config.trust_proxy_headers)
    ip_key = f"login:ip:{client_host}"
    user_key = f"login:addr-user:{client_host}|{username}"

    retry_after = limiter.check(ip_key)
    if retry_after is None:
        retry_after = limiter.check(user_key)
    if retry_after is not None:
        # Rust parity (login.rs rate-limited site): a throttled login attempt
        # also counts as a failed authentication.
        request.app.state.metrics.oauth_failed_authentications.inc()
        return RedirectResponse(
            "/auth/login?error=too_many_attempts",
            status_code=303,
            headers={"Retry-After": str(retry_after)},
        )

    storage = request.app.state.storage
    user = await storage.get_user_by_username(username)

    # Every attempt performs the same work regardless of whether the username
    # exists, whether the account is enabled, or whether it is denylisted:
    # both denylist lookups and exactly one password verification (against the
    # stored hash, or a decoy hash when there is no user). Do not turn these
    # into a short-circuiting `or` chain or skip steps for unknown users, as
    # that would make response time depend on account state.
    #
    # Subject-kind denylist (Phase 3a): a hit on either the submitted username
    # or the looked-up user's email blocks the login with the same generic
    # redirect as any other failure. For an unknown user the email lookup runs
    # against a placeholder so the number of storage lookups matches; its
    # result is ignored because an unknown user always fails.
    username_denied = await check_subject_denylisted(storage, "username", username)
    email_denied = await check_subject_denylisted(
        storage, "email", user.email if user is not None else _UNKNOWN_USER_EMAIL
    )
    denylist_kind = "username" if username_denied is not None else "email"
    denylist_reason = username_denied if username_denied is not None else email_denied
    if user is None:
        denylist_reason = None

    password_ok = await verify_password_async(
        password, user.password_hash if user is not None else _DECOY_PASSWORD_HASH
    )

    # Generic error for unknown username, disabled account, bad password, and
    # a denylisted username/email alike, to avoid leaking account
    # existence/state. All operands are already computed (no short-circuit).
    if (
        user is None
        or not user.enabled
        or not password_ok
        or not credentials_are_text
        or denylist_reason is not None
    ):
        if denylist_reason is not None:
            logger.warning(
                "login blocked: %s is denylisted (reason=%s)", denylist_kind, denylist_reason
            )
        # Rust parity (login.rs: bad password / unknown user / disabled
        # account / denylisted all count as failed authentications). This
        # single branch already collapses all four Rust call sites into one
        # generic outcome (see the module docstring), so one increment here
        # covers all of them.
        request.app.state.metrics.oauth_failed_authentications.inc()
        return RedirectResponse("/auth/login?error=invalid_credentials", status_code=303)

    # Successful login — clear only the (address, username) key. The user proved
    # themselves for their own account, so their earlier typos shouldn't keep
    # throttling them; the per-IP window must expire naturally, or an attacker
    # holding one valid credential could reset the IP throttle at will and
    # keep stuffing other usernames from the same address.
    limiter.reset(user_key)

    # `return_to` was saved to the session by GET /oauth/authorize (or
    # GET /oauth/device/verify) before redirecting here; read it before
    # set_login() clears the session.
    return_to_data = dict(request.session)
    set_login(
        request,
        user,
        acr=request.app.state.config.default_acr,
        amr=["pwd"],
    )

    # Only honor return_to when it was stamped by a recent redirect. A stale
    # (or unstamped) value from an abandoned request must not be replayed on
    # a later unrelated login (login-CSRF hardening).
    target = fresh_return_to(return_to_data, "/", now=clock.time())
    # RFC 9700 §4.11: 303 See Other for a POST-triggered redirect, so a
    # client always re-issues the follow-up as GET.
    return RedirectResponse(target, status_code=303)
