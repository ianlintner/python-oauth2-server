"""GET/POST /auth/login — HTML login page + username/password session login.

Ported from `crates/oauth2-actix/src/handlers/login.rs` (`login_page` for the
error-banner mapping, `login_submit` for credential verification,
disabled-account rejection, and the safe `return_to` redirect). Rate limiting
(`LoginRateLimiter` / `too_many_attempts`) is out of scope for this port —
the `too_many_attempts` error key is still supported by the banner mapping
below so a future rate limiter (or an upstream proxy) can redirect here with
it, but nothing in this module currently produces that redirect itself.
"""

from __future__ import annotations

import html
import importlib.resources
import time

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from oauth2_server.security import verify_password_async
from oauth2_server.services.auth import is_safe_redirect
from oauth2_server.sessions import set_login

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

    storage = request.app.state.storage
    user = await storage.get_user_by_username(username)

    # Generic error for unknown username, disabled account, and bad password
    # alike, to avoid leaking account existence/state.
    if (
        user is None
        or not user.enabled
        or not await verify_password_async(password, user.password_hash)
    ):
        return RedirectResponse("/auth/login?error=invalid_credentials", status_code=303)

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
