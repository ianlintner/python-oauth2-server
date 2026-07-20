"""POST /auth/login — username/password session login.

Ported from `crates/oauth2-actix/src/handlers/login.rs::login_submit` (credential
verification, disabled-account rejection, safe `return_to` redirect). Rate limiting
and the HTML login page are out of scope for this port.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse, RedirectResponse

from oauth2_server.security import verify_password_async
from oauth2_server.services.auth import is_safe_redirect
from oauth2_server.sessions import set_login

router = APIRouter()

# How long a pending `return_to` saved by GET /oauth/authorize stays valid.
# After this window a login no longer replays the stored authorize URL.
RETURN_TO_MAX_AGE_SECS = 600


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
        return ORJSONResponse({"error": "invalid_credentials"}, status_code=401)

    # `return_to` was saved to the session by GET /oauth/authorize before
    # redirecting here; read it before set_login() clears the session.
    return_to = request.session.get("return_to")
    return_to_ts = request.session.get("return_to_ts")
    set_login(request, user)

    # Only honor return_to when it was stamped by a recent authorize redirect.
    # A stale (or unstamped) value from an abandoned authorization request must
    # not be replayed on a later unrelated login (login-CSRF hardening).
    fresh = isinstance(return_to_ts, int) and time.time() - return_to_ts <= RETURN_TO_MAX_AGE_SECS

    target = return_to if fresh and is_safe_redirect(return_to) else "/"
    return RedirectResponse(target, status_code=302)
