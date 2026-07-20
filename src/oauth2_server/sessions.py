"""Signed-cookie session helpers built on `starlette.middleware.sessions`."""

from __future__ import annotations

import time

from starlette.requests import Request


def current_user_id(request: Request) -> str | None:
    return request.session.get("user_id")


def set_login(request: Request, user_id: str) -> None:
    # Starlette sessions are cookie-based (signed, client-held) rather than a
    # server-side session id, so there is nothing to "rotate" server-side.
    # Clearing the session before writing the new identity is the equivalent
    # mitigation for session fixation: any pre-login session state is
    # discarded rather than reused post-authentication.
    request.session.clear()
    request.session["user_id"] = user_id
    request.session["auth_time"] = int(time.time())
