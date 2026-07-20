"""Signed-cookie session helpers built on `starlette.middleware.sessions`."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from starlette.requests import Request

if TYPE_CHECKING:
    from oauth2_server.models import User


def current_user_id(request: Request) -> str | None:
    return request.session.get("user_id")


def set_login(request: Request, user: "User") -> None:
    # Starlette sessions are cookie-based (signed, client-held) rather than a
    # server-side session id, so there is nothing to "rotate" server-side.
    # Clearing the session before writing the new identity is the equivalent
    # mitigation for session fixation: any pre-login session state is
    # discarded rather than reused post-authentication.
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["auth_time"] = int(time.time())
    # role/email/username feed the admin guard (routes/admin/guard.py) and
    # future admin-surface actor attribution — mirrors the Rust session,
    # which stores the same fields at login.
    request.session["role"] = user.role
    request.session["email"] = user.email
    request.session["username"] = user.username
