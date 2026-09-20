"""Signed-cookie session helpers built on `starlette.middleware.sessions`."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from starlette.requests import Request

if TYPE_CHECKING:
    from oauth2_server.models import User


def current_user_id(request: Request) -> str | None:
    return request.session.get("user_id")


def current_acr(request: Request) -> str | None:
    """The Authentication Context Class Reference stamped at login (RFC 9470
    step-up). Server-side only: it is written by `set_login` from config and
    is never taken from a request parameter, so a client cannot talk its way
    into a stronger `acr` by asking for one."""
    return request.session.get("acr")


def current_amr(request: Request) -> list[str] | None:
    """The Authentication Methods References stamped at login (`["pwd"]` for
    password login, `["fed"]` for social/federated login)."""
    amr = request.session.get("amr")
    return amr if isinstance(amr, list) else None


def set_login(
    request: Request,
    user: "User",
    *,
    acr: str | None = None,
    amr: list[str] | None = None,
) -> None:
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
    # RFC 9470 / OIDC Core §2: what this authentication event can attest to.
    # `acr` comes from `config.acr_values_supported[0]` and `amr` from the
    # route that authenticated the user — both server-chosen, never client
    # input. Omitted keys simply leave the session without the claim, which
    # makes every `acr_values` request unsatisfiable (fail closed).
    if acr is not None:
        request.session["acr"] = acr
    if amr is not None:
        request.session["amr"] = list(amr)
