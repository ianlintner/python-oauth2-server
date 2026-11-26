"""Signed-cookie session helpers built on `starlette.middleware.sessions`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.requests import Request
from oauth2_server import clock
from oauth2_server.csrf import session_csrf_token

from oauth2_server.services.users import load_active_user

if TYPE_CHECKING:
    from oauth2_server.models import User


def current_user_id(request: Request) -> str | None:
    return request.session.get("user_id")


async def load_session_user(request: Request) -> User | None:
    """The active user behind this request's session, re-read from storage.

    The cookie is client-held, so it only names the user (`user_id`) and the
    `session_epoch` it was issued under; standing (enabled, denylist, role,
    epoch) always comes from the stored row. A session whose user is gone,
    inactive or at a different epoch is cleared and treated as logged out. A
    session without an epoch (issued before it existed) is also ended.
    """
    session = request.session
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = await load_active_user(request.app.state.storage, user_id)
    epoch = session.get("session_epoch")
    if user is None or not isinstance(epoch, int) or epoch != user.session_epoch:
        session.clear()
        return None
    return user


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
    user: User,
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
    request.session["auth_time"] = int(clock.time())
    # role/email/username feed the admin guard (routes/admin/guard.py) and
    # future admin-surface actor attribution — mirrors the Rust session,
    # which stores the same fields at login.
    request.session["session_epoch"] = user.session_epoch
    request.session["role"] = user.role
    request.session["email"] = user.email
    request.session["email_verified"] = user.email_verified
    request.session["username"] = user.username
    # Mint the CSRF token with the login itself. Sessions live in the cookie,
    # so a token first created while rendering a page would only exist in the
    # cookie that response sets; a caller that keeps the login cookie would
    # then submit a form whose token its session does not hold.
    session_csrf_token(request)
    # RFC 9470 / OIDC Core §2: what this authentication event can attest to.
    # `acr` comes from `config.acr_values_supported[0]` and `amr` from the
    # route that authenticated the user — both server-chosen, never client
    # input. Omitted keys simply leave the session without the claim, which
    # makes every `acr_values` request unsatisfiable (fail closed).
    if acr is not None:
        request.session["acr"] = acr
    if amr is not None:
        request.session["amr"] = list(amr)
