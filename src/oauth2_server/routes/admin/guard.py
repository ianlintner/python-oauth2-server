"""Admin RBAC guard — dual-mode (Bearer token + session) authorization for
`/admin/api/*`.

Ported from `crates/oauth2-actix/src/middleware/admin_guard.rs::AdminGuard`.
FastAPI dependencies cannot short-circuit a request by returning a `Response`
directly, so `require_admin` raises `AdminAuthError` — carrying a prebuilt
`Response` — which `create_app`'s exception handler (see `app.py`) turns back
into the actual HTTP response.

Bearer is checked first, matching the Rust guard: a Bearer header present but
invalid/unknown/revoked/expired short-circuits with 401 even if a valid
session cookie is also present. Only the absence of a Bearer header falls
through to the session path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import ORJSONResponse, RedirectResponse, Response


@dataclass
class AdminActor:
    """The authenticated admin caller. Bearer callers have no session
    identity, so both fields are empty strings — Rust parity."""

    actor_id: str
    actor_email: str


class AdminAuthError(Exception):
    """Raised by `require_admin` to short-circuit with a prebuilt `Response`.

    Caught by the exception handler registered in `create_app`, which returns
    `exc.response` verbatim.
    """

    def __init__(self, response: Response) -> None:
        self.response = response
        super().__init__("admin authorization failed")


def client_id_in_allowlist(client_id: str, allowlist: list[str]) -> bool:
    """Exact, trimmed match of `client_id` against `allowlist`.

    An empty allowlist (or one containing only blank entries) denies all —
    fail-closed, matching the Rust `client_id_in_allowlist` unit contract.
    No substring matching: "mcp_evil" does not match an allowlist entry
    "mcp".
    """
    trimmed = client_id.strip()
    if not trimmed:
        return False
    allowed = {entry.strip() for entry in allowlist if entry.strip()}
    return trimmed in allowed


def _invalid_token_error() -> AdminAuthError:
    return AdminAuthError(
        ORJSONResponse(
            {
                "error": "invalid_token",
                "error_description": "Bearer token is invalid or expired",
            },
            status_code=401,
        )
    )


def _insufficient_scope_error() -> AdminAuthError:
    return AdminAuthError(
        ORJSONResponse(
            {
                "error": "insufficient_scope",
                "error_description": "Token requires 'admin' scope",
            },
            status_code=403,
        )
    )


def _login_required_error() -> AdminAuthError:
    return AdminAuthError(RedirectResponse(url="/auth/login?error=login_required", status_code=302))


def _insufficient_permissions_error() -> AdminAuthError:
    return AdminAuthError(
        ORJSONResponse(
            {
                "error": "insufficient_permissions",
                "error_description": "Admin access required",
            },
            status_code=403,
        )
    )


async def _authenticate_bearer(request: Request, token_value: str) -> AdminActor:
    storage = request.app.state.storage
    config = request.app.state.config

    token = await storage.get_token_by_access_token(token_value)
    if token is None or token.revoked or token.expires_at <= datetime.now(timezone.utc):
        raise _invalid_token_error()

    has_admin_scope = "admin" in token.scope.split()
    allowlisted = client_id_in_allowlist(token.client_id, config.admin_client_ids)
    if not has_admin_scope or not allowlisted:
        raise _insufficient_scope_error()

    return AdminActor(actor_id="", actor_email="")


def _authenticate_session(request: Request) -> AdminActor:
    config = request.app.state.config
    session = request.session

    user_id = session.get("user_id")
    if not user_id:
        raise _login_required_error()

    role = session.get("role", "")
    email = session.get("email", "")
    is_admin = role == "admin" or email.lower() in config.admin_emails
    if not is_admin:
        raise _insufficient_permissions_error()

    return AdminActor(actor_id=user_id, actor_email=email)


async def require_admin(request: Request) -> AdminActor:
    """FastAPI dependency guarding `admin_router` — see `routes/admin/__init__.py`."""
    auth_header = request.headers.get("authorization", "")
    if auth_header[:7].lower() == "bearer ":
        token_value = auth_header[7:].strip()
        return await _authenticate_bearer(request, token_value)
    return _authenticate_session(request)
