"""Global IP denylist middleware + the (unwired) subject-denylist helper.

Ported from `crates/oauth2-actix/src/middleware/denylist.rs`. `DenylistGuard`
is a pure-ASGI middleware mounted around the whole app in `create_app` (see
`app.py`) so it sees every HTTP request — `/oauth/token`, `/oauth/introspect`,
`/auth/login`, `/admin/api/*`, everything — before routing. Any request whose
peer IP has an active `kind="ip"` denylist entry gets a 403; everything else
passes through untouched.

Deliberate divergence from Rust (see `research-denylist-audit.md` gotchas):
the Rust guard reads `realip_remote_addr()`, which honors `Forwarded`/
`X-Forwarded-For` unconditionally — spoofable, and independent of any
trusted-proxy config. This port uses `request.client.host` (the raw ASGI
peer address) directly and does not consult forwarding headers at all; a
faithful reproduction of the spoofable behavior would carry the vulnerability
forward for no benefit.

`check_subject_denylisted` is the non-IP counterpart for the other four
kinds (`user_id`/`username`/`email`/`client_id`). It originated unit tested
but unwired (Rust parity: `crates/oauth2-actix/src/middleware/
denylist.rs:93` — defined, tested, zero production call sites); wiring it in
was an explicit Phase 3 decision. Phase 3a wires three of the four kinds:
`routes/login.py::login` consults `username` (and the looked-up user's
`email`) before completing a session login, and `ClientService.authenticate`
(`services/clients.py`) plus `routes/authorize.py::authorize` both consult
`client_id` after the client row loads. `user_id` remains unwired — nothing
in this codebase authenticates a subject by `user_id` pre-auth (sessions and
tokens are keyed by `username`/`client_id`), so there is no call site to hang
the check on.
"""

from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

_DENYLIST_KIND_IP = "ip"

_ACCESS_DENIED_BODY = {
    "error": "access_denied",
    "error_description": "request source is denylisted",
}


class DenylistGuard:
    """Pure-ASGI middleware — blocks HTTP requests from a denylisted IP.

    Fail-open by design (Rust parity): a storage exception during the lookup,
    or a request with no peer address at all, passes the request through
    rather than turning a denylist-storage outage into a global 503.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        client = request.client
        if client is not None:
            storage = request.app.state.storage
            try:
                entry = await storage.find_denylist_entry(_DENYLIST_KIND_IP, client.host)
            except Exception:
                logger.warning("denylist lookup failed for ip=%s", client.host, exc_info=True)
                entry = None
            if entry is not None:
                response = JSONResponse(_ACCESS_DENIED_BODY, status_code=403)
                await response(scope, receive, send)
                return

        await self.app(scope, receive, send)


async def check_subject_denylisted(storage, kind: str, value: str) -> str | None:
    """Look up an active denylist entry for a non-IP subject kind.

    Returns the entry's `reason` when `(kind, value)` is actively denylisted,
    `None` otherwise — including for an empty `value` and for any storage
    error (fail-open, matching `DenylistGuard`).
    """
    if not value:
        return None
    try:
        entry = await storage.find_denylist_entry(kind, value)
    except Exception:
        logger.warning("denylist lookup failed for kind=%s", kind, exc_info=True)
        return None
    if entry is None:
        return None
    return entry.reason
