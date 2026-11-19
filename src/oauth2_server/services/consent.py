"""User consent for the authorization endpoint (RFC 6749 §3.1, OIDC Core §3.1.2.4).

`GET /oauth/authorize` validates the whole request, and when the user has not
yet approved the requested scopes for the client it parks the validated request
here and renders a consent page. `POST /oauth/consent` resumes *only* the parked
request: the browser submits an opaque handle plus a CSRF token, never
`redirect_uri`/`scope`/etc., so it cannot alter what is being approved.

Like `ParStore`, the store is in-process memory: entries are lost on restart and
are not shared between workers (the user simply repeats the authorization
request).
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

CONSENT_TTL_SECS = 600

# Human-readable labels for well-known scopes; anything else is shown verbatim
# (escaped by the page renderer).
SCOPE_LABELS = {
    "openid": "Verify your identity",
    "profile": "View your basic profile information",
    "email": "View your email address",
    "offline_access": "Keep access while you are not present",
    "read": "Read your data",
    "write": "Modify your data",
}


def scope_label(scope: str) -> str:
    return SCOPE_LABELS.get(scope, scope)


@dataclass
class PendingConsent:
    """A fully validated authorization request awaiting the user's decision."""

    user_id: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str | None
    response_mode: str
    hybrid: bool
    nonce: str | None
    code_challenge: str | None
    code_challenge_method: str | None
    authorization_details: str | None
    resource: str | None
    claims_request: str | None
    dpop_jkt: str | None
    acr_values: str | None = None
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    created_at: float = field(default_factory=time.monotonic)


class ConsentStore:
    def __init__(self) -> None:
        self._entries: dict[str, PendingConsent] = {}

    def _sweep_expired(self) -> None:
        now = time.monotonic()
        for handle in [
            h for h, e in self._entries.items() if now - e.created_at >= CONSENT_TTL_SECS
        ]:
            del self._entries[handle]

    def put(self, entry: PendingConsent) -> str:
        """Sweep expired entries, store `entry`, return its unguessable handle."""
        self._sweep_expired()
        handle = secrets.token_urlsafe(32)
        self._entries[handle] = entry
        return handle

    def take(self, handle: str) -> PendingConsent | None:
        """Sweep expired entries, then destructively pop (single-use lookup)."""
        self._sweep_expired()
        return self._entries.pop(handle, None)

    def peek(self, handle: str) -> PendingConsent | None:
        self._sweep_expired()
        return self._entries.get(handle)
