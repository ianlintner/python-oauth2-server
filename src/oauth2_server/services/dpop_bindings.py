"""RFC 9449 §10 `dpop_jkt` authorization-code bindings — in-memory store.

Divergence 52 (no Rust counterpart: the Rust server never parses `dpop_jkt`).
`/oauth/authorize` records the thumbprint the client asked its code to be
bound to; `/oauth/token` consumes it at redemption and refuses to issue
unless the request carries a DPoP proof from the same key.

The binding deliberately does NOT live on the `AuthorizationCode` row: the
schema is owned by the Rust server and may not grow a `dpop_jkt` column, so
this port keeps the association in process memory instead — the same shape as
`ParStore` (services/par.py) and `DpopReplayStore` (services/dpop.py), with
the same `time.monotonic()` sweep-on-access pattern.

**Single-process only.** A multi-worker or multi-instance deployment needs
this backed by shared storage (e.g. Redis): an authorization code issued by
one instance and redeemed on another finds no binding and — since an absent
binding is indistinguishable from "the client never asked for one" — skips
the check entirely rather than failing closed. That is a documented
limitation of divergence 52, not an oversight; the code's other protections
(PKCE, single use, client and redirect_uri matching) are unaffected.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class _Binding:
    jkt: str
    expires_at: float


class DpopCodeBindings:
    """`authorization code -> dpop_jkt` map with a TTL and destructive reads.

    `ttl_secs` is the authorization code's own lifetime
    (`config.authorization_code_ttl_secs`): an entry can never outlive the
    code it describes, so nothing accumulates for codes that are issued and
    then abandoned.
    """

    def __init__(self, ttl_secs: int) -> None:
        self._ttl_secs = max(1, ttl_secs)
        self._entries: dict[str, _Binding] = {}

    def _sweep_expired(self, now: float) -> None:
        expired = [code for code, entry in self._entries.items() if entry.expires_at <= now]
        for code in expired:
            del self._entries[code]

    def bind(self, code: str, jkt: str) -> None:
        """Sweep expired entries, then record `code -> jkt`."""
        now = time.monotonic()
        self._sweep_expired(now)
        self._entries[code] = _Binding(jkt=jkt, expires_at=now + self._ttl_secs)

    def take(self, code: str) -> str | None:
        """Sweep expired entries, then destructively pop `code`'s thumbprint.

        Destructive on every call, including one whose enforcement then
        fails: a redemption attempt is the single chance to prove possession
        of the bound key, and the token endpoint marks the code used when the
        proof does not match, so there is no second attempt to hand the
        binding to. Returns `None` when the code was never bound, was bound
        on another instance, or has already been redeemed.
        """
        now = time.monotonic()
        self._sweep_expired(now)
        entry = self._entries.pop(code, None)
        return entry.jkt if entry is not None else None
