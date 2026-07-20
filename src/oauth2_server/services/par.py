"""RFC 9126 Pushed Authorization Requests — in-memory store.

Ported from `AuthActor.par_store` (`crates/oauth2-actix/src/actors/auth_actor.rs`):
an `Arc<Mutex<HashMap<String, PAREntry>>>` field on the in-process actor, keyed
by `urn:ietf:params:oauth:request-uri:{uuid-v4}`, with a hardcoded 60-second
TTL and destructive (single-use) lookup. This is **single-process only** —
entries live in a plain `dict` on this `ParStore` instance, not in the
database. A multi-worker or multi-instance deployment would need this backed
by shared storage (e.g. Redis) instead; that is a deliberate Rust-parity
limitation, not an oversight.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

PAR_TTL_SECS = 60


@dataclass
class ParEntry:
    client_id: str
    params: dict[str, str]
    created_at: float = field(default_factory=time.monotonic)


class ParStore:
    def __init__(self) -> None:
        self._entries: dict[str, ParEntry] = {}

    def _sweep_expired(self) -> None:
        now = time.monotonic()
        expired = [
            request_uri
            for request_uri, entry in self._entries.items()
            if now - entry.created_at >= PAR_TTL_SECS
        ]
        for request_uri in expired:
            del self._entries[request_uri]

    def store(self, client_id: str, params: dict[str, str]) -> str:
        """Sweep expired entries, insert a new one, and return its request_uri."""
        self._sweep_expired()
        request_uri = f"urn:ietf:params:oauth:request-uri:{uuid.uuid4()}"
        self._entries[request_uri] = ParEntry(client_id=client_id, params=params)
        return request_uri

    def take(self, request_uri: str) -> ParEntry | None:
        """Sweep expired entries, then destructively pop (single-use lookup)."""
        self._sweep_expired()
        return self._entries.pop(request_uri, None)
