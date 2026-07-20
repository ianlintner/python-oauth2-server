"""Fixed-window login-attempt rate limiter.

Ported from `oauth2_actix::handlers::login::LoginRateLimiter`
(`crates/oauth2-actix/src/handlers/login.rs`), which wraps a token-bucket
`InMemoryRateLimiter` (`oauth2-ratelimit` crate) with no reset primitive at
all — every check, allowed or not, permanently consumes a token until the
bucket refills on its own schedule. This port intentionally simplifies that
to a fixed window (simpler to reason about for the same 10-attempts/15-minute
credential-stuffing threshold) and adds an explicit `reset()`, used by
`routes/login.py` to clear only the per-username key on a *successful*
login — a legitimate user who mistypes their password a few times should not
stay throttled after finally getting it right. The per-IP key is deliberately
NOT reset on success: clearing it would let an attacker who controls one
valid account keep resetting the IP-level throttle while stuffing other
usernames from the same address. This is a deliberate, documented deviation
from strict Rust parity, not an oversight.

**Single-process only** — entries live in a plain `dict` on this instance,
not in the database or a shared cache; same caveat family as `ParStore`
(services/par.py). A multi-worker or multi-instance deployment needs this
backed by shared storage (e.g. Redis) instead.

Like `ParStore._sweep_expired`, `check()` sweeps every expired window out of
`_windows` before inserting, rather than only lazily evicting the key it was
called with. Without this, a key touched exactly once (e.g. an attacker
probing many distinct usernames or source IPs, each only a handful of times)
would never be revisited and its `_Window` would leak for the life of the
process. A full-dict sweep on every `check()` call is O(n) amortized, which
is fine at login volumes.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field


@dataclass
class _Window:
    start: float = field(default_factory=time.monotonic)
    count: int = 0


class FixedWindowLimiter:
    def __init__(self, max_attempts: int, window_secs: int) -> None:
        self.max_attempts = max_attempts
        self.window_secs = window_secs
        self._windows: dict[str, _Window] = {}

    def _sweep_expired(self, now: float) -> None:
        expired = [
            k for k, window in self._windows.items() if now - window.start >= self.window_secs
        ]
        for k in expired:
            del self._windows[k]

    def check(self, key: str) -> int | None:
        """Gate and record one attempt against `key`.

        Returns `None` when allowed — which also records the attempt against
        the key's current window — or the number of seconds remaining until
        the window resets when `key` has already reached `max_attempts`
        within the current window (a blocked check does not record another
        attempt; it is already over the limit).

        Sweeps every expired window out of `_windows` before inserting (see
        module docstring) so keys touched only once or twice still get
        evicted, instead of relying on that same key being re-checked later.
        """
        now = time.monotonic()
        self._sweep_expired(now)
        window = self._windows.get(key)
        if window is None or now - window.start >= self.window_secs:
            window = _Window(start=now, count=0)
            self._windows[key] = window

        if window.count >= self.max_attempts:
            remaining = self.window_secs - (now - window.start)
            return max(1, math.ceil(remaining))

        window.count += 1
        return None

    def reset(self, key: str) -> None:
        """Clear all recorded attempts for `key` (called on successful login)."""
        self._windows.pop(key, None)
