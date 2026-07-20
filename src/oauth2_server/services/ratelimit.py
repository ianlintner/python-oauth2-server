"""Fixed-window login-attempt rate limiter.

Ported from `oauth2_actix::handlers::login::LoginRateLimiter`
(`crates/oauth2-actix/src/handlers/login.rs`), which wraps a token-bucket
`InMemoryRateLimiter` (`oauth2-ratelimit` crate) with no reset primitive at
all — every check, allowed or not, permanently consumes a token until the
bucket refills on its own schedule. This port intentionally simplifies that
to a fixed window (simpler to reason about for the same 10-attempts/15-minute
credential-stuffing threshold) and adds an explicit `reset()`, used by
`routes/login.py` to clear both the per-IP and per-username keys on a
*successful* login — a legitimate user who mistypes their password a few
times should not stay throttled after finally getting it right. This is a
deliberate, documented deviation from strict Rust parity, not an oversight.

**Single-process only** — entries live in a plain `dict` on this instance,
not in the database or a shared cache; same caveat family as `ParStore`
(services/par.py). A multi-worker or multi-instance deployment needs this
backed by shared storage (e.g. Redis) instead.
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

    def check(self, key: str) -> int | None:
        """Gate and record one attempt against `key`.

        Returns `None` when allowed — which also records the attempt against
        the key's current window — or the number of seconds remaining until
        the window resets when `key` has already reached `max_attempts`
        within the current window (a blocked check does not record another
        attempt; it is already over the limit).

        Lazily evicts an expired window the next time its key is touched
        here, rather than sweeping the whole dict proactively.
        """
        now = time.monotonic()
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
