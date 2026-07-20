"""In-memory token-bucket rate limiter.

Ported from `oauth2-ratelimit::InMemoryRateLimiter` (`oauth2-ratelimit/src/
in_memory.rs` + `token_bucket.rs`, see `.superpowers/sdd/
research-ratelimit-resilience.md`). The Rust crate also ships a Redis
fixed-window backend (`redis.rs`) — out of scope here; this port only
implements the in-memory continuous-refill token bucket, which is the
default backend and the only one exercised by the middleware/penalty-bucket
call sites in this codebase.

Algorithm: each key owns a bucket holding up to `max_tokens` tokens
(`max_requests`, clamped to >= 1 — a 0-capacity limiter would divide-by-zero
computing a refill rate and can never usefully allow anything), refilling
continuously at `max_tokens / window_secs` tokens/sec (`window_secs` also
clamped to >= 1 for the same reason, matching the Rust clamps). A bucket
starts full. `check(key)` refills based on elapsed wall time since the
bucket's last check (via `time.monotonic`, immune to system clock jumps),
then consumes one token if available.

Like `services/par.py::ParStore` and `services/ratelimit.py::
FixedWindowLimiter` (the login limiter — a separate, unrelated class), this
is **single-process only**: bucket state lives in a plain `dict` on the
instance, not shared storage. Also like those two, `check()` sweeps every
bucket idle for more than `2 * window_secs` out of the dict before doing its
own lookup, rather than relying on a background task (the Rust
`InMemoryRateLimiter` spawns a tokio cleanup task every 60s at construction
time — this port has no persistent background task anywhere, so it reuses
the ParStore/FixedWindowLimiter sweep-on-every-call precedent instead). A
bucket that's gone idle long enough to be swept has, by construction, also
had enough elapsed time to fully refill to `max_tokens` anyway (idle-2x-window
implies idle-1x-window, and a full window's idle time already saturates the
refill), so evicting it and recreating a fresh full bucket on the next touch
is behaviorally invisible — purely a memory bound.

This module is deliberately unaware of Prometheus: unlike the brief's
shorthand ("wire `rate_limit_rejected_total{ip_prefix}` + `rate_limit_
remaining` on the limiter"), the actual `oauth2_server_rate_limit_*` metric
increments live at the call site in `middleware_ratelimit.py`'s global
per-IP middleware, not inside this class — mirroring the existing
`FixedWindowLimiter`/`routes/login.py` split (the login limiter has no
`Metrics` dependency either; `routes/login.py` increments `oauth_failed_
authentications` itself). This class is reused for TWO different keyspaces
(the global per-IP middleware AND `routes/token.py`'s client_id-keyed
invalid_client penalty bucket), and only the former has a meaningful
`ip_prefix` — baking IP-shaped metric labels into a generic, key-agnostic
rate limiter would be a layering violation.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

# A bucket untouched for this many multiples of its own window is evicted on
# the next `check()` call for any key (dict-wide sweep, see module
# docstring) — same "idle > 2x window" threshold as the Rust cleanup task.
_SWEEP_IDLE_WINDOW_MULTIPLE = 2


@dataclass
class RateLimitResult:
    """Mirrors Rust `RateLimitResult { allowed, remaining, limit, reset_at,
    retry_after }`. `reset_at` is a Unix-epoch-seconds approximation —
    `now + window_secs` at check time, not tied to the bucket's actual refill
    schedule (Rust parity: "reset_at in-memory = now + full window
    (approximation)", research doc gotchas). `retry_after` is `None` when
    `allowed`, else the whole seconds a caller should wait before the next
    token is available, already clamped to >= 1 and ceiling-rounded — every
    consumer (the global middleware's `Retry-After` header, the
    invalid_client penalty's error_description text) needs exactly that
    representation, so the rounding happens once, here.
    """

    allowed: bool
    remaining: int
    limit: int
    reset_at: int
    retry_after: int | None = None


@dataclass
class _Bucket:
    tokens: float
    last_seen: float


class TokenBucketLimiter:
    """Continuous-refill token bucket, one instance per rate-limited
    keyspace (e.g. one for the global per-IP middleware, a separate one for
    the invalid_client penalty bucket — never shared)."""

    def __init__(self, max_requests: int, window_secs: int) -> None:
        # Clamp both to >= 1: a 0-capacity or 0-window limiter would either
        # divide by zero computing the refill rate or (Rust parity) produce
        # a degenerate always-current window — see module docstring.
        self.max_tokens = max(1, max_requests)
        self.window_secs = max(1, window_secs)
        self._refill_rate = self.max_tokens / self.window_secs
        self._buckets: dict[str, _Bucket] = {}

    def _sweep_expired(self, now: float) -> None:
        idle_cutoff = self.window_secs * _SWEEP_IDLE_WINDOW_MULTIPLE
        expired = [
            key for key, bucket in self._buckets.items() if now - bucket.last_seen >= idle_cutoff
        ]
        for key in expired:
            del self._buckets[key]

    def check(self, key: str) -> RateLimitResult:
        """Refill `key`'s bucket for elapsed time, then consume one token if
        available. Always records this call as the bucket's `last_seen` time,
        whether or not a token was available — matching `FixedWindowLimiter`/
        `ParStore`, a blocked check still "touches" the key for sweep
        purposes (it's still active traffic, not idle)."""
        now = time.monotonic()
        self._sweep_expired(now)

        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=float(self.max_tokens), last_seen=now)
            self._buckets[key] = bucket
        else:
            elapsed = now - bucket.last_seen
            if elapsed > 0:
                bucket.tokens = min(self.max_tokens, bucket.tokens + elapsed * self._refill_rate)
            bucket.last_seen = now

        reset_at = int(time.time()) + self.window_secs

        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return RateLimitResult(
                allowed=True,
                remaining=int(bucket.tokens),
                limit=self.max_tokens,
                reset_at=reset_at,
            )

        seconds_needed = (1 - bucket.tokens) / self._refill_rate
        retry_after = max(1, math.ceil(seconds_needed))
        return RateLimitResult(
            allowed=False,
            remaining=0,
            limit=self.max_tokens,
            reset_at=reset_at,
            retry_after=retry_after,
        )
