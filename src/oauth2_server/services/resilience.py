"""Circuit breaker + concurrency (back-pressure) limiter.

Ported from `oauth2-resilience` (`circuit_breaker.rs` + `back_pressure.rs`,
see `.superpowers/sdd/research-ratelimit-resilience.md`). Both are wired as
ONE `ResilienceMiddleware` (`middleware_ratelimit.py`) that also covers the
Rust `bulkhead.rs` behavior — SKIPPED in this port. Rust's bulkheads are
config-file-only (`resilience_from_env()` always sets `bulkheads: vec![]`;
only the HOCON config file path can populate them), and this port has no
config-file layer at all (env-var-only `Config`, see `config.py`), so there
is no way to configure one. Documented as a known gap, not an oversight.

**Concurrency model.** The Rust crate uses lock-free atomics with CAS loops
for the circuit breaker's half-open probe-slot counter (so a losing CAS
attempt can retry without ever "spending" a slot) because it runs under a
genuinely multi-threaded executor (tokio). This port runs under `asyncio`,
which is cooperatively single-threaded: two coroutines can only interleave at
an `await` point, never in the middle of a synchronous statement. That means
a plain `asyncio.Lock` around a probe-slot counter is already equivalent to
a CAS loop here — there is no possibility of two coroutines both observing
"slot available" and both incrementing before either's write lands, the way
there would be with real OS threads. `ConcurrencyLimiter` similarly tracks
its own `_in_flight` counter under a lock rather than reading `asyncio.
Semaphore`'s private internals, and rejects immediately (no queueing) instead
of using `Semaphore.acquire()`'s default blocking-wait behavior, matching
Rust's `try_acquire_owned()` semantics.
"""

from __future__ import annotations

import asyncio
import time
from enum import IntEnum


class CircuitState(IntEnum):
    """Numeric values match the `circuit_breaker_state` Prometheus gauge
    (`services/metrics.py`): 0=Closed, 1=Open, 2=HalfOpen (Rust parity)."""

    CLOSED = 0
    OPEN = 1
    HALF_OPEN = 2


class CircuitBreaker:
    """Consecutive-failure circuit breaker (Closed -> Open -> HalfOpen ->
    Closed/Open), keyed by response status externally (this class only knows
    "success"/"failure", not HTTP — the middleware decides what counts as
    failure, e.g. `status >= 500`).

    All four config knobs are clamped to >= 1 (a 0-threshold or 0-duration
    breaker is nonsensical — it would trip/reset/reopen every single check).
    """

    def __init__(
        self,
        failure_threshold: int,
        success_threshold: int,
        open_secs: int,
        half_open_max_probes: int,
    ) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.success_threshold = max(1, success_threshold)
        self.open_secs = max(1, open_secs)
        self.half_open_max_probes = max(1, half_open_max_probes)

        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._opened_at: float | None = None
        self._probes_in_use = 0
        self.total_trips = 0
        self._lock = asyncio.Lock()

    def state(self) -> CircuitState:
        """Current state. When `OPEN` and `open_secs` has elapsed (checked
        against `time.monotonic`), lazily transitions to `HALF_OPEN` as a
        side effect of this read — matching Rust's "checked lazily on
        state()/allow_request()" design (research doc `tests_to_port`), so
        callers never need a separate "tick" step."""
        if self._state == CircuitState.OPEN and self._opened_at is not None:
            if time.monotonic() - self._opened_at >= self.open_secs:
                self._state = CircuitState.HALF_OPEN
                self._probes_in_use = 0
                self._consecutive_successes = 0
        return self._state

    async def allow_request(self) -> bool:
        """`CLOSED` always allows. `OPEN` never allows (callers checking
        `state()` first and rejecting on `OPEN` before even calling this is
        the expected usage — see the middleware — but this is also correct
        standalone). `HALF_OPEN` admits at most `half_open_max_probes`
        concurrent callers; a rejected caller never consumes a slot."""
        state = self.state()
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.OPEN:
            return False
        async with self._lock:
            if self._probes_in_use >= self.half_open_max_probes:
                return False
            self._probes_in_use += 1
            return True

    async def record_success(self) -> None:
        """`CLOSED`: resets the consecutive-failure count (a good request
        forgives prior isolated failures — only a genuinely *consecutive*
        run trips the breaker). `HALF_OPEN`: releases this call's probe slot
        and counts toward `success_threshold`; closes the circuit once
        reached. A no-op when `OPEN` (nothing should be calling this for a
        rejected request)."""
        state = self.state()
        if state == CircuitState.HALF_OPEN:
            async with self._lock:
                self._probes_in_use = max(0, self._probes_in_use - 1)
            self._consecutive_successes += 1
            if self._consecutive_successes >= self.success_threshold:
                self._close()
        elif state == CircuitState.CLOSED:
            self._consecutive_failures = 0

    async def record_failure(self) -> None:
        """`CLOSED`: counts toward `failure_threshold`; opens once reached.
        `HALF_OPEN`: releases this call's probe slot and re-opens
        immediately — a single half-open failure is enough (no
        `failure_threshold` grace period while probing). A no-op when
        already `OPEN`."""
        state = self.state()
        if state == CircuitState.HALF_OPEN:
            async with self._lock:
                self._probes_in_use = max(0, self._probes_in_use - 1)
            self._open()
        elif state == CircuitState.CLOSED:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold:
                self._open()

    def _open(self) -> None:
        self._state = CircuitState.OPEN
        self._opened_at = time.monotonic()
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._probes_in_use = 0
        self.total_trips += 1

    def _close(self) -> None:
        self._state = CircuitState.CLOSED
        self._opened_at = None
        self._consecutive_failures = 0
        self._consecutive_successes = 0
        self._probes_in_use = 0


class ConcurrencyLimiter:
    """Global back-pressure: at most `max_concurrent` requests admitted at
    once, everything past that rejected immediately (no queueing) — Rust
    `ConcurrencyLimiter`/`try_acquire_owned()` parity."""

    def __init__(self, max_concurrent: int) -> None:
        self.max_concurrent = max(1, max_concurrent)
        self._in_flight = 0
        self.rejected_total = 0
        self._lock = asyncio.Lock()

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self._in_flight >= self.max_concurrent:
                self.rejected_total += 1
                return False
            self._in_flight += 1
            return True

    def release(self) -> None:
        """Synchronous (no `await`) so it can be called unconditionally from
        a `finally` block without risking a second suspension point during
        cleanup. Safe under asyncio's cooperative scheduling: this whole
        method body runs without yielding, so it can't race a concurrent
        `try_acquire`/`release` the way it could under real threads."""
        if self._in_flight > 0:
            self._in_flight -= 1

    def in_flight(self) -> int:
        return self._in_flight

    def available_permits(self) -> int:
        return self.max_concurrent - self._in_flight
