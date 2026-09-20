"""RFC 8628 §3.5 `slow_down` — single-process device-code poll-interval
tracker.

Divergence 35 (deliberate, beyond the Rust server): the Rust device grant
polling loop (`crates/oauth2-actix/src/handlers/device.rs`) never returns
`slow_down` — polling faster than the advertised `interval` isn't
penalized there at all. This Python port adds RFC 8628 §3.5 enforcement:
a `device_code` polled sooner than its currently-required interval gets
`slow_down` back, and the required interval grows by `SLOW_DOWN_STEP_SECS`
on every violation (uncapped) until the caller backs off enough to poll
successfully again. There is no Rust behavior to stay in parity with here.

**Single-process only** — like `DpopReplayStore` (services/dpop.py),
`ParStore` (services/par.py), and `FixedWindowLimiter` (services/
ratelimit.py), `DevicePollTracker` keeps its state in a plain `dict` on
the instance, not in the database or a shared cache. A multi-worker or
multi-instance deployment needs this backed by shared storage (e.g.
Redis) instead, or every worker enforces its own independent (and looser)
effective rate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# An entry is dropped after this long of inactivity, same
# sweep-on-every-call house pattern as `DpopReplayStore._sweep_expired`.
# Comfortably longer than this server's device_code `expires_in` (600s,
# `routes/device.py` `_EXPIRES_IN`), so a live poll loop is never evicted
# out from under it, but state for an abandoned/expired code doesn't leak
# forever either.
ENTRY_TTL_SECS = 24 * 60 * 60

# RFC 8628 §3.5: "the interval MUST increase by 5 seconds for each
# subsequent request" once a client is told to slow down.
SLOW_DOWN_STEP_SECS = 5


@dataclass
class _PollState:
    last_poll: float
    interval: int
    expiry: float


class DevicePollTracker:
    """Tracks the most recent poll time and currently-required interval per
    `device_code`, so `routes/token.py`'s device_code branch can enforce
    RFC 8628 §3.5 `slow_down`.

    Sweeps every expired entry on each `observe` call — same house
    pattern as `DpopReplayStore.check_and_insert` (services/dpop.py).
    """

    def __init__(self) -> None:
        self._entries: dict[str, _PollState] = {}

    def _sweep_expired(self, now: float) -> None:
        expired = [code for code, state in self._entries.items() if state.expiry <= now]
        for code in expired:
            del self._entries[code]

    def observe(self, device_code: str, base_interval: int) -> int | None:
        """Record a poll of `device_code`.

        Returns `None` when the poll is allowed — either the first poll
        ever seen for this code, or one that arrived no sooner than the
        currently-required interval (which starts at `base_interval` and
        only ever grows, via violations, never shrinks back down). Returns
        the new, incremented required interval (in seconds) when the poll
        arrived too soon (RFC 8628 §3.5 `slow_down`).
        """
        now = time.monotonic()
        self._sweep_expired(now)

        state = self._entries.get(device_code)
        if state is None:
            self._entries[device_code] = _PollState(
                last_poll=now, interval=base_interval, expiry=now + ENTRY_TTL_SECS
            )
            return None

        if now - state.last_poll < state.interval:
            state.interval += SLOW_DOWN_STEP_SECS
            state.last_poll = now
            state.expiry = now + ENTRY_TTL_SECS
            return state.interval

        state.last_poll = now
        state.expiry = now + ENTRY_TTL_SECS
        return None

    def forget(self, device_code: str) -> None:
        """Drop `device_code`'s poll history. Called on redemption (and any
        other terminal outcome) so no stale violation history lingers
        against a code that can no longer be legitimately polled again.
        No-op if the code has no tracked history."""
        self._entries.pop(device_code, None)
