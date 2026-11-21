"""The server's notion of "now", with a conformance-only forward offset.

Every protocol time decision (token/code/device_code/PAR expiry, `iat`/`exp`
stamping, the DPoP `iat` window and nonce buckets, RFC 8628 polling
intervals, OIDC `auth_time`/`max_age`) reads time through this module instead
of `datetime.now` / `time.time` / `time.monotonic` directly.

The offset is `0` and cannot change unless `advance()` is called. The only
caller is the `POST /conformance/clock` route, which is mounted exclusively
in conformance mode (see `oauth2_server/conformance_sut.py`), so a normal
start behaves exactly like the wall clock.

Contract (`contract/sut-interface.md` section 7.2): the offset is cumulative,
monotonic (it can never be set backwards) and process-local; `reset()` exists
for process (re)start semantics and tests only.
"""

from __future__ import annotations

import time as _time
from datetime import UTC, datetime, timedelta

# Upper bound for a single advance, mirroring the contract (one year).
MAX_ADVANCE_SECS = 31_536_000

_offset_secs: int = 0


def offset() -> int:
    """Accumulated forward offset in seconds."""
    return _offset_secs


def advance(seconds: int) -> None:
    """Move the clock forward. Only whole, in-range, non-negative amounts."""
    global _offset_secs
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise ValueError("seconds must be an integer")
    if not 0 <= seconds <= MAX_ADVANCE_SECS:
        raise ValueError(f"seconds must be between 0 and {MAX_ADVANCE_SECS}")
    _offset_secs += seconds


def reset() -> None:
    """Drop the offset (process start / test isolation)."""
    global _offset_secs
    _offset_secs = 0


def now() -> datetime:
    """Timezone-aware current UTC time plus the offset."""
    return datetime.now(UTC) + timedelta(seconds=_offset_secs)


def time() -> float:
    """Epoch seconds plus the offset (drop-in for `time.time()`)."""
    return _time.time() + _offset_secs


def monotonic() -> float:
    """Monotonic seconds plus the offset (drop-in for `time.monotonic()`),
    so interval/TTL bookkeeping sees advanced time too."""
    return _time.monotonic() + _offset_secs
