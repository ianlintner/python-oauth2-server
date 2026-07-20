"""In-memory ring buffer behind `GET /admin/api/events/recent` (Task 9).

Ported from the Rust `RecentEventsStore` (`crates/oauth2-actix/src/events.rs`)
— capacity-bounded, newest-first, in-memory only (no Redis-backed variant in
this port). One instance lives at `app.state.events` for the process
lifetime.
"""

from __future__ import annotations

from collections import deque


class RecentEventsStore:
    def __init__(self, capacity: int = 500) -> None:
        # `appendleft` on push keeps the deque newest-first at all times, so
        # `list(self._events)` never needs a reversal; maxlen evicts the
        # oldest (rightmost) entry once `capacity` is exceeded.
        self._events: deque[dict] = deque(maxlen=capacity)

    def push(self, event: dict) -> None:
        self._events.appendleft(event)

    def list(self, limit: int, offset: int) -> tuple[list[dict], int]:
        total = len(self._events)
        items = list(self._events)[offset : offset + limit]
        return items, total
