"""In-process event bus — models, filter, plugins, bus, idempotency store.

Ported from `crates/oauth2-events` (see `.superpowers/sdd/
research-events-observability.md`, `key_behaviors` "EVENT ENVELOPE JSON" /
"EVENT TYPES" / "DELIVERY MODEL" / "IDEMPOTENCY"). This is a best-effort,
fire-and-forget, strictly in-process, at-most-once bus — no persistence, no
outbox, no cross-worker delivery. Only the `in_memory`/`console`/
`RecentEventsPlugin` plugins are ported; the feature-gated Redis
Streams/Kafka/RabbitMQ publisher plugins are explicitly OUT of scope for
this port (research doc `config_keys` OAUTH2_EVENTS_BACKEND, `gotchas`).

`EventBus.publish_best_effort` is the ONLY public entry point routes/services
should call to emit an event — it spawns an `asyncio.create_task` and returns
immediately, so a broken or slow plugin can never delay or fail an OAuth
flow. Task references are held in `EventBus._tasks` (discarded on
completion) purely to prevent them from being garbage-collected mid-flight,
a documented `asyncio.create_task` footgun — never awaited inline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterable, Protocol, runtime_checkable

from pydantic import BaseModel, Field, field_validator, model_serializer

if TYPE_CHECKING:
    from oauth2_server.config import Config
    from oauth2_server.services.events import RecentEventsStore

logger = logging.getLogger(__name__)


def _uuid4_hex() -> str:
    return uuid.uuid4().hex


def _rfc3339_now() -> str:
    # Matches the rest of the codebase's RFC 3339 convention (e.g.
    # `services/audit.py::build_audit`'s `received_at`) — a `+00:00` offset
    # suffix rather than a literal `Z`, both valid RFC 3339.
    return datetime.now(timezone.utc).isoformat()


# --- Models (serde-parity with crates/oauth2-events/src/envelope.rs) -------


class AuthEvent(BaseModel):
    """A single domain event. Field-for-field port of the Rust `AuthEvent`
    (research doc `key_behaviors` "EVENT ENVELOPE JSON"). Unlike
    `EventEnvelope` below, none of these fields are omitted when `None` —
    `user_id`/`client_id`/`error` all serialize as JSON `null`, matching
    serde's default (no `skip_serializing_if` on this struct)."""

    id: str = Field(default_factory=_uuid4_hex)
    event_type: str
    timestamp: str = Field(default_factory=_rfc3339_now)
    severity: str = "info"
    user_id: str | None = None
    client_id: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    error: str | None = None

    @field_validator("severity")
    @classmethod
    def _lowercase_severity(cls, v: str) -> str:
        return v.lower()


class EventEnvelope(BaseModel):
    """Wraps an `AuthEvent` with delivery/tracing metadata. Field-for-field
    port of the Rust `EventEnvelope`. `idempotency_key`/`traceparent`/
    `tracestate` are omitted from the serialized JSON when `None`, and
    `attributes` is omitted when empty — via the `_serialize` wrap-mode
    model_serializer below, so both `model_dump()`/`model_dump(mode="json")`
    and `model_dump_json()` apply the same exclusion uniformly, without
    disturbing the nested `event` object's own (never-excluded) `None`
    fields the way a blanket `exclude_none=True` over the whole envelope
    would."""

    event: AuthEvent
    idempotency_key: str | None = None
    traceparent: str | None = None
    tracestate: str | None = None
    correlation_id: str = Field(default_factory=_uuid4_hex)
    producer: str = "oauth2_server"
    produced_at: str = Field(default_factory=_rfc3339_now)
    attributes: dict[str, str] = Field(default_factory=dict)

    def effective_idempotency_key(self) -> str:
        """The explicit `idempotency_key`, when non-blank, else `event.id`."""
        key = (self.idempotency_key or "").strip()
        return key if key else self.event.id

    @model_serializer(mode="wrap")
    def _serialize(self, handler) -> dict:
        data = handler(self)
        for name in ("idempotency_key", "traceparent", "tracestate"):
            if data.get(name) is None:
                data.pop(name, None)
        if not data.get("attributes"):
            data.pop("attributes", None)
        return data


# --- Filter ------------------------------------------------------------


@dataclass(frozen=True)
class EventFilter:
    """Include/exclude gate applied to `event_type` before fan-out. Ported
    from `crates/oauth2-events/src/plugins.rs`'s `EventFilter` — `allow_all`
    is the default (everything emitted); `include_only` emits ONLY the
    listed types; `exclude_events` emits everything EXCEPT the listed
    types."""

    mode: str = "allow_all"
    types: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def allow_all(cls) -> "EventFilter":
        return cls("allow_all", frozenset())

    @classmethod
    def include_only(cls, types: Iterable[str]) -> "EventFilter":
        return cls("include", frozenset(types))

    @classmethod
    def exclude_events(cls, types: Iterable[str]) -> "EventFilter":
        return cls("exclude", frozenset(types))

    def should_emit(self, event_type: str) -> bool:
        if self.mode == "include":
            return event_type in self.types
        if self.mode == "exclude":
            return event_type not in self.types
        return True


# --- Plugins -------------------------------------------------------------


@runtime_checkable
class EventPlugin(Protocol):
    """Port of the Rust `EventPlugin` trait. `emit` raises on failure — the
    bus catches and logs per-plugin, never propagating (see `EventBus.
    _fan_out`)."""

    name: str

    async def emit(self, envelope: EventEnvelope) -> None: ...

    async def health_check(self) -> bool: ...


class InMemoryEventLogger:
    """Ring buffer of the most recent `max_events` `AuthEvent`s (not full
    envelopes — mirrors the Rust plugin, whose in-memory store and its unit
    tests key off the bare event, e.g. `events[0].user_id`). `deque(maxlen=)`
    drops the OLDEST entry from the left as new ones are appended on the
    right, so after pushing more than `max_events` the store always holds
    the newest `max_events`, oldest-first."""

    name = "in_memory"

    def __init__(self, max_events: int = 1000) -> None:
        self._events: deque[AuthEvent] = deque(maxlen=max_events)

    async def emit(self, envelope: EventEnvelope) -> None:
        self._events.append(envelope.event)

    def get_events(self) -> list[AuthEvent]:
        return list(self._events)

    async def health_check(self) -> bool:
        return True


class ConsoleEventLogger:
    """Logs each envelope as a single JSON log line — port of the Rust
    `ConsoleEventLogger` (`tracing::info!("Event: {json}")`)."""

    name = "console"

    def __init__(self, log: logging.Logger | None = None) -> None:
        self._log = log or logger

    async def emit(self, envelope: EventEnvelope) -> None:
        self._log.info("Event: %s", json.dumps(envelope.model_dump(mode="json")))

    async def health_check(self) -> bool:
        return True


class RecentEventsPlugin:
    """Bridges every published envelope into the existing admin-UI
    `RecentEventsStore` (`services/events.py`, already backing `GET
    /admin/api/events/recent`) — the Python analog of the Rust
    `RecentEventsPlugin` defined inline in the server binary. Always
    appended to the plugin list regardless of `events_backend`, matching
    Rust parity (research doc `config_keys` OAUTH2_EVENTS_BACKEND: "Every
    recognized backend ALSO gets the RecentEventsPlugin appended")."""

    name = "recent_events"

    def __init__(self, store: "RecentEventsStore") -> None:
        self._store = store

    async def emit(self, envelope: EventEnvelope) -> None:
        self._store.push(envelope.model_dump(mode="json"))

    async def health_check(self) -> bool:
        return True


# --- Bus -------------------------------------------------------------------


class EventBus:
    """Fire-and-forget in-process fan-out (research doc `key_behaviors`
    "DELIVERY MODEL": "strictly in-process, at-most-once, fire-and-forget").
    """

    def __init__(self, plugins: list[EventPlugin], event_filter: EventFilter | None = None) -> None:
        self.plugins = list(plugins)
        self._filter = event_filter or EventFilter.allow_all()
        # Holds strong references to in-flight fan-out tasks so they aren't
        # garbage-collected mid-await (a well-known `asyncio.create_task`
        # footgun); each task removes itself once done.
        self._tasks: set[asyncio.Task] = set()

    def publish_best_effort(self, envelope: EventEnvelope) -> None:
        """Fan out `envelope` to every plugin without blocking the caller.
        NEVER awaited inline by a request handler — spawns a task and
        returns immediately, so a broken/slow plugin can never delay or
        fail the OAuth flow that triggered the event."""
        if not self._filter.should_emit(envelope.event.event_type):
            return
        task = asyncio.create_task(self._fan_out(envelope))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _fan_out(self, envelope: EventEnvelope) -> None:
        for plugin in self.plugins:
            try:
                await plugin.emit(envelope)
            except Exception:
                logger.warning(
                    "event plugin %s failed to emit event_type=%s",
                    plugin.name,
                    envelope.event.event_type,
                    exc_info=True,
                )

    async def health(self) -> list[dict]:
        """`[{"name": ..., "healthy": ...}, ...]` for every plugin — feeds
        `GET /events/health`. A plugin whose `health_check` itself raises is
        reported unhealthy rather than propagating (fail-safe, matching this
        bus's overall best-effort posture)."""
        result = []
        for plugin in self.plugins:
            try:
                healthy = await plugin.health_check()
            except Exception:
                logger.warning("event plugin %s health_check failed", plugin.name, exc_info=True)
                healthy = False
            result.append({"name": plugin.name, "healthy": healthy})
        return result

    def get_plugin(self, name: str) -> EventPlugin | None:
        for plugin in self.plugins:
            if plugin.name == name:
                return plugin
        return None


def emit_event(
    event_bus: EventBus | None,
    event_type: str,
    *,
    user_id: str | None = None,
    client_id: str | None = None,
    severity: str = "info",
    metadata: dict[str, str] | None = None,
    error: str | None = None,
) -> None:
    """Convenience wrapper for route/service call sites: build an `AuthEvent`
    + `EventEnvelope` and publish it, no-op when `event_bus` is `None`
    (events disabled). Callers fetch `event_bus` from `request.app.state.
    event_bus` (or thread it through a service constructor, e.g.
    `ClientService`) — this function itself has no FastAPI/Starlette
    dependency so it stays usable from plain service modules."""
    if event_bus is None:
        return
    event = AuthEvent(
        event_type=event_type,
        severity=severity,
        user_id=user_id,
        client_id=client_id,
        metadata=metadata or {},
        error=error,
    )
    event_bus.publish_best_effort(EventEnvelope(event=event))


def build_event_bus(config: "Config", recent_events_store: "RecentEventsStore") -> EventBus:
    """Construct the app's `EventBus` from `Config.events_backend`/
    `events_filter_mode`/`events_types` (research doc `config_keys`
    OAUTH2_EVENTS_BACKEND/OAUTH2_EVENTS_FILTER_MODE/OAUTH2_EVENTS_TYPES).
    Only `console`/`in_memory`/`both` are real backends in this port —
    Redis Streams/Kafka/RabbitMQ are feature-gated in Rust and explicitly
    out of scope here (module docstring). An unrecognized `events_backend`
    value falls back to `in_memory` with a warning, matching Rust's startup
    behavior; `RecentEventsPlugin` is unconditionally appended regardless of
    backend."""
    backend = (config.events_backend or "in_memory").strip().lower()
    plugins: list[EventPlugin] = []
    if backend == "console":
        plugins.append(ConsoleEventLogger())
    elif backend == "both":
        plugins.append(InMemoryEventLogger())
        plugins.append(ConsoleEventLogger())
    elif backend == "in_memory":
        plugins.append(InMemoryEventLogger())
    else:
        logger.warning(
            "unknown OAUTH2_EVENTS_BACKEND=%r; falling back to in_memory", config.events_backend
        )
        plugins.append(InMemoryEventLogger())
    plugins.append(RecentEventsPlugin(recent_events_store))

    filter_mode = (config.events_filter_mode or "allow_all").strip().lower()
    if filter_mode == "include":
        event_filter = EventFilter.include_only(config.events_types)
    elif filter_mode == "exclude":
        event_filter = EventFilter.exclude_events(config.events_types)
    else:
        event_filter = EventFilter.allow_all()

    return EventBus(plugins, event_filter)


# --- Ingest idempotency ------------------------------------------------


class IdempotencyStore:
    """In-process TTL-deduplication for `POST /events/ingest` (research doc
    `key_behaviors` "IDEMPOTENCY" / `storage_methods` `IdempotencyStore.
    is_duplicate_and_record`). Purely `dict[str, float]` (monotonic-clock
    insert time) behind an `asyncio.Lock` — NOT cross-worker/replica, exactly
    matching the Rust `tokio::Mutex<HashMap<String, Instant>>` (documented
    gap in the research doc's `gotchas`: a multi-worker deployment silently
    weakens dedup unless reimplemented on a shared backend like Redis).

    TTL is pruned on every call; if the map still holds >= `max_entries`
    afterwards, the ENTIRE map is cleared (best-effort — Rust parity, not a
    partial eviction) rather than ever growing unbounded.
    """

    def __init__(self, ttl: float = 300, max_entries: int = 100_000) -> None:
        self._ttl = ttl
        self._max_entries = max_entries
        self._entries: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def is_duplicate_and_record(self, key: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            self._prune(now)
            if len(self._entries) >= self._max_entries:
                logger.warning(
                    "IdempotencyStore exceeded max_entries=%d; clearing", self._max_entries
                )
                self._entries.clear()
            if key in self._entries:
                return True
            self._entries[key] = now
            return False

    def _prune(self, now: float) -> None:
        expired = [k for k, t in self._entries.items() if now - t >= self._ttl]
        for k in expired:
            del self._entries[k]
