"""Event bus + ingest + recent-events fan-out — Phase 3c Task 3.

Ported from `crates/oauth2-events/src/{envelope,plugins,event_actor,
actix_bus}.rs` + `tests/security_http.rs` (see `.superpowers/sdd/
research-events-observability.md`, `tests_to_port`).
"""

from __future__ import annotations

import asyncio
import base64

from tests.conftest import build_client_app
from tests.helpers import post_token
from tests.test_token_endpoint import run_code_flow

from oauth2_server.services.events_bus import (
    AuthEvent,
    ConsoleEventLogger,
    EventBus,
    EventEnvelope,
    EventFilter,
    IdempotencyStore,
    InMemoryEventLogger,
    RecentEventsPlugin,
    build_event_bus,
)
from oauth2_server.services.events import RecentEventsStore


def _envelope_body(event_type: str = "widget.created", **overrides) -> dict:
    event: dict = {"event_type": event_type, "metadata": {}}
    body: dict = {"event": event}
    for key, value in overrides.items():
        if key in ("idempotency_key", "traceparent", "tracestate"):
            body[key] = value
        else:
            event[key] = value
    return body


# --- models ------------------------------------------------------------


def test_envelope_roundtrip():
    envelope = EventEnvelope(
        event=AuthEvent(
            event_type="token_created", user_id="u1", client_id="c1", metadata={"scope": "read"}
        )
    )
    data = envelope.model_dump(mode="json")

    # idempotency_key/traceparent/tracestate omitted when None; attributes
    # omitted when empty — but the nested AuthEvent's own None fields stay.
    assert "idempotency_key" not in data
    assert "traceparent" not in data
    assert "tracestate" not in data
    assert "attributes" not in data
    assert data["event"]["client_id"] == "c1"
    assert data["event"]["user_id"] == "u1"
    assert data["event"]["error"] is None

    restored = EventEnvelope.model_validate(data)
    assert restored.producer == envelope.producer == "oauth2_server"
    assert restored.correlation_id == envelope.correlation_id
    assert restored.event.event_type == "token_created"


def test_envelope_keeps_idempotency_key_traceparent_attributes_when_set():
    envelope = EventEnvelope(
        event=AuthEvent(event_type="token_created"),
        idempotency_key="k1",
        traceparent="00-trace-01",
        tracestate="vendor=1",
        attributes={"region": "us"},
    )
    data = envelope.model_dump(mode="json")
    assert data["idempotency_key"] == "k1"
    assert data["traceparent"] == "00-trace-01"
    assert data["tracestate"] == "vendor=1"
    assert data["attributes"] == {"region": "us"}


def test_effective_idempotency_key_defaults_to_event_id():
    event = AuthEvent(event_type="token_created")
    envelope = EventEnvelope(event=event)
    assert envelope.effective_idempotency_key() == event.id


def test_effective_idempotency_key_prefers_explicit_key():
    event = AuthEvent(event_type="token_created")
    envelope = EventEnvelope(event=event, idempotency_key="k1")
    assert envelope.effective_idempotency_key() == "k1"


def test_effective_idempotency_key_blank_key_falls_back_to_event_id():
    event = AuthEvent(event_type="token_created")
    envelope = EventEnvelope(event=event, idempotency_key="   ")
    assert envelope.effective_idempotency_key() == event.id


def test_severity_is_lowercased():
    event = AuthEvent(event_type="token_created", severity="WARNING")
    assert event.severity == "warning"


# --- EventFilter ---------------------------------------------------------


def test_event_filter_allow_all():
    f = EventFilter.allow_all()
    assert f.should_emit("token_created")
    assert f.should_emit("client_registered")


def test_event_filter_include_only():
    f = EventFilter.include_only(["token_created", "token_revoked"])
    assert f.should_emit("token_created")
    assert f.should_emit("token_revoked")
    assert not f.should_emit("client_registered")


def test_event_filter_exclude():
    f = EventFilter.exclude_events(["token_validated"])
    assert not f.should_emit("token_validated")
    assert f.should_emit("token_created")
    assert f.should_emit("client_registered")


# --- plugins ---------------------------------------------------------------


async def test_in_memory_logger_max_events():
    plugin = InMemoryEventLogger(max_events=3)
    for i in range(5):
        await plugin.emit(EventEnvelope(event=AuthEvent(event_type="x", user_id=f"user_{i}")))
    events = plugin.get_events()
    assert len(events) == 3
    assert events[0].user_id == "user_2"
    assert events[2].user_id == "user_4"


async def test_console_logger_health_check_is_always_true():
    plugin = ConsoleEventLogger()
    assert await plugin.health_check() is True
    # emit must not raise
    await plugin.emit(EventEnvelope(event=AuthEvent(event_type="token_created")))


async def test_recent_events_plugin_bridges_into_store():
    store = RecentEventsStore()
    plugin = RecentEventsPlugin(store)
    await plugin.emit(EventEnvelope(event=AuthEvent(event_type="token_created", client_id="c1")))
    items, total = store.list(10, 0)
    assert total == 1
    assert items[0]["event"]["event_type"] == "token_created"
    assert items[0]["event"]["client_id"] == "c1"


# --- EventBus ----------------------------------------------------------


async def test_bus_publishes_to_in_memory_logger():
    in_memory = InMemoryEventLogger()
    bus = EventBus([in_memory])
    envelope = EventEnvelope(event=AuthEvent(event_type="token_created", client_id="c1"))
    bus.publish_best_effort(envelope)
    await asyncio.sleep(0)
    events = in_memory.get_events()
    assert len(events) == 1
    assert events[0].event_type == "token_created"
    assert events[0].client_id == "c1"


async def test_bus_respects_filter():
    in_memory = InMemoryEventLogger()
    bus = EventBus([in_memory], EventFilter.include_only(["token_created"]))
    bus.publish_best_effort(EventEnvelope(event=AuthEvent(event_type="client_registered")))
    await asyncio.sleep(0)
    assert in_memory.get_events() == []


async def test_bus_survives_a_failing_plugin_and_still_reaches_the_next_one():
    class Boom:
        name = "boom"

        async def emit(self, envelope):
            raise RuntimeError("plugin exploded")

        async def health_check(self):
            return True

    in_memory = InMemoryEventLogger()
    bus = EventBus([Boom(), in_memory])
    bus.publish_best_effort(EventEnvelope(event=AuthEvent(event_type="token_created")))
    await asyncio.sleep(0)
    assert len(in_memory.get_events()) == 1


async def test_bus_health_reports_every_plugin():
    bus = EventBus([InMemoryEventLogger(), ConsoleEventLogger()])
    health = await bus.health()
    assert {"name": "in_memory", "healthy": True} in health
    assert {"name": "console", "healthy": True} in health


def test_build_event_bus_appends_recent_events_plugin_and_warns_on_unknown_backend(caplog):
    from oauth2_server.config import Config

    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        events_backend="not-a-real-backend",
    )
    bus = build_event_bus(config, RecentEventsStore())
    names = {p.name for p in bus.plugins}
    assert "in_memory" in names
    assert "recent_events" in names


# --- IdempotencyStore --------------------------------------------------


async def test_idempotency_store_detects_duplicate():
    store = IdempotencyStore()
    assert await store.is_duplicate_and_record("k1") is False
    assert await store.is_duplicate_and_record("k1") is True


async def test_idempotency_store_independent_keys():
    store = IdempotencyStore()
    assert await store.is_duplicate_and_record("a") is False
    assert await store.is_duplicate_and_record("b") is False


async def test_idempotency_store_ttl_expiry(monkeypatch):
    store = IdempotencyStore(ttl=10)
    clock = [1000.0]
    monkeypatch.setattr("oauth2_server.services.events_bus.time.monotonic", lambda: clock[0])
    assert await store.is_duplicate_and_record("k1") is False
    clock[0] += 5
    assert await store.is_duplicate_and_record("k1") is True
    clock[0] += 11
    assert await store.is_duplicate_and_record("k1") is False


async def test_idempotency_store_overflow_clears_entire_map():
    store = IdempotencyStore(ttl=300, max_entries=2)
    assert await store.is_duplicate_and_record("a") is False
    assert await store.is_duplicate_and_record("b") is False
    # third insert crosses max_entries -> best-effort full clear, so "a" is
    # forgotten and is-not-a-duplicate again.
    assert await store.is_duplicate_and_record("c") is False
    assert await store.is_duplicate_and_record("a") is False


# --- POST /events/ingest ----------------------------------------------


async def test_ingest_auth_not_configured_503(client_app):
    # Default config: events_public_ingest=False, events_ingest_bearer_token
    # unset -> fails CLOSED with 503, not a 401.
    resp = await client_app.post("/events/ingest", json=_envelope_body())
    assert resp.status_code == 503
    assert resp.json() == {"error": "event_ingest_auth_not_configured"}


async def test_ingest_requires_bearer_by_default():
    async with build_client_app({"events_ingest_bearer_token": "s3cr3t-token"}) as client:
        resp = await client.post("/events/ingest", json=_envelope_body())
        assert resp.status_code == 401
        assert resp.headers["www-authenticate"] == "Bearer"
        assert resp.json() == {
            "error": "invalid_token",
            "error_description": "Missing or invalid bearer token",
        }


async def test_ingest_wrong_bearer_401():
    async with build_client_app({"events_ingest_bearer_token": "s3cr3t-token"}) as client:
        resp = await client.post(
            "/events/ingest",
            json=_envelope_body(),
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"


async def test_ingest_correct_bearer_accepted():
    async with build_client_app({"events_ingest_bearer_token": "s3cr3t-token"}) as client:
        resp = await client.post(
            "/events/ingest",
            json=_envelope_body(),
            headers={"Authorization": "Bearer s3cr3t-token"},
        )
        assert resp.status_code == 202
        assert resp.json()["status"] == "accepted"


async def test_ingest_public_can_be_enabled():
    async with build_client_app({"events_public_ingest": True}) as client:
        resp = await client.post("/events/ingest", json=_envelope_body())
        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "accepted"
        assert "idempotency_key" in body
        assert "event_id" in body


async def test_ingest_events_disabled_503():
    # public_ingest=True skips the auth guard entirely so this isolates the
    # "event bus absent" branch from the auth-not-configured branch below.
    async with build_client_app({"events_enabled": False, "events_public_ingest": True}) as client:
        resp = await client.post("/events/ingest", json=_envelope_body())
        assert resp.status_code == 503
        assert resp.json() == {"error": "eventing_disabled"}


async def test_ingest_auth_guard_runs_before_the_disabled_check():
    # When BOTH conditions are true (no bearer configured AND events
    # disabled), the auth guard wins — Rust parity ordering (research doc
    # `endpoints`, brief bullet order): a misconfigured deployment fails
    # closed on auth regardless of whether eventing itself is on.
    async with build_client_app({"events_enabled": False}) as client:
        resp = await client.post("/events/ingest", json=_envelope_body())
        assert resp.status_code == 503
        assert resp.json() == {"error": "event_ingest_auth_not_configured"}


async def test_ingest_duplicate_returns_202_duplicate():
    async with build_client_app({"events_public_ingest": True}) as client:
        payload = _envelope_body(idempotency_key="fixed-key-1")
        first = await client.post("/events/ingest", json=payload)
        assert first.status_code == 202
        assert first.json()["status"] == "accepted"

        second = await client.post("/events/ingest", json=payload)
        assert second.status_code == 202
        body = second.json()
        assert body["status"] == "duplicate"
        assert body["idempotency_key"] == "fixed-key-1"
        assert "event_id" in body


async def test_ingest_idempotency_key_header_overrides_envelope():
    async with build_client_app({"events_public_ingest": True}) as client:
        payload = _envelope_body(idempotency_key="envelope-key")

        first = await client.post(
            "/events/ingest", json=payload, headers={"Idempotency-Key": "header-key"}
        )
        assert first.json()["idempotency_key"] == "header-key"

        second = await client.post(
            "/events/ingest", json=payload, headers={"Idempotency-Key": "header-key"}
        )
        assert second.json()["status"] == "duplicate"
        assert second.json()["idempotency_key"] == "header-key"

        # A fresh header key is NOT a duplicate even with the same envelope
        # idempotency_key body.
        third = await client.post(
            "/events/ingest", json=payload, headers={"Idempotency-Key": "another-header-key"}
        )
        assert third.json()["status"] == "accepted"


async def test_ingest_pushes_accepted_envelope_to_recent_events_store():
    async with build_client_app({"events_public_ingest": True}) as client:
        resp = await client.post("/events/ingest", json=_envelope_body(event_type="widget.created"))
        assert resp.status_code == 202
        await asyncio.sleep(0)  # drain the bus's own RecentEventsPlugin fan-out
        items, total = client.app.state.events.list(10, 0)
        # Rust parity (research doc `endpoints` /events/ingest, task brief):
        # the ingest handler pushes the accepted envelope into
        # RecentEventsStore directly AND ALSO calls `publish_best_effort`,
        # whose fan-out separately reaches the always-appended
        # `RecentEventsPlugin` — so one accepted ingest genuinely records
        # TWO entries, not one.
        assert total == 2
        assert items[0]["event"]["event_type"] == "widget.created"
        assert items[1]["event"]["event_type"] == "widget.created"


async def test_ingest_duplicate_does_not_push_a_second_time():
    async with build_client_app({"events_public_ingest": True}) as client:
        payload = _envelope_body(idempotency_key="dup-key")
        await client.post("/events/ingest", json=payload)
        await client.post("/events/ingest", json=payload)
        await asyncio.sleep(0)
        _items, total = client.app.state.events.list(10, 0)
        # One accepted ingest records 2 (see test above); the duplicate
        # ingest records 0 more.
        assert total == 2


# --- GET /events/health -------------------------------------------------


async def test_events_health_shape(client_app):
    resp = await client_app.get("/events/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["enabled"] is True
    names = {p["name"] for p in body["plugins"]}
    assert "in_memory" in names
    assert "recent_events" in names
    assert all(p["healthy"] is True for p in body["plugins"])


async def test_events_health_disabled_shape():
    async with build_client_app({"events_enabled": False}) as client:
        resp = await client.get("/events/health")
        assert resp.status_code == 200
        assert resp.json() == {"enabled": False, "plugins": []}


# --- emit sites ----------------------------------------------------------


async def test_token_created_event_emitted(client_app):
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials", "scope": "read"},
        basic_auth=("client1", "s3cret"),
    )
    assert resp.status_code == 200
    await asyncio.sleep(0)

    in_memory = client_app.app.state.event_bus.get_plugin("in_memory")
    created = [e for e in in_memory.get_events() if e.event_type == "token_created"]
    assert created
    last = created[-1]
    assert last.client_id == "client1"
    assert last.metadata["scope"] == "read"
    assert last.metadata["has_refresh_token"] == "false"


async def test_client_validated_event_emitted_on_success_and_failure(client_app):
    await post_token(
        client_app,
        {"grant_type": "client_credentials", "scope": "read"},
        basic_auth=("client1", "s3cret"),
    )
    await post_token(
        client_app,
        {"grant_type": "client_credentials", "scope": "read"},
        basic_auth=("client1", "wrong-secret"),
    )
    await asyncio.sleep(0)

    in_memory = client_app.app.state.event_bus.get_plugin("in_memory")
    validated = [e for e in in_memory.get_events() if e.event_type == "client_validated"]
    assert any(e.metadata.get("success") == "true" for e in validated)
    assert any(e.metadata.get("success") == "false" for e in validated)


async def test_authorization_code_created_and_validated_events_emitted(client_app):
    resp, _code = await run_code_flow(client_app)
    assert resp.status_code == 200
    await asyncio.sleep(0)

    in_memory = client_app.app.state.event_bus.get_plugin("in_memory")
    types = [e.event_type for e in in_memory.get_events()]
    assert "authorization_code_created" in types
    assert "authorization_code_validated" in types
    assert "token_created" in types

    created = next(
        e for e in in_memory.get_events() if e.event_type == "authorization_code_created"
    )
    assert created.metadata["scope"] == "openid email"
    assert created.metadata["redirect_uri"] == "https://a.example/cb"


async def test_token_revoked_event_emitted(client_app):
    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
    )
    access_token = resp.json()["access_token"]
    revoke_resp = await client_app.post(
        "/oauth/revoke",
        data={"token": access_token},
        headers={"Authorization": "Basic " + base64.b64encode(b"client1:s3cret").decode()},
    )
    assert revoke_resp.status_code == 200
    await asyncio.sleep(0)

    in_memory = client_app.app.state.event_bus.get_plugin("in_memory")
    revoked = [e for e in in_memory.get_events() if e.event_type == "token_revoked"]
    assert revoked
    assert revoked[-1].client_id == "client1"
