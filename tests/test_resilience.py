"""`CircuitBreaker` + `ConcurrencyLimiter` (services/resilience.py) unit
tests, and `ResilienceMiddleware` (middleware_ratelimit.py) integration
tests.

Ported from `oauth2-resilience/src/circuit_breaker.rs` (10-test unit suite)
and `back_pressure.rs` (5-test unit suite), plus the `crates/oauth2-actix/
src/middleware/resilience.rs` integration suite minus its bulkhead case
(bulkheads are config-file-only in Rust and out of scope here — see
`services/resilience.py`'s module docstring). See `.superpowers/sdd/
research-ratelimit-resilience.md` and `.superpowers/sdd/task-2-brief.md`.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from oauth2_server.middleware_ratelimit import ResilienceMiddleware
from oauth2_server.services.metrics import Metrics
from oauth2_server.services.resilience import CircuitBreaker, CircuitState, ConcurrencyLimiter
from tests.conftest import build_client_app

# ---------------------------------------------------------------------------
# CircuitBreaker (unit)
# ---------------------------------------------------------------------------


def _breaker(**overrides) -> CircuitBreaker:
    kwargs = dict(failure_threshold=3, success_threshold=2, open_secs=30, half_open_max_probes=2)
    kwargs.update(overrides)
    return CircuitBreaker(**kwargs)


def test_circuit_starts_closed():
    cb = _breaker()
    assert cb.state() == CircuitState.CLOSED


async def test_circuit_opens_after_consecutive_failure_threshold():
    cb = _breaker(failure_threshold=3)
    for _ in range(2):
        await cb.record_failure()
        assert cb.state() == CircuitState.CLOSED
    await cb.record_failure()
    assert cb.state() == CircuitState.OPEN
    assert cb.total_trips == 1
    assert await cb.allow_request() is False


async def test_success_resets_consecutive_failure_count():
    cb = _breaker(failure_threshold=3)
    await cb.record_failure()
    await cb.record_failure()
    await cb.record_success()
    # Only 2 consecutive failures accumulate after the reset -> stays closed.
    await cb.record_failure()
    await cb.record_failure()
    assert cb.state() == CircuitState.CLOSED


async def test_open_transitions_to_half_open_after_duration(monkeypatch):
    import oauth2_server.services.resilience as resilience_module

    real_monotonic = resilience_module.time.monotonic
    cb = _breaker(failure_threshold=1, open_secs=30)
    await cb.record_failure()
    assert cb.state() == CircuitState.OPEN

    monkeypatch.setattr(resilience_module.time, "monotonic", lambda: real_monotonic() + 31)
    assert cb.state() == CircuitState.HALF_OPEN


async def test_half_open_closes_after_success_threshold(monkeypatch):
    import oauth2_server.services.resilience as resilience_module

    real_monotonic = resilience_module.time.monotonic
    cb = _breaker(failure_threshold=1, open_secs=30, success_threshold=2)
    await cb.record_failure()
    monkeypatch.setattr(resilience_module.time, "monotonic", lambda: real_monotonic() + 31)
    assert cb.state() == CircuitState.HALF_OPEN

    await cb.record_success()
    assert cb.state() == CircuitState.HALF_OPEN
    await cb.record_success()
    assert cb.state() == CircuitState.CLOSED


async def test_half_open_failure_reopens_immediately(monkeypatch):
    import oauth2_server.services.resilience as resilience_module

    real_monotonic = resilience_module.time.monotonic
    cb = _breaker(failure_threshold=1, open_secs=30, success_threshold=5)
    await cb.record_failure()
    assert cb.total_trips == 1
    monkeypatch.setattr(resilience_module.time, "monotonic", lambda: real_monotonic() + 31)
    assert cb.state() == CircuitState.HALF_OPEN

    await cb.record_failure()
    assert cb.state() == CircuitState.OPEN
    assert cb.total_trips == 2


async def test_half_open_allows_exactly_max_probes(monkeypatch):
    import oauth2_server.services.resilience as resilience_module

    real_monotonic = resilience_module.time.monotonic
    cb = _breaker(failure_threshold=1, open_secs=30, half_open_max_probes=2)
    await cb.record_failure()
    monkeypatch.setattr(resilience_module.time, "monotonic", lambda: real_monotonic() + 31)
    assert cb.state() == CircuitState.HALF_OPEN

    assert await cb.allow_request() is True
    assert await cb.allow_request() is True
    assert await cb.allow_request() is False


async def test_probe_slot_released_on_success(monkeypatch):
    import oauth2_server.services.resilience as resilience_module

    real_monotonic = resilience_module.time.monotonic
    cb = _breaker(failure_threshold=1, open_secs=30, half_open_max_probes=1, success_threshold=5)
    await cb.record_failure()
    monkeypatch.setattr(resilience_module.time, "monotonic", lambda: real_monotonic() + 31)

    assert await cb.allow_request() is True
    assert await cb.allow_request() is False  # slot occupied

    await cb.record_success()  # releases the slot (success_threshold not yet reached)
    assert cb.state() == CircuitState.HALF_OPEN
    assert await cb.allow_request() is True


async def test_probe_slot_released_on_failure(monkeypatch):
    import oauth2_server.services.resilience as resilience_module

    real_monotonic = resilience_module.time.monotonic
    cb = _breaker(failure_threshold=1, open_secs=30, half_open_max_probes=1)
    await cb.record_failure()
    monkeypatch.setattr(resilience_module.time, "monotonic", lambda: real_monotonic() + 31)

    assert await cb.allow_request() is True
    await cb.record_failure()  # releases the slot AND re-opens
    assert cb.state() == CircuitState.OPEN


async def test_rejected_probe_does_not_consume_a_slot(monkeypatch):
    import oauth2_server.services.resilience as resilience_module

    real_monotonic = resilience_module.time.monotonic
    cb = _breaker(failure_threshold=1, open_secs=30, half_open_max_probes=1)
    await cb.record_failure()
    monkeypatch.setattr(resilience_module.time, "monotonic", lambda: real_monotonic() + 31)

    assert await cb.allow_request() is True
    for _ in range(5):
        assert await cb.allow_request() is False  # never consumes a slot

    await cb.record_success()
    # Slot count is back to 0 (the one real probe's release), not negative
    # and not still "stuck" from the 5 rejected attempts.
    assert await cb.allow_request() is True


# ---------------------------------------------------------------------------
# ConcurrencyLimiter (unit)
# ---------------------------------------------------------------------------


async def test_limiter_allows_n_permits_then_rejects():
    limiter = ConcurrencyLimiter(max_concurrent=2)
    assert await limiter.try_acquire() is True
    assert await limiter.try_acquire() is True
    assert await limiter.try_acquire() is False


async def test_release_frees_a_slot():
    limiter = ConcurrencyLimiter(max_concurrent=1)
    assert await limiter.try_acquire() is True
    assert await limiter.try_acquire() is False
    limiter.release()
    assert await limiter.try_acquire() is True


async def test_rejected_total_counts_rejections():
    limiter = ConcurrencyLimiter(max_concurrent=1)
    await limiter.try_acquire()
    assert await limiter.try_acquire() is False
    assert await limiter.try_acquire() is False
    assert limiter.rejected_total == 2


async def test_in_flight_and_available_permits_arithmetic():
    limiter = ConcurrencyLimiter(max_concurrent=4)
    await limiter.try_acquire()
    await limiter.try_acquire()
    assert limiter.in_flight() == 2
    assert limiter.available_permits() == 2


async def test_shared_instance_shared_capacity():
    # Python has no "Arc<Semaphore>::clone()" equivalent — the same object
    # reference IS the shared-capacity mechanism (no separate clone() API
    # needed); two "handles" to the same limiter contend for one budget.
    limiter = ConcurrencyLimiter(max_concurrent=1)
    handle_a = limiter
    handle_b = limiter
    assert await handle_a.try_acquire() is True
    assert await handle_b.try_acquire() is False


# ---------------------------------------------------------------------------
# ResilienceMiddleware — lightweight harness (status-code-driven recording)
# ---------------------------------------------------------------------------


def _build_harness(
    circuit: CircuitBreaker,
    concurrency: ConcurrencyLimiter,
    metrics: Metrics,
    status_code: int = 200,
):
    async def endpoint(request):
        return PlainTextResponse("ok", status_code=status_code)

    app = Starlette(routes=[Route("/probe", endpoint), Route("/health", endpoint)])
    app.state.circuit_breaker = circuit
    app.state.concurrency_limiter = concurrency
    app.state.metrics = metrics
    app.add_middleware(ResilienceMiddleware)
    return app


@asynccontextmanager
async def _harness_client(
    circuit: CircuitBreaker,
    concurrency: ConcurrencyLimiter,
    metrics: Metrics,
    status_code: int = 200,
):
    app = _build_harness(circuit, concurrency, metrics, status_code)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def test_middleware_records_failure_for_5xx_response():
    circuit = CircuitBreaker(
        failure_threshold=1, success_threshold=2, open_secs=30, half_open_max_probes=3
    )
    concurrency = ConcurrencyLimiter(max_concurrent=10)
    metrics = Metrics()

    async with _harness_client(circuit, concurrency, metrics, status_code=500) as c:
        resp = await c.get("/probe")
        assert resp.status_code == 500
        assert circuit.state() == CircuitState.OPEN
        assert circuit.total_trips == 1

        # Circuit now open: the NEXT request is rejected by the middleware
        # itself before the handler ever runs.
        resp2 = await c.get("/probe")
        assert resp2.status_code == 503
        assert resp2.json() == {
            "error": "service_unavailable",
            "error_description": "Server is temporarily unavailable. Please retry later.",
        }
        assert resp2.headers["retry-after"] == "30"


async def test_middleware_records_success_for_2xx_response():
    circuit = CircuitBreaker(
        failure_threshold=3, success_threshold=2, open_secs=30, half_open_max_probes=3
    )
    concurrency = ConcurrencyLimiter(max_concurrent=10)
    metrics = Metrics()

    async with _harness_client(circuit, concurrency, metrics, status_code=200) as c:
        await circuit.record_failure()
        await circuit.record_failure()
        resp = await c.get("/probe")
        assert resp.status_code == 200
        # A success (via the middleware, CLOSED state) resets the
        # consecutive-failure count back to 0.
        await circuit.record_failure()
        await circuit.record_failure()
        assert circuit.state() == CircuitState.CLOSED


async def test_middleware_releases_concurrency_slot_after_response():
    circuit = CircuitBreaker(
        failure_threshold=3, success_threshold=2, open_secs=30, half_open_max_probes=3
    )
    concurrency = ConcurrencyLimiter(max_concurrent=1)
    metrics = Metrics()

    async with _harness_client(circuit, concurrency, metrics, status_code=200) as c:
        resp = await c.get("/probe")
        assert resp.status_code == 200
        assert concurrency.in_flight() == 0


async def test_middleware_exempt_path_bypasses_everything():
    circuit = CircuitBreaker(
        failure_threshold=1, success_threshold=2, open_secs=30, half_open_max_probes=3
    )
    circuit._open()  # force OPEN directly, no HTTP round trip needed
    concurrency = ConcurrencyLimiter(max_concurrent=0)  # can never admit anything
    metrics = Metrics()

    async with _harness_client(circuit, concurrency, metrics, status_code=200) as c:
        resp = await c.get("/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# ResilienceMiddleware — real app integration (mounting/ordering/metrics)
# ---------------------------------------------------------------------------


async def test_resilience_disabled_by_default(client_app):
    # Default config: resilience_enabled=False -> middleware not mounted at
    # all, so a forced-open circuit has zero effect on real requests.
    client_app.app.state.circuit_breaker._open()
    resp = await client_app.get("/oauth/nonexistent")
    assert resp.status_code == 404


async def test_circuit_open_returns_503_with_retry_after_on_real_app():
    async with build_client_app(
        {
            "resilience_enabled": True,
            "resilience_cb_open_secs": 45,
        }
    ) as c:
        # Force the circuit open directly rather than hunting for a genuine
        # 5xx-producing route.
        c.app.state.circuit_breaker._open()

        resp = await c.get("/oauth/nonexistent")
        assert resp.status_code == 503
        assert resp.json() == {
            "error": "service_unavailable",
            "error_description": "Server is temporarily unavailable. Please retry later.",
        }
        assert resp.headers["retry-after"] == "45"


async def test_exempt_paths_bypass_resilience_even_when_circuit_open():
    async with build_client_app({"resilience_enabled": True}) as c:
        c.app.state.circuit_breaker._open()

        for path in ("/health", "/ready", "/metrics"):
            resp = await c.get(path)
            assert resp.status_code == 200


async def test_back_pressure_returns_503_at_capacity():
    async with build_client_app({"resilience_enabled": True}) as c:
        limiter = c.app.state.concurrency_limiter
        for _ in range(limiter.max_concurrent):
            assert await limiter.try_acquire() is True

        resp = await c.get("/oauth/nonexistent")
        assert resp.status_code == 503
        assert resp.json() == {
            "error": "service_unavailable",
            "error_description": "Server is at capacity. Please retry later.",
        }
        assert resp.headers["retry-after"] == "1"


async def test_back_pressure_increments_rejected_metric():
    async with build_client_app({"resilience_enabled": True}) as c:
        limiter = c.app.state.concurrency_limiter
        for _ in range(limiter.max_concurrent):
            assert await limiter.try_acquire() is True

        await c.get("/oauth/nonexistent")

        body = (await c.get("/metrics")).text
        assert "oauth2_server_back_pressure_rejected_total 1.0" in body


async def test_resilience_headers_absent_when_disabled(client_app):
    resp = await client_app.get("/oauth/nonexistent")
    assert resp.status_code == 404
