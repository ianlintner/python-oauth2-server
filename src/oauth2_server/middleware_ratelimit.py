"""Global per-IP rate-limit middleware + the resilience (circuit breaker /
back-pressure) middleware.

Ported from `crates/oauth2-actix/src/middleware/rate_limit.rs` and
`crates/oauth2-actix/src/middleware/resilience.rs` (see `.superpowers/sdd/
research-ratelimit-resilience.md`). Both classes are pure-ASGI middleware,
mounted conditionally in `app.py` (only when `config.rate_limit_enabled` /
`config.resilience_enabled`, matching Rust's both-off-by-default posture),
and both live in this one module because the brief groups them together —
they're independent middleware, not layered on each other, and neither
imports the other.

**Middleware ordering (load-bearing — see `app.py`'s `create_app`).** Rust's
documented stack is `HttpsRedirect -> Resilience -> DenylistGuard ->
RateLimit -> Session -> ...` (outermost to innermost): resilience runs
before the denylist check (503 fast-fail is the cheapest possible path, even
for a denylisted caller), and the denylist check runs before rate limiting
specifically so a denylisted IP's requests never consume its rate-limit
quota (a blocked IP retrying forever shouldn't be able to exhaust a shared
budget some *other*, non-denylisted caller behind the same NAT/proxy would
also draw from). This port has no `HttpsRedirect` middleware, and `app.py`
already established `MetricsMiddleware` as the single outermost layer (Task
1 — it must count every request including ones `DenylistGuard` short-
circuits). Composing both constraints, the target call order (outermost to
innermost) is:

    MetricsMiddleware -> ResilienceMiddleware -> DenylistGuard ->
    RateLimitMiddleware -> SessionMiddleware -> ...

Starlette's `add_middleware` prepends (the most-recently-added layer runs
first/outermost), so `app.py` achieves this by adding `RateLimitMiddleware`
*before* `DenylistGuard`, and `ResilienceMiddleware` *after* it (but still
before the pre-existing `MetricsMiddleware` add call).

**Exempt paths.** Both middleware skip `/health`, `/ready`, `/metrics`
(prefix match, Rust parity) — these are polled by orchestrators/scrapers and
must stay reachable regardless of quota or circuit state.
"""

from __future__ import annotations

import logging

import orjson
from fastapi.responses import ORJSONResponse
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from oauth2_server.services.limiter import RateLimitResult
from oauth2_server.services.resilience import CircuitBreaker, CircuitState, ConcurrencyLimiter

logger = logging.getLogger(__name__)

_EXEMPT_PREFIXES = ("/health", "/ready", "/metrics")

_RATE_LIMIT_DESCRIPTION = "Rate limit exceeded. Try again later."
_CIRCUIT_OPEN_DESCRIPTION = "Server is temporarily unavailable. Please retry later."
_AT_CAPACITY_DESCRIPTION = "Server is at capacity. Please retry later."

# Metric label for the single global circuit — this port has exactly one
# circuit breaker (no per-route/per-provider breakers on the HTTP path,
# unlike social login's separate per-provider breakers), matching Rust's
# single "global" circuit name.
_GLOBAL_CIRCUIT_LABEL = "global"


def _is_exempt(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES)


def _ip_prefix(key: str) -> str:
    """Coarsen a rate-limit key (an IP address, or "unknown") into a
    lower-cardinality Prometheus label value.

    The Rust source's exact derivation isn't recoverable from the research
    digest (the two rate-limit metrics were dead code there — never
    recorded at all, see research doc gotchas — so there's no reference
    behavior to match byte-for-byte). Per the task brief's fallback
    instruction, this takes the first two dot-segments of an IPv4 address
    (`"203.0.113.5"` -> `"203.0"`) or the first two colon-segments of an
    IPv6 address, falling back to the input unchanged for anything else
    (including the "unknown" sentinel) — a deliberate, documented judgment
    call, not a parity claim.
    """
    if "." in key:
        parts = key.split(".")
        if len(parts) >= 2:
            return f"{parts[0]}.{parts[1]}"
        return key
    if ":" in key:
        parts = key.split(":")
        if len(parts) >= 2:
            return f"{parts[0]}:{parts[1]}"
        return key
    return key


async def _send_rate_limit_rejected(
    scope: Scope, send: Send, body: dict, retry_after: int, result: RateLimitResult
) -> None:
    """Send the 429 response with CASE-EXACT `Retry-After`/`X-RateLimit-*`
    headers (Rust parity, research doc `endpoints`: rejected responses carry
    uppercase header names, distinct from the lowercase `x-ratelimit-*` an
    ALLOWED response gets via `send_wrapper` below).

    Deliberately bypasses Starlette's `Response` class for this one path:
    empirically, `Response(headers={...})` lower-cases every header name it's
    given before encoding (verified — `MutableHeaders`/`init_headers`
    normalize casing), so there is no way to get case-exact header names
    through it. Sending raw ASGI messages directly is the only way to
    control wire-level header-name casing, hence the manual `orjson.dumps`
    here instead of `ORJSONResponse` (which the rest of this codebase uses
    freely — header casing doesn't matter anywhere else since HTTP header
    names are case-insensitive per RFC 7230 §3.2; this is purely to match
    a documented, if cosmetic, Rust behavioral detail).
    """
    payload = orjson.dumps(body)
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(payload)).encode()),
        (b"Retry-After", str(retry_after).encode()),
        (b"X-RateLimit-Limit", str(result.limit).encode()),
        (b"X-RateLimit-Remaining", b"0"),
        (b"X-RateLimit-Reset", str(result.reset_at).encode()),
    ]
    await send({"type": "http.response.start", "status": 429, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


def _rate_limit_key(request: Request, trust_proxy_headers: bool) -> str:
    """Client IP is a spoofable proxy header (`X-Forwarded-For`, first
    entry) only when `trust_proxy_headers` is enabled — otherwise the raw
    ASGI peer address, falling back to the literal string `"unknown"` when
    there is no peer at all (Rust parity: research doc `endpoints`, "fallback
    'unknown'"). Unlike `DenylistGuard` (which always uses `request.client.
    host` and never consults `X-Forwarded-For` at all — a deliberate,
    documented divergence from Rust's unconditionally-XFF-trusting denylist
    guard, see `middleware.py`), this mirrors Rust's OWN conditional gate on
    `server.trust_proxy_headers` for rate limiting specifically.
    """
    if trust_proxy_headers:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            first = forwarded_for.split(",")[0].strip()
            if first:
                return first
    client = request.client
    return client.host if client is not None else "unknown"


class RateLimitMiddleware:
    """Global per-IP token-bucket rate limiter, applied to every route
    except the exempt health/metrics paths.

    Allowed responses gain lowercase `x-ratelimit-limit`/`-remaining`/
    `-reset` headers; rejected requests short-circuit with a 429 carrying
    the uppercase `X-RateLimit-*` + `Retry-After` headers (this asymmetric
    casing is Rust parity, research doc `key_behaviors`/`endpoints` — not a
    typo). A limiter backend error fails OPEN: the request proceeds
    unthrottled rather than turning a limiter bug into a global outage.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        if _is_exempt(request.url.path):
            await self.app(scope, receive, send)
            return

        app_state = scope["app"].state
        limiter = app_state.rate_limiter
        metrics = app_state.metrics
        key = _rate_limit_key(request, app_state.config.trust_proxy_headers)

        try:
            result = limiter.check(key)
        except Exception:
            logger.warning("rate limiter backend error; failing open", exc_info=True)
            await self.app(scope, receive, send)
            return

        metrics.rate_limit_remaining.observe(result.remaining)

        if not result.allowed:
            retry_after = result.retry_after if result.retry_after is not None else 1
            metrics.rate_limit_rejected_total.labels(ip_prefix=_ip_prefix(key)).inc()
            body = {
                "error": "too_many_requests",
                "error_description": _RATE_LIMIT_DESCRIPTION,
                "retry_after": retry_after,
            }
            await _send_rate_limit_rejected(scope, send, body, retry_after, result)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-ratelimit-limit", str(result.limit).encode()))
                headers.append((b"x-ratelimit-remaining", str(result.remaining).encode()))
                headers.append((b"x-ratelimit-reset", str(result.reset_at).encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


class ResilienceMiddleware:
    """Circuit breaker + back-pressure (concurrency) admission control.

    Check order per Rust (research doc `endpoints`, "ResilienceMiddleware
    ... check order"): (1) circuit `OPEN` -> reject immediately; (2)
    back-pressure (concurrency) full -> reject; (3) bulkheads — SKIPPED, see
    module docstring; (4) circuit half-open probe gate, deliberately AFTER
    the capacity checks so a request that was going to be capacity-rejected
    anyway never wastes a scarce half-open probe slot. After the handler
    runs, a response status `>= 500` records a circuit failure, anything
    else a circuit success — but ONLY when the circuit was `CLOSED` or this
    request was itself a half-open probe (Rust parity: outcomes are not
    recorded for e.g. a request that raced in while the circuit was already
    `OPEN` — though that path is unreachable here since `OPEN` is rejected
    at step 1 before the handler ever runs).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        # Rust increments `circuit_breaker_trips_total` via a CAS-guarded
        # delta against a `last_trips` counter specifically to avoid
        # double-counting a trip that's already been observed (research doc
        # `key_behaviors`). This middleware instance is constructed once per
        # app (in `create_app`) and persists across every request it
        # handles, so tracking the last-observed `total_trips` here as an
        # instance attribute reproduces that delta-increment without needing
        # a CAS loop (single-threaded asyncio — see `services/resilience.py`
        # module docstring for the general argument).
        self._last_trips = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        if _is_exempt(request.url.path):
            await self.app(scope, receive, send)
            return

        app_state = scope["app"].state
        circuit: CircuitBreaker = app_state.circuit_breaker
        concurrency: ConcurrencyLimiter = app_state.concurrency_limiter
        metrics = app_state.metrics

        if circuit.state() == CircuitState.OPEN:
            self._record_circuit_metrics(metrics, circuit)
            await self._send_circuit_open(circuit, scope, receive, send)
            return

        if not await concurrency.try_acquire():
            metrics.back_pressure_rejected_total.inc()
            metrics.concurrent_requests_in_flight.set(concurrency.in_flight())
            await self._send_at_capacity(scope, receive, send)
            return
        metrics.concurrent_requests_in_flight.set(concurrency.in_flight())

        is_probe = False
        if circuit.state() == CircuitState.HALF_OPEN:
            if not await circuit.allow_request():
                concurrency.release()
                metrics.concurrent_requests_in_flight.set(concurrency.in_flight())
                self._record_circuit_metrics(metrics, circuit)
                await self._send_circuit_open(circuit, scope, receive, send)
                return
            is_probe = True

        status_box = {"code": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_box["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            concurrency.release()
            metrics.concurrent_requests_in_flight.set(concurrency.in_flight())

        if circuit.state() == CircuitState.CLOSED or is_probe:
            if status_box["code"] >= 500:
                await circuit.record_failure()
            else:
                await circuit.record_success()

        self._record_circuit_metrics(metrics, circuit)

    def _record_circuit_metrics(self, metrics, circuit: CircuitBreaker) -> None:
        metrics.circuit_breaker_state.labels(circuit=_GLOBAL_CIRCUIT_LABEL).set(
            int(circuit.state())
        )
        trips = circuit.total_trips
        if trips > self._last_trips:
            metrics.circuit_breaker_trips_total.labels(circuit=_GLOBAL_CIRCUIT_LABEL).inc(
                trips - self._last_trips
            )
            self._last_trips = trips

    @staticmethod
    async def _send_circuit_open(
        circuit: CircuitBreaker, scope: Scope, receive: Receive, send: Send
    ) -> None:
        body = {"error": "service_unavailable", "error_description": _CIRCUIT_OPEN_DESCRIPTION}
        response = ORJSONResponse(
            body, status_code=503, headers={"Retry-After": str(circuit.open_secs)}
        )
        await response(scope, receive, send)

    @staticmethod
    async def _send_at_capacity(scope: Scope, receive: Receive, send: Send) -> None:
        body = {"error": "service_unavailable", "error_description": _AT_CAPACITY_DESCRIPTION}
        response = ORJSONResponse(body, status_code=503, headers={"Retry-After": "1"})
        await response(scope, receive, send)
