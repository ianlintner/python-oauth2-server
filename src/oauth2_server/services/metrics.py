"""Prometheus metrics registry.

Ported from `crates/oauth2-observability/src/metrics.rs` (see
`.superpowers/sdd/research-events-observability.md`, `key_behaviors`
"METRICS REGISTRY" / "METRICS ACTUALLY WIRED", and `gotchas`).

Each `Metrics` instance owns a dedicated `prometheus_client.CollectorRegistry`
— never the process-wide default registry — mirroring the Rust
`Metrics::new()` constructing its own `prometheus::Registry`. This lets every
test (and every `create_app` call) build a fresh, isolated instance instead
of leaking global state across app instances/test runs, which would also
make re-registering the same family name in a second app instance a hard
`ValueError` against the default registry.

Every family name is `oauth2_server_`-prefixed and passed as a LITERAL
string (not composed via a `namespace=` kwarg) so exposition text matches
the Rust server's family names byte-for-byte. Two families deliberately have
NO `_total` suffix — `oauth2_server_oauth_authorization_codes_issued` and
`oauth2_server_oauth_failed_authentications` — copied verbatim; Rust breaks
Prometheus naming convention on purpose here (research doc `gotchas`).

Only a subset of the registered families is ever incremented by application
code in this task (the HTTP middleware families, `oauth_token_issued_total`,
`oauth_token_revoked_total`, `oauth_authorization_codes_issued`,
`oauth_failed_authentications`) — matching Rust's "METRICS ACTUALLY WIRED"
list. Everything else (`db_*`, `oauth_clients_total`, `oauth_active_tokens`,
`rate_limit_*`, `errors_total`, `http_client_*`, `events_published_*`,
`redis_client_*`, `circuit_breaker_*`, `back_pressure_rejected_total`,
`concurrent_requests_in_flight`, `bulkhead_rejected_total`) is register-and-
seed-only for this task (scrape parity with the Rust dashboards) — later
Phase 3c tasks (rate limiting/resilience, event bus) wire some of these up
for real.
"""

from __future__ import annotations

import platform

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from oauth2_server import __version__ as _APP_VERSION

# The Rust exposition content-type is exactly 'text/plain; version=0.0.4'
# with no charset; `prometheus_client`'s own `CONTENT_TYPE_LATEST` appends
# '; charset=utf-8', so this module defines and uses its own literal
# constant instead (research doc gotchas, divergence 22).
CONTENT_TYPE = "text/plain; version=0.0.4"

# oauth2-observability/src/metrics.rs STANDARD_LATENCY_BUCKETS /
# STANDARD_SIZE_BUCKETS — kept here (even though no size-histogram exists
# yet, mirroring the Rust module which defines-and-tests them unused too)
# for parity and for any Phase 3c+ histogram that adopts them.
STANDARD_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
STANDARD_SIZE_BUCKETS = (128, 512, 2048, 8192, 32768, 131072, 524288, 2097152, 8388608)

_HTTP_DURATION_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
_RATE_LIMIT_REMAINING_BUCKETS = (0, 1, 5, 10, 25, 50, 75, 100)

# `app_info`'s `service` label. Deliberately the underscored package name
# ("oauth2_server"), matching `routes/system.py`'s `/health` JSON `service`
# field for internal consistency — a documented, cosmetic divergence from
# the Rust metric's hyphenated crate-name label value ("oauth2-server");
# nothing downstream keys off which spelling wins.
_SERVICE_LABEL = "oauth2_server"


class Metrics:
    """Dedicated Prometheus registry + every `oauth2_server_*` family."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        r = self.registry

        # --- HTTP middleware families (services/... wired by middleware.py's
        # MetricsMiddleware) ---
        self.http_requests_total = Counter(
            "oauth2_server_http_requests_total",
            "Total number of HTTP requests received",
            registry=r,
        )
        self.http_request_duration_seconds = Histogram(
            "oauth2_server_http_request_duration_seconds",
            "HTTP request duration in seconds",
            buckets=_HTTP_DURATION_BUCKETS,
            registry=r,
        )
        self.http_requests_by_class_total = Counter(
            "oauth2_server_http_requests_by_class_total",
            "Total HTTP requests by response status class",
            ["status_class"],
            registry=r,
        )
        self.http_requests_total_by_route = Counter(
            "oauth2_server_http_requests_total_by_route",
            "Total HTTP requests by method, route, and status",
            ["method", "route", "status"],
            registry=r,
        )
        self.http_request_duration_seconds_by_route = Histogram(
            "oauth2_server_http_request_duration_seconds_by_route",
            "HTTP request duration in seconds by method, route, and status",
            ["method", "route", "status"],
            registry=r,
        )

        # --- OAuth domain counters/gauges (wired at the routes listed in the
        # module docstring) ---
        self.oauth_token_issued_total = Counter(
            "oauth2_server_oauth_token_issued_total", "Total OAuth tokens issued", registry=r
        )
        self.oauth_token_revoked_total = Counter(
            "oauth2_server_oauth_token_revoked_total", "Total OAuth tokens revoked", registry=r
        )
        # No `_total` suffix on the next two — deliberate, copied verbatim
        # from the Rust exposition names (research doc gotchas: "the
        # dashboard tests grep for the exact strings"). These are declared
        # as `Gauge` rather than `Counter`, and only ever `.inc()`'d, never
        # `.dec()`/`.set()`: `prometheus_client`'s `Counter._child_samples()`
        # unconditionally appends a literal `_total` suffix to every counter
        # sample at collection time (hardcoded in the library, no opt-out —
        # see `Counter._metric_init`/`_child_samples` in
        # `prometheus_client.metrics`), so matching these two names
        # byte-for-byte is only possible with a different metric type. This
        # changes their `# TYPE` line to `gauge` instead of Rust's
        # `IntCounter` (-> `counter`) — an accepted, documented divergence in
        # exchange for exact name parity, which the brief weights higher.
        self.oauth_authorization_codes_issued = Gauge(
            "oauth2_server_oauth_authorization_codes_issued",
            "Total authorization codes issued",
            registry=r,
        )
        self.oauth_failed_authentications = Gauge(
            "oauth2_server_oauth_failed_authentications",
            "Total failed authentication attempts",
            registry=r,
        )
        self.oauth_clients_total = Gauge(
            "oauth2_server_oauth_clients_total", "Total registered OAuth clients", registry=r
        )
        self.oauth_active_tokens = Gauge(
            "oauth2_server_oauth_active_tokens",
            "Total active (non-expired) OAuth tokens",
            registry=r,
        )

        # --- Register-and-seed-only families (parity, unwired this task) ---
        self.db_queries_total = Counter(
            "oauth2_server_db_queries_total", "Total database queries executed", registry=r
        )
        self.db_query_duration_seconds = Histogram(
            "oauth2_server_db_query_duration_seconds",
            "Database query duration in seconds",
            registry=r,
        )
        self.rate_limit_rejected_total = Counter(
            "oauth2_server_rate_limit_rejected_total",
            "Total requests rejected by rate limiting",
            ["ip_prefix"],
            registry=r,
        )
        self.rate_limit_remaining = Histogram(
            "oauth2_server_rate_limit_remaining",
            "Remaining rate-limit budget observed at request time",
            buckets=_RATE_LIMIT_REMAINING_BUCKETS,
            registry=r,
        )
        self.circuit_breaker_state = Gauge(
            "oauth2_server_circuit_breaker_state",
            "Circuit breaker state (0=Closed 1=Open 2=HalfOpen)",
            ["circuit"],
            registry=r,
        )
        self.circuit_breaker_trips_total = Counter(
            "oauth2_server_circuit_breaker_trips_total",
            "Total circuit breaker trips",
            ["circuit"],
            registry=r,
        )
        self.back_pressure_rejected_total = Counter(
            "oauth2_server_back_pressure_rejected_total",
            "Total requests rejected by back-pressure limiting",
            registry=r,
        )
        self.concurrent_requests_in_flight = Gauge(
            "oauth2_server_concurrent_requests_in_flight",
            "Number of requests currently in flight",
            registry=r,
        )
        self.bulkhead_rejected_total = Counter(
            "oauth2_server_bulkhead_rejected_total",
            "Total requests rejected by bulkhead limiting",
            ["bulkhead"],
            registry=r,
        )
        self.errors_total = Counter(
            "oauth2_server_errors_total",
            "Total errors by kind",
            ["kind"],
            registry=r,
        )
        self.http_client_requests_total = Counter(
            "oauth2_server_http_client_requests_total",
            "Total outbound HTTP client requests",
            ["peer_service", "http_method", "http_status_code"],
            registry=r,
        )
        self.http_client_request_duration_seconds = Histogram(
            "oauth2_server_http_client_request_duration_seconds",
            "Outbound HTTP client request duration in seconds",
            ["peer_service", "http_method"],
            buckets=STANDARD_LATENCY_BUCKETS,
            registry=r,
        )
        self.events_published_total = Counter(
            "oauth2_server_events_published_total",
            "Total events published to the event bus",
            ["backend", "event_type", "outcome"],
            registry=r,
        )
        self.events_publish_duration_seconds = Histogram(
            "oauth2_server_events_publish_duration_seconds",
            "Event publish duration in seconds",
            ["backend", "outcome"],
            buckets=STANDARD_LATENCY_BUCKETS,
            registry=r,
        )
        self.redis_client_operations_total = Counter(
            "oauth2_server_redis_client_operations_total",
            "Total Redis client operations",
            ["backend", "operation", "outcome"],
            registry=r,
        )
        self.redis_client_operation_duration_seconds = Histogram(
            "oauth2_server_redis_client_operation_duration_seconds",
            "Redis client operation duration in seconds",
            ["backend", "operation"],
            buckets=STANDARD_LATENCY_BUCKETS,
            registry=r,
        )

        # --- Static build info ---
        self.app_info = Gauge(
            "oauth2_server_app_info",
            "Static application build/version info; always 1",
            ["service", "version", "python_version"],
            registry=r,
        )
        self.app_info.labels(
            service=_SERVICE_LABEL,
            version=_APP_VERSION,
            python_version=platform.python_version(),
        ).set(1)

    def bootstrap_seed(self) -> None:
        """Touch every parity-only *labeled* family with a `bootstrap`-style
        label combination so a cold scrape (before any real traffic) carries
        an actual zero-valued data series for it, not just `# HELP`/`# TYPE`
        — matching the Rust server's zero-seeded bootstrap series (research
        doc `key_behaviors` "METRICS ACTUALLY WIRED": e.g.
        `errors_total{kind="internal"} 0`,
        `http_client_requests_total{peer_service="bootstrap",...} 0`,
        `events_published_total{backend="bootstrap",event_type="boot",
        outcome="success"} 0`, and the Redis analogue).

        Unlabeled families (`db_queries_total`, `db_query_duration_seconds`,
        `rate_limit_remaining`, `oauth_clients_total`, `oauth_active_tokens`,
        ...) need no seeding: `prometheus_client`, like the Rust `prometheus`
        crate, always emits `# HELP`/`# TYPE` plus a zero-valued series for a
        metric with no label dimensions the moment it's registered.
        """
        self.rate_limit_rejected_total.labels(ip_prefix="bootstrap").inc(0)
        self.circuit_breaker_state.labels(circuit="bootstrap").set(0)
        self.circuit_breaker_trips_total.labels(circuit="bootstrap").inc(0)
        self.bulkhead_rejected_total.labels(bulkhead="bootstrap").inc(0)
        self.errors_total.labels(kind="internal").inc(0)
        self.http_client_requests_total.labels(
            peer_service="bootstrap", http_method="GET", http_status_code="0"
        ).inc(0)
        self.http_client_request_duration_seconds.labels(
            peer_service="bootstrap", http_method="GET"
        ).observe(0)
        self.events_published_total.labels(
            backend="bootstrap", event_type="boot", outcome="success"
        ).inc(0)
        self.events_publish_duration_seconds.labels(backend="bootstrap", outcome="success").observe(
            0
        )
        self.redis_client_operations_total.labels(
            backend="bootstrap", operation="ping", outcome="success"
        ).inc(0)
        self.redis_client_operation_duration_seconds.labels(
            backend="bootstrap", operation="ping"
        ).observe(0)

    def render(self) -> bytes:
        """Prometheus text exposition of this instance's registry."""
        return generate_latest(self.registry)
