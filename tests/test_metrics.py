"""Prometheus metrics + /metrics, /health, /ready — Phase 3c Task 1.

Ported from `tests/metrics_wiring.rs` + `tests/metrics_paved_path_baseline.rs`
(see `.superpowers/sdd/research-events-observability.md`, `tests_to_port`).
"""

from __future__ import annotations

from oauth2_server import __version__ as _APP_VERSION
from oauth2_server.services.metrics import CONTENT_TYPE, Metrics
from tests.helpers import login_admin, login_session, post_token, seed_admin

# --- helpers -------------------------------------------------------------


def _metric_value(body: str, prefix: str) -> float:
    """Find the first exposition line whose metric name is exactly `prefix`
    (either unlabeled `name value` or labeled `name{...} value`), and return
    its value. Guards against `prefix` being a strict substring of a
    *longer* metric name (e.g. `..._total` vs `..._total_by_route`) by
    requiring the character right after `prefix` to be a space or `{`."""
    for line in body.splitlines():
        if not line.startswith(prefix):
            continue
        rest = line[len(prefix) :]
        if rest and rest[0] not in (" ", "{"):
            continue
        return float(line.rsplit(" ", 1)[1])
    return 0.0


# --- Metrics class: registration + bootstrap seeding ----------------------

_REQUIRED_FAMILIES = [
    "oauth2_server_http_requests_total",
    "oauth2_server_http_request_duration_seconds",
    "oauth2_server_http_client_requests_total",
    "oauth2_server_http_client_request_duration_seconds",
    "oauth2_server_errors_total",
    "oauth2_server_db_queries_total",
    "oauth2_server_db_query_duration_seconds",
    "oauth2_server_redis_client_operations_total",
    "oauth2_server_redis_client_operation_duration_seconds",
    "oauth2_server_events_published_total",
    "oauth2_server_events_publish_duration_seconds",
    "oauth2_server_app_info",
]


def test_required_metrics_are_registered():
    metrics = Metrics()
    text = metrics.render().decode()
    for family in _REQUIRED_FAMILIES:
        assert f"# TYPE {family} " in text, f"missing family: {family}"


def test_app_info_carries_version_label_and_is_one():
    metrics = Metrics()
    text = metrics.render().decode()
    lines = [ln for ln in text.splitlines() if ln.startswith("oauth2_server_app_info{")]
    assert len(lines) == 1
    line = lines[0]
    assert 'service="oauth2_server"' in line
    assert f'version="{_APP_VERSION}"' in line
    assert float(line.rsplit(" ", 1)[1]) == 1.0


def test_two_metrics_instances_have_independent_registries():
    # Each `Metrics()` owns a dedicated `CollectorRegistry` — not the global
    # default — so two instances (as tests build fresh apps repeatedly) never
    # collide re-registering the same family name.
    a = Metrics()
    b = Metrics()
    a.oauth_token_issued_total.inc()
    assert _metric_value(a.render().decode(), "oauth2_server_oauth_token_issued_total") == 1.0
    assert _metric_value(b.render().decode(), "oauth2_server_oauth_token_issued_total") == 0.0


def test_bootstrap_seed_adds_series_for_parity_only_labeled_families():
    metrics = Metrics()
    metrics.bootstrap_seed()
    text = metrics.render().decode()
    assert 'oauth2_server_errors_total{kind="internal"} 0.0' in text
    assert "oauth2_server_events_published_total{" in text
    assert "oauth2_server_redis_client_operations_total{" in text
    assert "oauth2_server_http_client_requests_total{" in text


# --- /metrics content-type -------------------------------------------------


async def test_metrics_content_type_is_exact(client_app):
    resp = await client_app.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == CONTENT_TYPE
    assert "charset" not in resp.headers["content-type"]


# --- HTTP middleware: status class + duration ------------------------------


async def test_http_status_class_counters(client_app):
    for _ in range(3):
        resp = await client_app.get("/health")
        assert resp.status_code == 200
    for _ in range(2):
        resp = await client_app.get("/this-path-does-not-exist")
        assert resp.status_code == 404

    body = (await client_app.get("/metrics")).text
    assert _metric_value(body, 'oauth2_server_http_requests_by_class_total{status_class="2xx"}') > 0
    assert _metric_value(body, 'oauth2_server_http_requests_by_class_total{status_class="4xx"}') > 0
    assert _metric_value(body, 'oauth2_server_http_request_duration_seconds_bucket{le="+Inf"}') > 0


async def test_metrics_scrape_counts_itself(client_app):
    # Rust parity: /metrics scrapes are counted by the metrics middleware too
    # (research doc `MIDDLEWARE ORDER` note: "/health, /ready, /metrics ...
    # ARE counted by MetricsMiddleware (including /metrics scrapes
    # themselves)").
    before = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_http_requests_total"
    )
    after = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_http_requests_total"
    )
    assert after > before


async def test_unmatched_route_bucketed_as_unmatched(client_app):
    # Bounds cardinality (divergence from Rust's raw-path fallback): a 404
    # with no matched route template buckets under a constant "unmatched"
    # route label rather than the raw request path.
    await client_app.get("/this-path-does-not-exist")
    body = (await client_app.get("/metrics")).text
    assert 'route="unmatched"' in body


async def test_matched_route_uses_route_template_not_raw_path(client_app):
    await client_app.get("/health")
    body = (await client_app.get("/metrics")).text
    assert 'route="/health"' in body


async def test_by_route_family_name_has_no_double_total(client_app):
    # `oauth2_server_http_requests_total_by_route` has `_total` in the
    # *middle* of its name, not at the end. `prometheus_client`'s `Counter`
    # unconditionally appends a literal `_total` suffix to the declared name
    # unless it already ENDS with `_total`; since this name doesn't, a
    # `Counter` would emit a doubled-up
    # `oauth2_server_http_requests_total_by_route_total`, which the Rust
    # exposition (and any dashboard querying the Rust name) never produces.
    # It's declared as a `Gauge` instead (only ever `.inc()`'d in
    # middleware.py, which `Gauge` supports) specifically to avoid this.
    await client_app.get("/health")
    body = (await client_app.get("/metrics")).text
    assert "oauth2_server_http_requests_total_by_route{" in body
    assert "_by_route_total" not in body


def test_no_created_series_in_scrape():
    # `prometheus_client` normally emits an extra `..._created` gauge series
    # per Counter/Histogram family (registration timestamp) that Rust's
    # `prometheus` exposition doesn't have. `disable_created_metrics()` is
    # called once at module import in `services/metrics.py`, so no `_created`
    # series should ever appear in a scrape, even after real increments.
    metrics = Metrics()
    metrics.bootstrap_seed()
    metrics.http_requests_total.inc()
    metrics.oauth_token_issued_total.inc()
    metrics.http_request_duration_seconds.observe(0.01)
    text = metrics.render().decode()
    assert "_created" not in text


# --- oauth_authorization_codes_issued --------------------------------------


async def test_authorize_increments_codes_issued(app_with_session):
    await login_session(app_with_session)
    before = _metric_value(
        (await app_with_session.get("/metrics")).text,
        "oauth2_server_oauth_authorization_codes_issued",
    )

    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
        },
    )
    assert resp.status_code == 302

    after = _metric_value(
        (await app_with_session.get("/metrics")).text,
        "oauth2_server_oauth_authorization_codes_issued",
    )
    assert after >= before + 1


# --- oauth_failed_authentications -------------------------------------------


async def test_login_failures_increment_failed_authentications(client_app):
    before = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_failed_authentications"
    )

    resp = await client_app.post(
        "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/auth/login?error=invalid_credentials"

    resp2 = await client_app.post(
        "/auth/login", data={"username": "no-such-user", "password": "whatever"}
    )
    assert resp2.status_code == 303
    assert resp2.headers["location"] == "/auth/login?error=invalid_credentials"

    after = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_failed_authentications"
    )
    assert after >= before + 2


async def test_token_bad_client_secret_increments_failed_authentications(client_app):
    before = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_failed_authentications"
    )

    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "wrong-secret")
    )
    assert resp.status_code == 401

    after = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_failed_authentications"
    )
    assert after >= before + 1


async def test_token_bad_refresh_token_increments_failed_authentications(client_app):
    before = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_failed_authentications"
    )

    resp = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": "bogus-refresh-token"},
        basic_auth=("client1", "s3cret"),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"

    after = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_failed_authentications"
    )
    assert after >= before + 1


# --- oauth_token_issued_total ------------------------------------------------


async def test_token_issued_counter(client_app):
    before = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_token_issued_total"
    )

    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 200

    after = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_token_issued_total"
    )
    assert after >= before + 1


# --- oauth_token_revoked_total ------------------------------------------------


async def test_revoke_increments_revoked_counter(client_app):
    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 200
    access_token = resp.json()["access_token"]

    before = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_token_revoked_total"
    )

    revoke_resp = await client_app.post(
        "/oauth/revoke",
        data={"token": access_token, "client_id": "client1", "client_secret": "s3cret"},
    )
    assert revoke_resp.status_code == 200

    after = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_token_revoked_total"
    )
    assert after >= before + 1


async def test_admin_revoke_increments_revoked_counter(client_app):
    await seed_admin(client_app.storage)

    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 200
    access_token = resp.json()["access_token"]
    token_row = await client_app.storage.get_token_by_access_token(access_token)

    login_resp = await login_admin(client_app)
    assert login_resp.status_code == 303

    before = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_token_revoked_total"
    )

    revoke_resp = await client_app.post(f"/admin/api/tokens/{token_row.id}/revoke")
    assert revoke_resp.status_code == 200

    after = _metric_value(
        (await client_app.get("/metrics")).text, "oauth2_server_oauth_token_revoked_total"
    )
    assert after >= before + 1


# --- /health, /ready ----------------------------------------------------------


async def test_health_shape(client_app):
    resp = await client_app.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["service"] == "oauth2_server"
    assert "timestamp" in body


async def test_ready_success_shape(client_app):
    resp = await client_app.get("/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready", "checks": {"database": "ok"}}


async def test_ready_failure_returns_503_plain_text(client_app):
    async def _broken_healthcheck():
        raise RuntimeError("db is down")

    client_app.storage.healthcheck = _broken_healthcheck

    resp = await client_app.get("/ready")
    assert resp.status_code == 503
    assert resp.headers["content-type"].startswith("text/plain")
    assert "db is down" in resp.text
