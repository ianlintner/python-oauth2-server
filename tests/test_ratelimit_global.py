"""`TokenBucketLimiter` (services/limiter.py) unit tests, the global per-IP
`RateLimitMiddleware` integration tests, and the `routes/token.py`
invalid_client penalty bucket HTTP tests.

Ported from `oauth2-ratelimit/src/in_memory.rs` + `token_bucket.rs` (unit
suite) and `tests/rfc9700_rate_limit.rs` (invalid_client HTTP suite), plus
the middleware tests Rust itself lacks (research doc `tests_to_port`: "no
Rust tests exist for RateLimitMiddleware itself"). See
`.superpowers/sdd/research-ratelimit-resilience.md` and
`.superpowers/sdd/task-2-brief.md`.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from httpx import ASGITransport, AsyncClient

from oauth2_server.app import create_app
from oauth2_server.config import Config
from oauth2_server.models import DenylistEntry
from oauth2_server.services.limiter import TokenBucketLimiter
from tests.conftest import build_client_app
from tests.helpers import make_storage, post_token, seed_client, seed_user

# ---------------------------------------------------------------------------
# TokenBucketLimiter (unit)
# ---------------------------------------------------------------------------


def test_new_bucket_starts_full_and_first_request_allowed():
    limiter = TokenBucketLimiter(max_requests=3, window_secs=60)
    result = limiter.check("k")
    assert result.allowed is True
    assert result.remaining == 2
    assert result.limit == 3
    assert result.retry_after is None


def test_rejects_after_limit_exceeded():
    limiter = TokenBucketLimiter(max_requests=3, window_secs=60)
    for _ in range(3):
        assert limiter.check("10.0.0.1").allowed is True

    result = limiter.check("10.0.0.1")
    assert result.allowed is False
    assert result.remaining == 0
    assert result.retry_after is not None
    assert result.retry_after > 0


def test_different_keys_are_independent():
    limiter = TokenBucketLimiter(max_requests=1, window_secs=900)
    assert limiter.check("user-a").allowed is True
    assert limiter.check("user-b").allowed is True
    assert limiter.check("user-a").allowed is False


def test_result_limit_echoes_configured_max():
    limiter = TokenBucketLimiter(max_requests=100, window_secs=60)
    result = limiter.check("k")
    assert result.limit == 100


def test_allows_requests_within_limit():
    limiter = TokenBucketLimiter(max_requests=5, window_secs=60)
    for _ in range(5):
        assert limiter.check("k").allowed is True


def test_window_secs_zero_clamped_to_one_no_infinity_refill():
    # No divide-by-zero, and no infinite-refill escape hatch: capacity 2
    # still rejects a 3rd near-instantaneous request.
    limiter = TokenBucketLimiter(max_requests=2, window_secs=0)
    assert limiter.window_secs == 1
    assert limiter.check("k").allowed is True
    assert limiter.check("k").allowed is True
    assert limiter.check("k").allowed is False


def test_max_requests_zero_clamped_to_one():
    limiter = TokenBucketLimiter(max_requests=0, window_secs=60)
    assert limiter.max_tokens == 1
    assert limiter.check("k").allowed is True
    result = limiter.check("k")
    assert result.allowed is False
    assert result.retry_after is not None
    assert result.retry_after > 0


def test_retry_after_bounded_for_small_bucket():
    # capacity 2 / window 60 -> refill rate 1 token per 30s; an empty bucket
    # needs at most 30s for its next token.
    limiter = TokenBucketLimiter(max_requests=2, window_secs=60)
    limiter.check("k")
    limiter.check("k")
    result = limiter.check("k")
    assert result.allowed is False
    assert 0 < result.retry_after <= 30


def test_idle_buckets_are_swept(monkeypatch):
    import oauth2_server.services.limiter as limiter_module

    real_monotonic = limiter_module.time.monotonic
    limiter = TokenBucketLimiter(max_requests=3, window_secs=60)
    for i in range(50):
        limiter.check(f"probe-{i}")
    assert len(limiter._buckets) == 50

    monkeypatch.setattr(limiter_module.time, "monotonic", lambda: real_monotonic() + 121)

    limiter.check("live")
    assert set(limiter._buckets) == {"live"}


# ---------------------------------------------------------------------------
# RateLimitMiddleware (global per-IP) — HTTP integration
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _build_client(config_overrides: dict | None = None, client_ip: str = "203.0.113.5"):
    overrides = {
        "jwt_secret": "unit-test-secret-not-for-production-0123456789abcdef",
        "issuer": "https://auth.example.com",
        **(config_overrides or {}),
    }
    config = Config(**overrides)
    storage = await make_storage()
    await seed_client(storage)
    await seed_user(storage)
    app = create_app(config, storage)
    async with AsyncClient(
        transport=ASGITransport(app=app, client=(client_ip, 123)),
        base_url="https://auth.example.com",
    ) as c:
        c.storage = storage
        c.app = app
        yield c


async def test_rate_limit_headers_absent_when_disabled(client_app):
    # Default config: rate_limit_enabled=False (Rust parity) -> no
    # middleware mounted at all, no x-ratelimit-* headers on any response.
    resp = await client_app.get("/health")
    assert resp.status_code == 200
    assert "x-ratelimit-limit" not in resp.headers


async def test_allowed_request_carries_lowercase_ratelimit_headers():
    async with _build_client({"rate_limit_enabled": True, "rate_limit_max_requests": 5}) as c:
        resp = await c.get("/health")  # exempt, doesn't touch the limiter
        assert "x-ratelimit-limit" not in resp.headers

        resp = await c.get("/oauth/.well-known-does-not-matter", follow_redirects=False)
        # Any non-exempt route triggers the limiter, even a 404.
        header_names = {name for name, _ in resp.headers.raw}
        assert b"x-ratelimit-limit" in header_names
        assert b"x-ratelimit-remaining" in header_names
        assert b"x-ratelimit-reset" in header_names
        assert resp.headers["x-ratelimit-limit"] == "5"


async def test_global_limit_429_body_and_headers():
    async with _build_client({"rate_limit_enabled": True, "rate_limit_max_requests": 2}) as c:
        for _ in range(2):
            resp = await c.get("/oauth/nonexistent")
            assert resp.status_code == 404

        resp = await c.get("/oauth/nonexistent")
        assert resp.status_code == 429
        body = resp.json()
        assert body["error"] == "too_many_requests"
        assert body["error_description"] == "Rate limit exceeded. Try again later."
        assert isinstance(body["retry_after"], int)
        assert body["retry_after"] >= 1
        assert int(resp.headers["retry-after"]) == body["retry_after"]
        assert resp.headers["x-ratelimit-limit"] == "2"
        assert resp.headers["x-ratelimit-remaining"] == "0"
        assert "x-ratelimit-reset" in resp.headers

        header_names = {name for name, _ in resp.headers.raw}
        assert b"X-RateLimit-Limit" in header_names
        assert b"X-RateLimit-Remaining" in header_names
        assert b"X-RateLimit-Reset" in header_names
        assert b"Retry-After" in header_names


async def test_global_limit_429_on_oauth_token_carries_no_store():
    # Matches the `DenylistGuard`-403 precedent (`test_denylist_middleware.py`
    # ::test_middleware_blocked_oauth_response_carries_security_headers`): a
    # rate-limited `/oauth*` response must not be cacheable either.
    async with _build_client({"rate_limit_enabled": True, "rate_limit_max_requests": 1}) as c:
        resp = await c.post("/oauth/token", data={"grant_type": "client_credentials"})
        assert resp.status_code != 429  # first request consumes the single-token bucket

        resp = await c.post("/oauth/token", data={"grant_type": "client_credentials"})
        assert resp.status_code == 429
        assert resp.headers["cache-control"] == "no-store"
        assert resp.headers["pragma"] == "no-cache"
        assert resp.headers["x-frame-options"] == "DENY"
        assert resp.headers["referrer-policy"] == "no-referrer"
        assert resp.headers["x-content-type-options"] == "nosniff"


async def test_global_limit_429_on_admin_api_carries_no_store():
    async with _build_client({"rate_limit_enabled": True, "rate_limit_max_requests": 1}) as c:
        resp = await c.get("/admin/api/users")
        assert resp.status_code != 429

        resp = await c.get("/admin/api/users")
        assert resp.status_code == 429
        assert resp.headers["cache-control"] == "no-store"


async def test_global_limit_429_off_oauth_admin_api_has_no_security_headers():
    # Negative case: a non-`/oauth*`/`/admin/api*` path's 429 does NOT gain
    # the security-header bundle -- the condition is genuinely path-scoped,
    # not applied unconditionally to every 429.
    async with _build_client({"rate_limit_enabled": True, "rate_limit_max_requests": 1}) as c:
        resp = await c.get("/auth/login")
        assert resp.status_code != 429

        resp = await c.get("/auth/login")
        assert resp.status_code == 429
        assert "cache-control" not in resp.headers


async def test_exempt_paths_bypass_rate_limit():
    async with _build_client({"rate_limit_enabled": True, "rate_limit_max_requests": 1}) as c:
        for _ in range(5):
            resp = await c.get("/health")
            assert resp.status_code == 200
        for _ in range(5):
            resp = await c.get("/ready")
            assert resp.status_code == 200
        for _ in range(5):
            resp = await c.get("/metrics")
            assert resp.status_code == 200


async def test_fail_open_on_backend_error():
    async with _build_client({"rate_limit_enabled": True, "rate_limit_max_requests": 1}) as c:

        def _broken_check(key):
            raise RuntimeError("limiter backend is down")

        c.app.state.rate_limiter.check = _broken_check

        resp = await c.get("/health")
        # /health is exempt regardless, so hit a non-exempt route instead.
        resp = await c.get("/oauth/nonexistent")
        assert resp.status_code == 404


async def test_denylisted_ip_does_not_consume_quota():
    async with _build_client(
        {"rate_limit_enabled": True, "rate_limit_max_requests": 3},
        client_ip="198.51.100.42",
    ) as c:
        await c.storage.add_denylist_entry(
            DenylistEntry(
                id="deny1",
                kind="ip",
                value="198.51.100.42",
                reason="test",
                created_at=datetime.now(timezone.utc),
            )
        )

        # Far more requests than the rate-limit budget — if RateLimitMiddleware
        # ran before DenylistGuard, some of these would flip to 429 instead of
        # staying 403 once the (shared) budget was exhausted.
        for _ in range(10):
            resp = await c.get("/oauth/nonexistent")
            assert resp.status_code == 403
            assert resp.json()["error"] == "access_denied"


async def test_trust_proxy_headers_uses_xff_first_entry():
    async with _build_client(
        {
            "rate_limit_enabled": True,
            "rate_limit_max_requests": 1,
            "trust_proxy_headers": True,
        }
    ) as c:
        resp = await c.get("/oauth/nonexistent", headers={"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
        assert resp.status_code == 404
        # Same underlying peer, different XFF first-entry -> independent bucket.
        resp = await c.get("/oauth/nonexistent", headers={"X-Forwarded-For": "9.9.9.9"})
        assert resp.status_code == 404
        # Reusing the first XFF value again now hits the exhausted bucket.
        resp = await c.get("/oauth/nonexistent", headers={"X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
        assert resp.status_code == 429


async def test_ignores_xff_when_trust_proxy_headers_disabled():
    async with _build_client(
        {
            "rate_limit_enabled": True,
            "rate_limit_max_requests": 1,
            "trust_proxy_headers": False,
        }
    ) as c:
        resp = await c.get("/oauth/nonexistent", headers={"X-Forwarded-For": "1.2.3.4"})
        assert resp.status_code == 404
        # Different XFF, SAME peer -> shares the peer-keyed bucket, already
        # exhausted by the request above.
        resp = await c.get("/oauth/nonexistent", headers={"X-Forwarded-For": "9.9.9.9"})
        assert resp.status_code == 429


async def test_rate_limit_metrics_wired():
    async with _build_client({"rate_limit_enabled": True, "rate_limit_max_requests": 1}) as c:
        await c.get("/oauth/nonexistent")
        resp = await c.get("/oauth/nonexistent")
        assert resp.status_code == 429

        body = (await c.get("/metrics")).text
        assert "oauth2_server_rate_limit_rejected_total{" in body
        assert "oauth2_server_rate_limit_remaining_bucket{" in body


# ---------------------------------------------------------------------------
# invalid_client penalty bucket (routes/token.py) — HTTP integration
# ---------------------------------------------------------------------------


async def test_invalid_client_returns_429_after_budget_exhausted():
    async with build_client_app({"rate_limit_invalid_client_max_requests": 3}) as c:
        for _ in range(3):
            resp = await post_token(
                c, {"grant_type": "client_credentials"}, basic_auth=("client1", "WRONG")
            )
            assert resp.status_code == 401
            assert resp.json()["error"] == "invalid_client"

        resp = await post_token(
            c, {"grant_type": "client_credentials"}, basic_auth=("client1", "WRONG")
        )
        assert resp.status_code == 429
        # capacity 3 / window 60s -> refill rate 1 token per 20s.
        assert resp.json() == {
            "error": "too_many_requests",
            "error_description": "Too many failed authentication attempts. Retry after 20s.",
            "error_uri": None,
        }
        assert "retry-after" not in resp.headers


async def test_invalid_client_no_limiter_returns_401():
    async with build_client_app({"rate_limit_invalid_client_max_requests": 0}) as c:
        assert c.app.state.invalid_client_limiter is None
        for _ in range(10):
            resp = await post_token(
                c, {"grant_type": "client_credentials"}, basic_auth=("client1", "WRONG")
            )
            assert resp.status_code == 401
            assert resp.json()["error"] == "invalid_client"


async def test_invalid_client_buckets_isolated_per_client_id():
    async with build_client_app({"rate_limit_invalid_client_max_requests": 2}) as c:
        await seed_client(
            c.storage, client_id="client_iso_b", client_secret="s3cret-b", name="iso-b"
        )

        for _ in range(2):
            resp = await post_token(
                c, {"grant_type": "client_credentials"}, basic_auth=("client1", "WRONG")
            )
            assert resp.status_code == 401
        resp = await post_token(
            c, {"grant_type": "client_credentials"}, basic_auth=("client1", "WRONG")
        )
        assert resp.status_code == 429

        # A different client_id's own bucket is untouched.
        resp = await post_token(
            c, {"grant_type": "client_credentials"}, basic_auth=("client_iso_b", "WRONG")
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"


async def test_valid_requests_do_not_deplete_invalid_client_bucket():
    async with build_client_app({"rate_limit_invalid_client_max_requests": 1}) as c:
        for _ in range(5):
            resp = await post_token(
                c, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
            )
            assert resp.status_code == 200

        # The bucket (capacity 1) is still full: the first-ever failure
        # still gets a plain 401, not a 429.
        resp = await post_token(
            c, {"grant_type": "client_credentials"}, basic_auth=("client1", "WRONG")
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"


async def test_invalid_client_penalty_from_public_client_check():
    async with build_client_app({"rate_limit_invalid_client_max_requests": 2}) as c:
        await seed_client(
            c.storage,
            client_id="public-client",
            client_secret="",
            token_endpoint_auth_method="none",
            name="public",
        )

        for _ in range(2):
            resp = await post_token(
                c, {"grant_type": "client_credentials", "client_id": "public-client"}
            )
            assert resp.status_code == 401
            assert resp.json()["error"] == "invalid_client"

        resp = await post_token(
            c, {"grant_type": "client_credentials", "client_id": "public-client"}
        )
        assert resp.status_code == 429
        assert resp.json()["error"] == "too_many_requests"
