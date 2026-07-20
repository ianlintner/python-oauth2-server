"""Login rate limiting — `FixedWindowLimiter` (services/ratelimit.py) unit
tests plus `POST /auth/login` integration tests.

Ported from `crates/oauth2-actix/src/handlers/login.rs::LoginRateLimiter`
(10 attempts / 15 minutes, keyed `login:ip:{ip}` and `login:user:{username}`,
blocked -> 303 `/auth/login?error=too_many_attempts` + `Retry-After` header).
The Rust limiter is a token bucket with no reset-on-success; this port uses a
simpler fixed window and resets only the per-username key on a successful
login — the per-IP key deliberately survives success so one valid credential
can't be used to keep clearing the IP throttle while stuffing other accounts
(see `services/ratelimit.py` module docstring and `routes/login.py`) — a
deliberate, documented deviation from strict Rust parity.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from httpx import ASGITransport, AsyncClient

import oauth2_server.routes.login as login_routes
from oauth2_server.app import create_app
from oauth2_server.config import Config
from oauth2_server.services.ratelimit import FixedWindowLimiter
from tests.helpers import make_storage, seed_admin, seed_client, seed_user

# ---------------------------------------------------------------------------
# FixedWindowLimiter (unit)
# ---------------------------------------------------------------------------


def test_limiter_blocks_after_max_attempts():
    limiter = FixedWindowLimiter(max_attempts=10, window_secs=900)
    for _ in range(10):
        assert limiter.check("k") is None

    retry_after = limiter.check("k")
    assert retry_after is not None
    assert retry_after > 0


def test_limiter_window_expires(monkeypatch):
    import oauth2_server.services.ratelimit as ratelimit_module

    real_monotonic = ratelimit_module.time.monotonic
    limiter = FixedWindowLimiter(max_attempts=10, window_secs=900)
    for _ in range(10):
        assert limiter.check("k") is None
    assert limiter.check("k") is not None

    monkeypatch.setattr(ratelimit_module.time, "monotonic", lambda: real_monotonic() + 901)

    assert limiter.check("k") is None


def test_limiter_reset_clears_key():
    limiter = FixedWindowLimiter(max_attempts=10, window_secs=900)
    for _ in range(10):
        assert limiter.check("k") is None
    assert limiter.check("k") is not None

    limiter.reset("k")

    assert limiter.check("k") is None


def test_limiter_keys_are_independent():
    limiter = FixedWindowLimiter(max_attempts=1, window_secs=900)
    assert limiter.check("a") is None
    assert limiter.check("b") is None
    assert limiter.check("a") is not None


def test_expired_windows_are_swept(monkeypatch):
    """Keys touched once must not leak: any later check() sweeps them out."""
    import oauth2_server.services.ratelimit as ratelimit_module

    real_monotonic = ratelimit_module.time.monotonic
    limiter = FixedWindowLimiter(max_attempts=10, window_secs=900)
    for i in range(50):
        assert limiter.check(f"probe-{i}") is None
    assert len(limiter._windows) == 50

    monkeypatch.setattr(ratelimit_module.time, "monotonic", lambda: real_monotonic() + 901)

    # One check on a fresh key prunes every expired window dict-wide.
    assert limiter.check("live") is None
    assert set(limiter._windows) == {"live"}


# ---------------------------------------------------------------------------
# POST /auth/login integration
# ---------------------------------------------------------------------------


async def test_login_blocked_after_repeated_failures(client_app, monkeypatch):
    calls = []

    async def spy_verify_password_async(password, phc_hash):
        calls.append(password)
        return False

    monkeypatch.setattr(login_routes, "verify_password_async", spy_verify_password_async)

    for _ in range(10):
        resp = await client_app.post(
            "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/auth/login?error=invalid_credentials"
    assert len(calls) == 10

    resp = await client_app.post(
        "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/auth/login?error=too_many_attempts"
    assert int(resp.headers["retry-after"]) > 0
    # The blocked attempt must short-circuit before credential verification.
    assert len(calls) == 10


async def test_login_success_resets_user_key():
    """Success clears the per-username window (proven from a fresh IP, so the
    surviving per-IP window can't confound the assertion)."""
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    storage = await make_storage()
    await seed_client(storage)
    await seed_user(storage)
    app = create_app(config, storage)

    async with _build_client_from_ip(app, "10.1.0.1") as client_a:
        # 9 failures + 1 success = 10 user-key checks; without the reset the
        # next user_rfc attempt (the 11th) would be blocked.
        for _ in range(9):
            resp = await client_a.post(
                "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
            )
            assert resp.headers["location"] == "/auth/login?error=invalid_credentials"
        good = await client_a.post(
            "/auth/login", data={"username": "user_rfc", "password": "password123"}
        )
        assert good.status_code == 303
        assert good.headers["location"] == "/"

    async with _build_client_from_ip(app, "10.1.0.2") as client_b:
        resp = await client_b.post(
            "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
        )
        assert resp.headers["location"] == "/auth/login?error=invalid_credentials"


async def test_success_does_not_reset_ip_counter():
    """An attacker with one valid credential must not be able to clear the
    per-IP throttle by logging into their own account between stuffing runs."""
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    storage = await make_storage()
    await seed_client(storage)
    await seed_user(storage)
    await seed_admin(storage)
    app = create_app(config, storage)

    async with _build_client_from_ip(app, "10.2.0.1") as client:
        # 9 failed probes against one account, then a successful login to the
        # attacker's own account from the same IP (10th IP-key check).
        for _ in range(9):
            resp = await client.post(
                "/auth/login", data={"username": "admin_rfc", "password": "wrong-password"}
            )
            assert resp.headers["location"] == "/auth/login?error=invalid_credentials"
        good = await client.post(
            "/auth/login", data={"username": "user_rfc", "password": "password123"}
        )
        assert good.status_code == 303
        assert good.headers["location"] == "/"

        # The IP window survived the success: the 11th attempt from this IP is
        # blocked even though it targets a different username.
        blocked = await client.post(
            "/auth/login", data={"username": "someone_else", "password": "x"}
        )
        assert blocked.status_code == 303
        assert blocked.headers["location"] == "/auth/login?error=too_many_attempts"
        assert int(blocked.headers["retry-after"]) > 0


@asynccontextmanager
async def _build_client_from_ip(app, client_ip: str):
    """Like `tests.test_denylist_middleware.build_client_from_ip`, but reuses
    a caller-supplied `app` (rather than building its own) so multiple
    clients pinned to different source IPs can share the same
    `app.state.login_limiter`."""
    async with AsyncClient(
        transport=ASGITransport(app=app, client=(client_ip, 123)),
        base_url="https://auth.example.com",
    ) as c:
        yield c


async def test_login_rate_limit_keys_are_per_username():
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    storage = await make_storage()
    await seed_client(storage)
    await seed_user(storage)
    await seed_admin(storage)
    app = create_app(config, storage)

    # Exhaust both the per-IP (10.0.0.9) and per-username (user_rfc) limiter
    # keys with repeated failures.
    async with _build_client_from_ip(app, "10.0.0.9") as client_a:
        for _ in range(10):
            resp = await client_a.post(
                "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
            )
            assert resp.status_code == 303
        blocked = await client_a.post(
            "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
        )
        assert blocked.headers["location"] == "/auth/login?error=too_many_attempts"

    # A different user, from a different IP, hits neither exhausted key —
    # their correct-password login succeeds normally.
    async with _build_client_from_ip(app, "10.0.0.10") as client_b:
        good = await client_b.post(
            "/auth/login", data={"username": "admin_rfc", "password": "password123"}
        )

    assert good.status_code == 303
    assert good.headers["location"] == "/"
