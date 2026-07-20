import pytest
from httpx import ASGITransport, AsyncClient

from oauth2_server.app import create_app
from oauth2_server.config import Config
from tests.helpers import make_storage, seed_client, seed_user, login_session


@pytest.fixture
async def client():
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    app = create_app(config, await make_storage())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://auth.example.com"
    ) as c:
        yield c


async def test_health(client):
    # Full shape coverage: tests/test_metrics.py::test_health_shape.
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_insecure_jwt_secret_rejected():
    with pytest.raises(ValueError):
        Config(jwt_secret="secret", issuer="x").validate_for_production()


def test_config_reads_env_vars(monkeypatch):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", "0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("OAUTH2_PUBLIC_URL", "https://issuer.test")
    monkeypatch.setenv("OAUTH2_ALLOWED_ORIGINS", "https://a.test, https://b.test")
    c = Config()
    assert c.issuer == "https://issuer.test"
    assert c.allowed_origins == ["https://a.test", "https://b.test"]


async def test_session_cookie_is_secure_by_default():
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    storage = await make_storage()
    await seed_client(storage)
    await seed_user(storage)
    app = create_app(config, storage)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://auth.example.com"
    ) as c:
        resp = await login_session(c)
        assert resp.status_code == 303
        set_cookie = resp.headers.get("set-cookie", "")
        assert "Secure" in set_cookie or "secure" in set_cookie


def test_build_uses_lifespan_not_on_event(monkeypatch):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", "unit-test-secret-not-for-production-0123456789abcdef")
    from oauth2_server.app import build

    app = build()
    assert app.router.on_startup == []  # deprecated hook list must be empty
    assert app.router.lifespan_context is not None
