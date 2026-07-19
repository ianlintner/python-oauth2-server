import pytest
from httpx import ASGITransport, AsyncClient

from oauth2_server.app import create_app
from oauth2_server.config import Config
from tests.helpers import make_storage


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
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_insecure_jwt_secret_rejected():
    with pytest.raises(ValueError):
        Config(jwt_secret="secret", issuer="x").validate_for_production()
