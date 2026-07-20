from contextlib import asynccontextmanager

import pytest
from httpx import ASGITransport, AsyncClient

from oauth2_server.app import create_app
from oauth2_server.config import Config
from tests.helpers import make_storage, seed_client, seed_user


@asynccontextmanager
async def build_client_app(config_overrides: dict | None = None):
    """Build an app+client with the default seeded client1/user_rfc, honoring
    `config_overrides` on top of the standard unit-test Config."""
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
        **(config_overrides or {}),
    )
    storage = await make_storage()
    await seed_client(storage)
    await seed_user(storage)
    app = create_app(config, storage)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://auth.example.com"
    ) as c:
        c.storage = storage
        yield c


@pytest.fixture
async def client_app():
    async with build_client_app() as c:
        yield c


@pytest.fixture
async def app_with_session(client_app):
    """Alias for `client_app` — every app instance carries SessionMiddleware."""
    return client_app
