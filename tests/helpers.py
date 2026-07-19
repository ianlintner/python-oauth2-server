import base64
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from oauth2_server import security
from oauth2_server.models import Client, User
from oauth2_server.storage.sql import SqlStorage

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations" / "sql"


async def make_storage() -> SqlStorage:
    s = SqlStorage("sqlite+aiosqlite://", MIGRATIONS)
    await s.init()
    return s


async def seed_client(storage, **overrides) -> Client:
    now = datetime.now(timezone.utc)
    fields = dict(
        id=uuid.uuid4().hex,
        client_id="client1",
        client_secret="s3cret",
        redirect_uris=json.dumps(["https://a.example/cb"]),
        grant_types=json.dumps(["authorization_code", "client_credentials", "refresh_token"]),
        scope="read openid email profile",
        name="test-client",
        created_at=now,
        updated_at=now,
        token_endpoint_auth_method="client_secret_basic",
    )
    fields.update(overrides)
    client = Client(**fields)
    await storage.save_client(client)
    return client


async def seed_user(storage) -> User:
    user = User(
        id="u1",
        username="user_rfc",
        email="user_rfc@example.test",
        password_hash=security.hash_password("password123"),
    )
    await storage.save_user(user)
    return user


async def post_token(client_app, data: dict, basic_auth: tuple[str, str] | None = None):
    headers = {}
    if basic_auth is not None:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    return await client_app.post("/oauth/token", data=data, headers=headers)
