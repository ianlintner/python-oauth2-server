import base64
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

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
        grant_types=json.dumps(
            [
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ]
        ),
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


async def reseed_client(client_app, **overrides) -> Client:
    """Delete and re-save `client1` with `overrides` layered on top of the
    `seed_client` defaults. Useful for tests that need `client1` to have a
    narrower `grant_types` allow-list than the default. `grant_types` may be
    passed as a plain list (it will be JSON-encoded automatically)."""
    if isinstance(overrides.get("grant_types"), list):
        overrides["grant_types"] = json.dumps(overrides["grant_types"])
    storage = client_app.storage
    await storage.delete_client("client1")
    return await seed_client(storage, **overrides)


async def seed_user(storage) -> User:
    user = User(
        id="u1",
        username="user_rfc",
        email="user_rfc@example.test",
        password_hash=security.hash_password("password123"),
    )
    await storage.save_user(user)
    return user


async def seed_admin(storage) -> User:
    user = User(
        id="admin1",
        username="admin_rfc",
        email="admin_rfc@example.test",
        password_hash=security.hash_password("password123"),
        role="admin",
    )
    await storage.save_user(user)
    return user


async def login_session(client, username: str = "user_rfc", password: str = "password123"):
    """POST /auth/login and let the httpx client carry the resulting session cookie."""
    return await client.post("/auth/login", data={"username": username, "password": password})


async def login_admin(client):
    """POST /auth/login as the seeded admin user from `seed_admin`."""
    return await login_session(client, username="admin_rfc", password="password123")


async def post_token(
    client_app, data: dict, basic_auth: tuple[str, str] | None = None, headers: dict | None = None
):
    request_headers = dict(headers or {})
    if basic_auth is not None:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
        request_headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    return await client_app.post("/oauth/token", data=data, headers=request_headers)


def _b64u_fixed(value: int, length: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def generate_dpop_key() -> tuple[bytes, dict]:
    """Generate an ES256 (P-256) keypair for DPoP proof tests.

    Returns `(private_key_pem, public_jwk)` — factored out of the
    ES256-keypair generation duplicated in `tests/test_dpop.py`'s
    `_generate_ec_keypair` so `make_dpop_proof` below (and any test that
    needs the SAME key across multiple proofs, e.g. a nonce bootstrap
    round-trip) can share one implementation.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u_fixed(numbers.x, 32),
        "y": _b64u_fixed(numbers.y, 32),
    }
    return pem, jwk


def make_dpop_proof(
    url: str,
    method: str,
    key: tuple[bytes, dict] | None = None,
    nonce: str | None = None,
    *,
    jti: str | None = None,
    iat: float | None = None,
) -> tuple[str, dict]:
    """Build a real, signed ES256 DPoP proof JWT for `method` + `url`.

    `key` is an optional pre-generated `(private_key_pem, public_jwk)` pair
    from `generate_dpop_key` — pass the same key across two calls to reuse
    one DPoP key for a nonce-bootstrap round trip (first proof rejected for
    a missing nonce, second proof from the SAME key embeds the fresh
    nonce). When omitted, a fresh key is generated per call. Returns
    `(proof, public_jwk)` so callers can independently compute the expected
    `jkt` thumbprint (`oauth2_server.services.dpop.jwk_thumbprint`) without
    threading the key back out separately.
    """
    if key is None:
        key = generate_dpop_key()
    private_pem, public_jwk = key
    claims = {
        "htm": method,
        "htu": url,
        "iat": int(iat if iat is not None else time.time()),
        "jti": jti or uuid.uuid4().hex,
    }
    if nonce is not None:
        claims["nonce"] = nonce
    proof = jwt.encode(
        claims, private_pem, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public_jwk}
    )
    return proof, public_jwk
