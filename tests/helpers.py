import base64
import json
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from oauth2_server import security
from oauth2_server.models import Client, User
from oauth2_server.storage.sql import SqlStorage

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations" / "sql"

# The `issuer` every test app is built with (`tests.conftest.build_client_app`)
# plus `/oauth/token` — RFC 7523 §3 assertions are audienced at the TOKEN
# endpoint at every endpoint that authenticates a client, so this is the
# expected `aud` for introspect/revoke/PAR too.
TOKEN_ENDPOINT = "https://auth.example.com/oauth/token"

# A fixed PKCE pair (RFC 7636 Appendix B) for tests where PKCE is incidental:
# every client, confidential included, must present one (RFC 9700 §2.1.1).
PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def make_client_assertion(
    client_id: str,
    key,
    alg: str,
    aud: str = TOKEN_ENDPOINT,
    headers: dict | None = None,
    **claim_overrides,
) -> str:
    """Build a signed RFC 7523 client assertion.

    Any claim passed as `None` in `claim_overrides` is *removed* from the
    payload, which is how the "missing jti" case in
    `tests/test_client_assertion.py` is constructed.
    """
    now = int(time.time())
    claims: dict = {
        "iss": client_id,
        "sub": client_id,
        "aud": aud,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 60,
    }
    claims.update(claim_overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers=headers)


def generate_rsa_keypair(kid: str = "client-key-1") -> tuple[bytes, dict]:
    """Return `(private_key_pem, jwks_document)` for a fresh RS256 keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk["kid"] = kid
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    return pem, {"keys": [public_jwk]}


async def make_storage() -> SqlStorage:
    s = SqlStorage("sqlite+aiosqlite://", MIGRATIONS)
    await s.init()
    return s


@asynccontextmanager
async def build_mongo_client_app(uri: str, config_overrides: dict | None = None):
    """Mongo analogue of `tests.conftest.build_client_app`: build a full
    FastAPI app on `MongoStorage` bound to a real mongod at `uri`, seed the
    same `client1`/`user_rfc` fixtures the SQL path uses, and yield an httpx
    ASGI client carrying `.storage`/`.app` — used by the
    `RUN_TESTCONTAINERS=1`-gated Mongo end-to-end tests
    (`tests/test_mongo_e2e.py`, `tests/test_rfc_compliance.py::
    test_mongo_backend_storage_contract`).

    `MongoStorage` (and `create_app`/`Config`/httpx) are imported lazily
    inside this function, not at module level — `motor` is an optional
    dependency (`pip install oauth2-server[mongo]`), so importing
    `tests.helpers` itself (which every test module in the suite does,
    directly or transitively) must never require it. Callers are
    responsible for gating on `RUN_TESTCONTAINERS=1` (+ motor/testcontainers
    importability) before calling this — see the module docstring of
    `tests/test_mongo_storage.py` for the shared gating pattern.
    """
    from httpx import ASGITransport, AsyncClient

    from oauth2_server.app import create_app
    from oauth2_server.config import Config
    from oauth2_server.storage.mongo import MongoStorage

    storage = MongoStorage(uri)
    await storage.init()
    await seed_client(storage)
    await seed_user(storage)

    overrides = {
        "jwt_secret": "unit-test-secret-not-for-production-0123456789abcdef",
        "issuer": "https://auth.example.com",
        "dynamic_registration_enabled": True,
        **(config_overrides or {}),
    }
    config = Config(**overrides)
    app = create_app(config, storage)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://auth.example.com"
    ) as c:
        c.storage = storage
        c.app = app
        yield c


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
    extra_claims: dict | None = None,
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

    `extra_claims` merges arbitrary extra payload claims over the defaults —
    used by `tests/test_userinfo_dpop.py` to attach the `ath` claim a
    resource-server proof needs (divergence 50).
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
    if extra_claims:
        claims.update(extra_claims)
    proof = jwt.encode(
        claims, private_pem, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public_jwk}
    )
    return proof, public_jwk
