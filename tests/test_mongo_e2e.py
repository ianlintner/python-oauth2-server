"""MongoDB backend end-to-end HTTP tests — proves the full FastAPI app (real
routes, real ASGI request/response cycle) behaves identically when `Storage`
is backed by `MongoStorage` instead of `SqlStorage`.

Unlike `tests/test_mongo_storage.py`/`tests/test_mongo_admin.py` (which call
`MongoStorage` methods directly), this drives the same flows the Rust
`mongo_parity_smoke` proof drives, over real HTTP via httpx's ASGI
transport: client_credentials -> introspect, then a full
authorization_code -> exchange -> refresh -> refresh-replay sequence that
specifically proves divergence 28 (`revoke_token_family` actually cascades
on Mongo through the real `routes/token.py` refresh-rotation code path,
unlike Rust's silently-no-op trait default). A second test proves the
denylist path (divergence 29) blocks a request with a real 403 through
`middleware.py::DenylistGuard`, not just a storage-layer lookup.

Self-skips (module-level) unless `RUN_TESTCONTAINERS=1` is set AND
motor/testcontainers are importable — same gate as `tests/test_mongo_storage.
py`; see that file's docstring for why. A real mongod is started once per
module via testcontainers; each test builds its own database (via
`tests.helpers.build_mongo_client_app`) so state can't leak across tests.
"""

from __future__ import annotations

import base64
import os
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest

RUN_TESTCONTAINERS = os.environ.get("RUN_TESTCONTAINERS") == "1"

try:
    import motor.motor_asyncio  # noqa: F401
    from testcontainers.mongodb import MongoDbContainer

    _DEPS_ERROR: Exception | None = None
except ImportError as e:  # pragma: no cover - exercised when deps missing
    MongoDbContainer = None  # type: ignore[assignment,misc]
    _DEPS_ERROR = e

pytestmark = pytest.mark.skipif(
    not RUN_TESTCONTAINERS or _DEPS_ERROR is not None,
    reason=(
        "set RUN_TESTCONTAINERS=1 (with motor + testcontainers installed) to run "
        "the MongoStorage end-to-end app test against a real mongod"
    ),
)

from httpx import ASGITransport, AsyncClient  # noqa: E402

from oauth2_server.app import create_app  # noqa: E402
from oauth2_server.config import Config  # noqa: E402
from oauth2_server.models import DenylistEntry  # noqa: E402
from tests.helpers import build_mongo_client_app, login_session, post_token  # noqa: E402


def _pkce_pair() -> tuple[str, str]:
    import hashlib
    import secrets

    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.rstrip(b"=").decode()


def _query(location: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}


async def _basic(client_app, path: str, data: dict, client_id="client1", client_secret="s3cret"):
    raw = f"{client_id}:{client_secret}".encode()
    headers = {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    return await client_app.post(path, data=data, headers=headers)


async def _issue_authorization_code(client_app) -> tuple[str, str]:
    """Log in, hit GET /oauth/authorize with PKCE, return (code, verifier)."""
    await login_session(client_app)
    verifier, challenge = _pkce_pair()
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "openid email",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 302, resp.text
    return _query(resp.headers["location"])["code"], verifier


@pytest.fixture(scope="module")
def _mongo_container():
    with MongoDbContainer("mongo:7.0") as mongo:
        yield mongo


def _mongo_uri(container, db_name: str) -> str:
    host = container.get_container_host_ip()
    port = container.get_exposed_port(container.port)
    return (
        f"mongodb://{container.username}:{container.password}"
        f"@{host}:{port}/{db_name}?authSource=admin"
    )


async def test_mongo_e2e_client_credentials_then_introspect(_mongo_container):
    db_name = f"oauth2_e2e_{uuid.uuid4().hex[:10]}"
    async with build_mongo_client_app(_mongo_uri(_mongo_container, db_name)) as app:
        resp = await _basic(app, "/oauth/token", {"grant_type": "client_credentials"})
        assert resp.status_code == 200, resp.text
        access_token = resp.json()["access_token"]

        introspect = await _basic(app, "/oauth/introspect", {"token": access_token})
        assert introspect.status_code == 200, introspect.text
        assert introspect.json()["active"] is True

        await app.storage._client.drop_database(db_name)
        app.storage._client.close()


async def test_mongo_e2e_auth_code_refresh_and_family_cascade(_mongo_container):
    """The core divergence-28 proof: an authorization_code -> token exchange
    -> refresh -> refresh-REPLAY sequence over real HTTP against MongoStorage,
    asserting the replay both gets rejected AND actually revokes the sibling
    (rotated-in) token via `revoke_token_family`'s Mongo `update_many` — not
    a silent no-op like Rust's Mongo backend.
    """
    db_name = f"oauth2_e2e_{uuid.uuid4().hex[:10]}"
    async with build_mongo_client_app(_mongo_uri(_mongo_container, db_name)) as app:
        code, verifier = await _issue_authorization_code(app)
        resp1 = await post_token(
            app,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://a.example/cb",
                "client_id": "client1",
                "code_verifier": verifier,
            },
            basic_auth=("client1", "s3cret"),
        )
        assert resp1.status_code == 200, resp1.text
        body1 = resp1.json()
        access_token1 = body1["access_token"]
        refresh_token1 = body1["refresh_token"]
        assert access_token1 and refresh_token1

        introspect1 = await _basic(app, "/oauth/introspect", {"token": access_token1})
        assert introspect1.status_code == 200, introspect1.text
        assert introspect1.json()["active"] is True

        # Refresh once: rotates to a new access/refresh token pair in the
        # same token_family.
        resp2 = await post_token(
            app,
            {"grant_type": "refresh_token", "refresh_token": refresh_token1},
            basic_auth=("client1", "s3cret"),
        )
        assert resp2.status_code == 200, resp2.text
        body2 = resp2.json()
        access_token2 = body2["access_token"]
        refresh_token2 = body2["refresh_token"]
        assert refresh_token2 != refresh_token1

        introspect2 = await _basic(app, "/oauth/introspect", {"token": access_token2})
        assert introspect2.status_code == 200, introspect2.text
        assert introspect2.json()["active"] is True, (
            "the freshly-rotated access token must be active"
        )

        # REPLAY the old (rotated-out) refresh token: rejected as invalid_grant,
        # AND — this is divergence 28 — the entire family gets revoked.
        resp3 = await post_token(
            app,
            {"grant_type": "refresh_token", "refresh_token": refresh_token1},
            basic_auth=("client1", "s3cret"),
        )
        assert resp3.status_code == 400, resp3.text
        assert resp3.json()["error"] == "invalid_grant"

        # Introspect the SIBLING token (access_token2, minted by the
        # legitimate refresh before the replay) — it must now be inactive.
        # Rust's Mongo backend leaves `revoke_token_family` as a no-op, so
        # this assertion is precisely what would fail on that backend.
        sibling_introspect = await _basic(app, "/oauth/introspect", {"token": access_token2})
        assert sibling_introspect.status_code == 200, sibling_introspect.text
        assert sibling_introspect.json()["active"] is False, (
            "refresh-token replay must cascade-revoke the whole token_family on Mongo "
            "(divergence 28) — a sibling token from the same family must go inactive"
        )

        await app.storage._client.drop_database(db_name)
        app.storage._client.close()


async def test_mongo_e2e_denylist_blocks_request(_mongo_container):
    """Divergence 29: denylist storage is implemented on Mongo (Rust stubs it
    as a no-op returning False from `supports_denylist()`). Adds a denylist
    entry directly via `MongoStorage.add_denylist_entry`, then proves
    `DenylistGuard` (the ASGI middleware mounted on every route) actually
    rejects a request from that IP with a real 403 — not just a storage-layer
    `find_denylist_entry` lookup.
    """
    db_name = f"oauth2_e2e_{uuid.uuid4().hex[:10]}"
    from oauth2_server.storage.mongo import MongoStorage

    uri = _mongo_uri(_mongo_container, db_name)
    storage = MongoStorage(uri)
    await storage.init()

    blocked_ip = "198.51.100.77"
    entry = DenylistEntry(
        id=uuid.uuid4().hex,
        kind="ip",
        value=blocked_ip,
        reason="e2e mongo denylist smoke",
        created_at=datetime.now(timezone.utc),
    )
    await storage.add_denylist_entry(entry)

    # Storage-level: find_denylist_entry sees it as active.
    found = await storage.find_denylist_entry("ip", blocked_ip)
    assert found is not None
    assert found.reason == "e2e mongo denylist smoke"

    # App-level: a real request from that IP is rejected by DenylistGuard.
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    app = create_app(config, storage)
    async with AsyncClient(
        transport=ASGITransport(app=app, client=(blocked_ip, 123)),
        base_url="https://auth.example.com",
    ) as blocked_client:
        resp = await blocked_client.get("/health")
        assert resp.status_code == 403
        assert resp.json() == {
            "error": "access_denied",
            "error_description": "request source is denylisted",
        }

    # A different IP is unaffected.
    async with AsyncClient(
        transport=ASGITransport(app=app, client=("203.0.113.9", 123)),
        base_url="https://auth.example.com",
    ) as allowed_client:
        resp = await allowed_client.get("/health")
        assert resp.status_code == 200

    await storage._client.drop_database(db_name)
    storage._client.close()
