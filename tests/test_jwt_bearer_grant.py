"""RFC 7523 §2.1 JWT bearer authorization grant
(`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`).

Every validation failure must surface as 400 `invalid_grant` (RFC 7523 §3.1).
The trusted issuer's JWKS is served through a mocked transport so no network
is touched.
"""

from __future__ import annotations

import json
import time
import uuid

import httpx
import jwt
import pytest

from oauth2_server.models import TrustedIssuer
from oauth2_server.services.jwks_cache import JwksCache
from tests.conftest import build_client_app
from tests.helpers import generate_rsa_keypair, post_token, seed_client

BEARER_URN = "urn:ietf:params:oauth:grant-type:jwt-bearer"
EXT_ISS = "https://idp.example.org"
JWKS_URI = "https://idp.example.org/jwks.json"
AUD = "https://auth.example.com"


async def _setup(client_app, *, jwks: dict, **issuer_overrides):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks)

    client_app.app.state.jwks_cache = JwksCache(
        httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    await seed_client(
        client_app.storage,
        client_id="jb_client",
        client_secret="jb_secret",
        grant_types=json.dumps([BEARER_URN]),
        scope="read profile",
    )
    fields = {"id": uuid.uuid4().hex, "issuer": EXT_ISS, "jwks_uri": JWKS_URI}
    fields.update(issuer_overrides)
    await client_app.storage.save_trusted_issuer(TrustedIssuer(**fields))


def _assertion(key, *, kid="client-key-1", **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": EXT_ISS,
        "sub": "u1",
        "aud": AUD,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 60,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


async def _redeem(client_app, assertion: str, **extra):
    return await post_token(
        client_app,
        {"grant_type": BEARER_URN, "assertion": assertion, **extra},
        basic_auth=("jb_client", "jb_secret"),
    )


def _assert_invalid_grant(resp):
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_grant"


async def test_valid_assertion_issues_access_token(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    resp = await _redeem(client_app, _assertion(key))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["access_token"]
    assert body["scope"] == "read profile"
    assert "refresh_token" not in body
    row = await client_app.storage.get_token_by_access_token(body["access_token"])
    assert row is not None and row.user_id == "u1"


async def test_requested_scope_subset_honoured_and_excess_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    ok = await _redeem(client_app, _assertion(key), scope="read")
    assert ok.status_code == 200
    assert ok.json()["scope"] == "read"
    bad = await _redeem(client_app, _assertion(key), scope="read admin")
    assert bad.status_code == 400
    assert bad.json()["error"] == "invalid_scope"


async def test_bad_signature_rejected(client_app):
    _, jwks = generate_rsa_keypair()
    other_key, _ = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(other_key)))


async def test_unknown_issuer_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, iss="https://evil.example")))


async def test_disabled_issuer_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, enabled=False)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key)))


async def test_wrong_audience_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, aud="https://other.example")))


async def test_registry_allowed_audience_accepted(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, allowed_audiences=json.dumps(["https://api.example"]))
    resp = await _redeem(client_app, _assertion(key, aud="https://api.example"))
    assert resp.status_code == 200, resp.text


async def test_expired_assertion_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    now = int(time.time())
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, iat=now - 600, exp=now - 300)))


async def test_future_iat_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    now = int(time.time())
    _assert_invalid_grant(
        await _redeem(client_app, _assertion(key, iat=now + 3600, exp=now + 3660))
    )


async def test_missing_jti_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, jti=None)))


async def test_replayed_jti_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    assertion = _assertion(key, jti="fixed-jti")
    assert (await _redeem(client_app, assertion)).status_code == 200
    _assert_invalid_grant(await _redeem(client_app, assertion))


async def test_unknown_subject_without_jit_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, sub="nobody")))


async def test_jit_provision_creates_user(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, jit_provision=True)
    resp = await _redeem(client_app, _assertion(key, sub="fresh-user"))
    assert resp.status_code == 200, resp.text
    assert await client_app.storage.get_user_by_id("fresh-user") is not None


async def test_email_mapping_resolves_existing_user(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, subject_mapping="email")
    resp = await _redeem(client_app, _assertion(key, sub="ext-123", email="user_rfc@example.test"))
    assert resp.status_code == 200, resp.text
    row = await client_app.storage.get_token_by_access_token(resp.json()["access_token"])
    assert row is not None and row.user_id == "u1"


async def test_client_not_in_issuer_allow_list_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, allowed_client_ids=json.dumps(["someone_else"]))
    _assert_invalid_grant(await _redeem(client_app, _assertion(key)))


async def test_missing_assertion_is_invalid_request(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    resp = await post_token(
        client_app, {"grant_type": BEARER_URN}, basic_auth=("jb_client", "jb_secret")
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


async def test_malformed_assertion_rejected(client_app):
    _, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, "not-a-jwt"))


async def test_client_without_grant_is_unauthorized_client(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    await seed_client(
        client_app.storage,
        client_id="plain",
        client_secret="plain_secret",
        grant_types=json.dumps(["client_credentials"]),
    )
    resp = await post_token(
        client_app,
        {"grant_type": BEARER_URN, "assertion": _assertion(key)},
        basic_auth=("plain", "plain_secret"),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "unauthorized_client"


@pytest.mark.parametrize("path", ["/.well-known/openid-configuration"])
async def test_discovery_advertises_jwt_bearer(client_app, path):
    resp = await client_app.get(path)
    assert BEARER_URN in resp.json()["grant_types_supported"]


async def test_build_client_app_still_importable():
    # guards the shared fixture import used above
    async with build_client_app() as c:
        assert c.app is not None
