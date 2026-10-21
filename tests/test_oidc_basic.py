"""OIDC basic profile (contract v0.3 `oidc-basic`, stable scenarios) end to end.

Drives the real `build()` factory in conformance test mode, mirroring the
black-box runner's login -> authorize -> token -> userinfo flow, plus negative
and security cases the contract does not assert.
"""

import base64
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from httpx import ASGITransport, AsyncClient

from oauth2_server.app import build
from tests.helpers import PKCE_CHALLENGE, PKCE_VERIFIER

SECRET = "unit-test-secret-not-for-production-0123456789abcdef"
ISSUER = "http://localhost:8080"
CALLBACK = "https://client.example/callback"
SEED = """
issuer: http://localhost:8080
clients:
  - client_id: client-a
    client_secret: test-only-secret
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: [https://client.example/callback]
    grant_types: [authorization_code, refresh_token]
  - client_id: client-cc
    client_secret: test-only-cc-secret
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: [https://client.example/callback]
    grant_types: [client_credentials]
users:
  - username: alice
    password: test-only-password
    auto_approve_clients: [client-a]
"""


def _basic(cid: str, secret: str) -> dict[str, str]:
    raw = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    return {"authorization": f"Basic {raw}"}


@pytest.fixture
async def oidc_client(monkeypatch, tmp_path):
    seed = tmp_path / "seed.yaml"
    seed.write_text(SEED, encoding="utf-8")
    monkeypatch.setenv("OAUTH2_JWT_SECRET", SECRET)
    monkeypatch.setenv("OAUTH2_CONFORMANCE_MODE", "1")
    monkeypatch.setenv("OAUTH2_CONFORMANCE_SEED", str(seed))
    monkeypatch.setenv("OAUTH2_ENV", "test")
    monkeypatch.delenv("OAUTH2_DATABASE_URL", raising=False)
    app = build()
    async with (
        app.router.lifespan_context(app),
        AsyncClient(transport=ASGITransport(app=app), base_url=ISSUER) as client,
    ):
        yield client


async def _login_cookie(client: AsyncClient, params: dict[str, str]) -> str:
    first = await client.get("/oauth/authorize", params=params)
    cookie = first.headers["set-cookie"].split(";", 1)[0]
    login = await client.post(
        "/auth/login",
        data={"username": "alice", "password": "test-only-password"},
        headers={"cookie": cookie},
    )
    assert login.status_code == 303
    return login.headers["set-cookie"].split(";", 1)[0]


async def _code_exchange(client: AsyncClient, scope: str, nonce: str | None = None) -> dict:
    params = {
        "response_type": "code",
        "client_id": "client-a",
        "redirect_uri": CALLBACK,
        "scope": scope,
        "state": "s1",
        "code_challenge": PKCE_CHALLENGE,
        "code_challenge_method": "S256",
    }
    if nonce is not None:
        params["nonce"] = nonce
    cookie = await _login_cookie(client, params)
    final = await client.get("/oauth/authorize", params=params, headers={"cookie": cookie})
    assert final.status_code == 302
    code = parse_qs(urlparse(final.headers["location"]).query)["code"][0]
    resp = await client.post(
        "/oauth/token",
        headers=_basic("client-a", "test-only-secret"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CALLBACK,
            "code_verifier": PKCE_VERIFIER,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _claims(id_token: str) -> dict:
    return jwt.decode(id_token, options={"verify_signature": False})


async def test_openid_scope_returns_compact_jwt_id_token_with_core_claims(oidc_client):
    body = await _code_exchange(oidc_client, "openid", nonce="n-123")
    assert body["id_token"].count(".") == 2
    claims = _claims(body["id_token"])
    assert claims["iss"] == ISSUER
    assert claims["sub"]
    assert "client-a" in (claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]])
    assert claims["exp"] > claims["iat"]
    assert claims["nonce"] == "n-123"


async def test_no_id_token_without_openid_scope(oidc_client):
    body = await _code_exchange(oidc_client, "read")
    assert "id_token" not in body


async def test_id_token_iss_equals_discovery_issuer(oidc_client):
    body = await _code_exchange(oidc_client, "openid")
    disc = (await oidc_client.get("/.well-known/openid-configuration")).json()
    assert _claims(body["id_token"])["iss"] == disc["issuer"]
    assert disc["userinfo_endpoint"] == f"{ISSUER}/oauth/userinfo"


async def test_userinfo_sub_matches_id_token_sub(oidc_client):
    body = await _code_exchange(oidc_client, "openid")
    resp = await oidc_client.get(
        "/oauth/userinfo", headers={"authorization": f"Bearer {body['access_token']}"}
    )
    assert resp.status_code == 200
    assert resp.json()["sub"] == _claims(body["id_token"])["sub"]


async def test_userinfo_without_token_is_401_with_bearer_challenge(oidc_client):
    resp = await oidc_client.get("/oauth/userinfo")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"].startswith("Bearer")


@pytest.mark.parametrize("token", ["garbage", "a.b.c", ""])
async def test_userinfo_rejects_malformed_bearer_tokens(oidc_client, token):
    resp = await oidc_client.get("/oauth/userinfo", headers={"authorization": f"Bearer {token}"})
    assert resp.status_code == 401


async def test_userinfo_rejects_client_credentials_token(oidc_client):
    tok = await oidc_client.post(
        "/oauth/token",
        headers=_basic("client-cc", "test-only-cc-secret"),
        data={"grant_type": "client_credentials"},
    )
    assert tok.status_code == 200
    resp = await oidc_client.get(
        "/oauth/userinfo", headers={"authorization": f"Bearer {tok.json()['access_token']}"}
    )
    assert resp.status_code == 401


async def test_id_token_is_not_accepted_as_a_userinfo_access_token(oidc_client):
    body = await _code_exchange(oidc_client, "openid")
    resp = await oidc_client.get(
        "/oauth/userinfo", headers={"authorization": f"Bearer {body['id_token']}"}
    )
    assert resp.status_code == 401
