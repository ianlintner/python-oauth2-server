"""OIDC hybrid `response_type=code id_token` at `/oauth/authorize`.

Covers the shared id-token minter (`oauth2_server.services.id_token`) and its
two callers: the token endpoint (unchanged after the refactor) and the
authorize endpoint's hybrid branch.

Rust-parity behaviors pinned here:
- hybrid defaults `response_mode` to `fragment` (OIDC Core §3.3.2.3);
- the id_token is issued only when the EFFECTIVE (code) scope has `openid`;
- `c_hash = base64url(SHA-256(code)[:16])` (no padding), no `at_hash` at
  authorize (no access token is issued in this flow), `aud == client_id`,
  `nonce` echoed;
- the id_token TTL is the token endpoint's (`access_token_ttl_secs`).

Divergence 39: hybrid REQUIRES `nonce` — a missing one is a redirect-channel
`invalid_request` rather than Rust's silently-unauthenticated id_token.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from oauth2_server.security import half_hash
from tests.conftest import build_client_app
from tests.helpers import login_session, reseed_client
from tests.test_token_endpoint import _pkce_pair, run_code_flow

ISSUER = "https://auth.example.com"
REDIRECT_URI = "https://a.example/cb"


def _hybrid_params(**overrides) -> dict:
    verifier, challenge = _pkce_pair()
    params = {
        "response_type": "code id_token",
        "client_id": "client1",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid read",
        "nonce": "n-0S6_WzA2Mj",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return {k: v for k, v in params.items() if v is not None}


def _fragment(resp) -> dict[str, list[str]]:
    split = urlsplit(resp.headers["location"])
    assert split.query == "", "hybrid must not use the query channel by default"
    return parse_qs(split.fragment)


def _unverified(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


async def test_wave5_hybrid_code_id_token_delivers_both_in_fragment(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get("/oauth/authorize", params=_hybrid_params(state="xyz"))
    assert resp.status_code == 302, resp.text
    frag = _fragment(resp)
    assert frag["code"], frag
    assert frag["id_token"], frag
    assert frag["state"] == ["xyz"]
    assert frag["iss"] == [ISSUER]


async def test_wave5_hybrid_no_openid_scope_omits_id_token(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get("/oauth/authorize", params=_hybrid_params(scope="read"))
    assert resp.status_code == 302, resp.text
    frag = _fragment(resp)
    assert frag["code"], frag
    assert "id_token" not in frag


async def test_hybrid_id_token_has_c_hash_nonce_and_no_at_hash(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get("/oauth/authorize", params=_hybrid_params())
    assert resp.status_code == 302, resp.text
    frag = _fragment(resp)
    claims = _unverified(frag["id_token"][0])

    assert claims["c_hash"] == half_hash(frag["code"][0])
    assert claims["nonce"] == "n-0S6_WzA2Mj"
    assert "at_hash" not in claims
    assert claims["aud"] == "client1"
    assert claims["iss"] == ISSUER
    assert claims["sub"] == "u1"
    assert claims["exp"] - claims["iat"] == 3600
    # auth_time comes from the session established by `login_session`.
    assert claims["auth_time"] <= claims["iat"]


async def test_hybrid_requires_nonce(app_with_session):
    # Divergence 39: a hybrid request without `nonce` is a redirect-channel
    # error, not an unauthenticated id_token.
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize", params=_hybrid_params(nonce=None, state="xyz")
    )
    assert resp.status_code == 302, resp.text
    frag = _fragment(resp)
    assert frag["error"] == ["invalid_request"]
    assert frag["error_description"] == ["nonce is required for response_type=code id_token"]
    assert frag["state"] == ["xyz"]
    assert "code" not in frag
    assert "id_token" not in frag


@pytest.fixture(scope="module")
def rsa_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


async def test_hybrid_id_token_verifies_against_jwks_when_rs256(rsa_pem):
    async with build_client_app(
        {"id_token_private_key_pem": rsa_pem, "id_token_kid": "test-rs256-key"}
    ) as client:
        await login_session(client)
        resp = await client.get("/oauth/authorize", params=_hybrid_params())
        assert resp.status_code == 302, resp.text
        id_token = _fragment(resp)["id_token"][0]

        header = jwt.get_unverified_header(id_token)
        assert header["alg"] == "RS256"

        jwks = (await client.get("/.well-known/jwks.json")).json()
        jwk = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        claims = jwt.decode(id_token, public_key, algorithms=["RS256"], audience="client1")
        assert claims["nonce"] == "n-0S6_WzA2Mj"


async def test_hybrid_form_post_carries_id_token(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize", params=_hybrid_params(response_mode="form_post", state="xyz")
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "text/html; charset=utf-8"
    code = re.search(r'name="code" value="([^"]+)"', resp.text).group(1)
    id_token = re.search(r'name="id_token" value="([^"]+)"', resp.text).group(1)
    assert _unverified(id_token)["c_hash"] == half_hash(code)
    assert '<input type="hidden" name="state" value="xyz"/>' in resp.text


async def test_hybrid_rejected_when_client_scope_excludes_openid(app_with_session):
    await reseed_client(app_with_session, scope="read")
    await login_session(app_with_session)
    resp = await app_with_session.get("/oauth/authorize", params=_hybrid_params())
    assert resp.status_code == 302, resp.text
    frag = _fragment(resp)
    assert frag["error"] == ["invalid_scope"]


async def test_token_endpoint_id_token_unchanged_after_refactor(client_app):
    # The token endpoint's id_token keeps its at_hash/c_hash/nonce shape
    # after delegating to the shared minter.
    resp, code = await run_code_flow(client_app, scope="openid email", nonce="tok-nonce")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    claims = _unverified(body["id_token"])
    assert claims["at_hash"] == half_hash(body["access_token"])
    assert claims["c_hash"] == half_hash(code)
    assert claims["nonce"] == "tok-nonce"
    assert claims["aud"] == "client1"
    assert claims["email"] == "user_rfc@example.test"
    assert claims["exp"] - claims["iat"] == 3600
