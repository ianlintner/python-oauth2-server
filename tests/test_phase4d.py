"""Phase 4d: PKCE for every client (divergence 64), `mtls_endpoint_aliases`
(61), and the `claims` `userinfo` member (63). Userinfo nonce enforcement
(62) lives in tests/test_dpop_nonce.py; the persisted `dpop_jkt` (52) in
tests/test_dpop_jkt.py."""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

from oauth2_server.services.auth import AuthorizeService
from tests.conftest import build_client_app
from tests.helpers import login_session, post_token
from tests.test_token_endpoint import _pkce_pair

REDIRECT_URI = "https://a.example/cb"
BASIC = ("client1", "s3cret")


# --- divergence 64: PKCE for confidential clients ---------------------------


async def test_authorize_requires_pkce_for_confidential_client(client_app):
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": REDIRECT_URI,
            "scope": "read",
            "state": "s",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["invalid_request"]
    assert "PKCE" in q["error_description"][0]
    assert "code" not in q


async def test_token_refuses_pkce_less_code_for_confidential_client(client_app):
    """A code minted without a challenge (e.g. before this change shipped) can
    no longer be redeemed, even by a client that authenticates."""
    user = await client_app.storage.get_user_by_username("user_rfc")
    client = await client_app.storage.get_client("client1")
    code = await AuthorizeService(client_app.storage, client_app.app.state.config).issue_code(
        client,
        user.id,
        REDIRECT_URI,
        "read",
        code_challenge=None,
        code_challenge_method=None,
        nonce=None,
    )
    resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code.code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "client1",
        },
        basic_auth=BASIC,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    assert "PKCE" in resp.json()["error_description"]


# --- divergence 61: mtls_endpoint_aliases -----------------------------------


async def test_mtls_endpoint_aliases_advertised_when_configured_and_trusted():
    async with build_client_app(
        {
            "trust_proxy_headers": True,
            "mtls_endpoint_base_url": "https://mtls.auth.example.com/",
        }
    ) as c:
        body = (await c.get("/.well-known/openid-configuration")).json()
    aliases = body["mtls_endpoint_aliases"]
    assert aliases["token_endpoint"] == "https://mtls.auth.example.com/oauth/token"
    assert aliases["introspection_endpoint"] == "https://mtls.auth.example.com/oauth/introspect"
    assert "authorization_endpoint" not in aliases  # browser-facing, never aliased
    assert body["token_endpoint"] == "https://auth.example.com/oauth/token"


async def test_mtls_endpoint_aliases_withheld_without_trusted_proxy():
    async with build_client_app({"mtls_endpoint_base_url": "https://mtls.auth.example.com"}) as c:
        body = (await c.get("/.well-known/openid-configuration")).json()
    assert "mtls_endpoint_aliases" not in body


# --- divergence 63: claims `userinfo` member --------------------------------


async def _userinfo_for(client_app, claims: dict | None) -> dict:
    await login_session(client_app)
    verifier, challenge = _pkce_pair()
    params = {
        "response_type": "code",
        "client_id": "client1",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid email profile",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if claims is not None:
        params["claims"] = json.dumps(claims)
    authz = await client_app.get("/oauth/authorize", params=params)
    code = parse_qs(urlparse(authz.headers["location"]).query)["code"][0]
    tok = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "client1",
            "code_verifier": verifier,
        },
        basic_auth=BASIC,
    )
    access = tok.json()["access_token"]
    resp = await client_app.get("/oauth/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_userinfo_without_claims_request_is_unchanged(client_app):
    body = await _userinfo_for(client_app, None)
    assert "email" in body and "preferred_username" in body


async def test_userinfo_claims_value_mismatch_omits_claim(client_app):
    body = await _userinfo_for(
        client_app, {"userinfo": {"email": {"value": "someone.else@example.com"}}}
    )
    assert "email" not in body
    assert "preferred_username" in body


async def test_userinfo_claims_matching_value_keeps_claim(client_app):
    user = await client_app.storage.get_user_by_username("user_rfc")
    body = await _userinfo_for(client_app, {"userinfo": {"email": {"value": user.email}}})
    assert body["email"] == user.email


async def test_userinfo_ignores_id_token_member(client_app):
    body = await _userinfo_for(client_app, {"id_token": {"email": {"value": "x@example.com"}}})
    assert "email" in body
