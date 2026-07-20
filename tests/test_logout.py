"""GET /oauth/logout (full OIDC RP-Initiated Logout) and GET /oauth/check_session.

Ported from `tests/compliance_wave6.rs`, `tests/security_http.rs`, and the
`oidc_logout.rs` unit tests (XSS hardening of the front-channel redirect
script) in the Rust source. `test_logout_with_invalid_aud_id_token_hint_returns_error`
stays in `tests/test_rfc_compliance.py`.
"""

from __future__ import annotations

import json

import httpx
import jwt

from oauth2_server.routes import logout
from tests.helpers import login_session, reseed_client
from tests.test_introspection import post_introspect
from tests.test_token_endpoint import run_code_flow

ISSUER = "https://auth.example.com"
JWT_SECRET = "unit-test-secret-not-for-production-0123456789abcdef"


def _id_token_hint(*, sub: str, aud: str, exp: int = 9999999999) -> str:
    return jwt.encode(
        {"iss": ISSUER, "sub": sub, "aud": aud, "exp": exp, "iat": 0},
        JWT_SECRET,
        algorithm="HS256",
    )


# ---------------------------------------------------------------------------
# GET /oauth/logout — standard branch (no front/back-channel clients)
# ---------------------------------------------------------------------------


async def test_simple_logout_returns_ok(client_app):
    await login_session(client_app)

    resp = await client_app.get("/oauth/logout")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "logged_out"}


async def test_logout_accepts_registered_post_logout_redirect_uri(client_app):
    await reseed_client(
        client_app,
        post_logout_redirect_uris=json.dumps(["https://example.com/logged-out"]),
    )

    resp = await client_app.get(
        "/oauth/logout",
        params={"post_logout_redirect_uri": "https://example.com/logged-out"},
    )
    assert resp.status_code == 302, resp.text
    assert resp.headers["location"].startswith("https://example.com/logged-out")


async def test_logout_redirects_with_exact_state(client_app):
    # Empty post_logout_redirect_uris exercises the redirect_uris fallback.
    await reseed_client(
        client_app,
        redirect_uris=json.dumps(["https://app.example.com/logged-out"]),
        post_logout_redirect_uris="",
    )

    resp = await client_app.get(
        "/oauth/logout",
        params={
            "post_logout_redirect_uri": "https://app.example.com/logged-out",
            "state": "xyz",
        },
    )
    assert resp.status_code == 302, resp.text
    assert resp.headers["location"] == "https://app.example.com/logged-out?state=xyz"


async def test_logout_rejects_unregistered_post_logout_redirect_uri(client_app):
    resp = await client_app.get(
        "/oauth/logout",
        params={"post_logout_redirect_uri": "https://evil.example/after-logout"},
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# Front-channel logout
# ---------------------------------------------------------------------------


async def test_logout_renders_frontchannel_iframes(client_app):
    await reseed_client(
        client_app,
        frontchannel_logout_uri="https://example.com/frontchannel-logout",
        frontchannel_logout_session_required=True,
    )
    await login_session(client_app)

    resp = await client_app.get("/oauth/logout")
    assert resp.status_code == 200, resp.text
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    assert "<iframe" in body
    assert "https://example.com/frontchannel-logout" in body
    assert "iss=" in body


# ---------------------------------------------------------------------------
# Back-channel logout
# ---------------------------------------------------------------------------


async def test_backchannel_logout_posts_valid_token(client_app):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    client_app.app.state.http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), timeout=10
    )

    await reseed_client(
        client_app,
        backchannel_logout_uri="https://rp.example/bc-logout",
        backchannel_logout_session_required=False,
    )

    id_token_hint = _id_token_hint(sub="u1", aud="client1")
    resp = await client_app.get("/oauth/logout", params={"id_token_hint": id_token_hint})
    assert resp.status_code == 200, resp.text

    assert len(captured) == 1
    req = captured[0]
    assert req.headers["content-type"] == "application/x-www-form-urlencoded"
    body = req.content.decode()
    assert body.startswith("logout_token=")
    logout_token = body.removeprefix("logout_token=")

    header = jwt.get_unverified_header(logout_token)
    assert header["typ"] == "logout+JWT"

    claims = jwt.decode(
        logout_token, JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False}
    )
    assert claims["iss"] == ISSUER
    assert claims["aud"] == "client1"
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert isinstance(claims["jti"], str)
    assert claims["events"] == {"http://schemas.openid.net/event/backchannel-logout": {}}
    assert claims["sub"] == "u1"


# ---------------------------------------------------------------------------
# id_token_hint -> cascade revocation
# ---------------------------------------------------------------------------


async def test_valid_hint_revokes_users_tokens(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    id_token_hint = _id_token_hint(sub="u1", aud="client1")
    logout_resp = await client_app.get("/oauth/logout", params={"id_token_hint": id_token_hint})
    assert logout_resp.status_code == 200, logout_resp.text

    introspect_resp = await post_introspect(client_app, access_token)
    assert introspect_resp.status_code == 200, introspect_resp.text
    assert introspect_resp.json()["active"] is False


# ---------------------------------------------------------------------------
# GET /oauth/check_session
# ---------------------------------------------------------------------------


async def test_check_session_iframe_returns_html(client_app):
    resp = await client_app.get("/oauth/check_session")
    assert resp.status_code == 200, resp.text
    assert "text/html" in resp.headers["content-type"]
    assert "postMessage" in resp.text
    assert "SHA-256" in resp.text


# ---------------------------------------------------------------------------
# Front-channel redirect script — XSS hardening (ported from oidc_logout.rs
# `mod tests`: redirect_url_is_json_encoded_not_raw /
# redirect_url_does_not_allow_script_breakout / no_redirect_script_when_absent)
# ---------------------------------------------------------------------------


def test_frontchannel_redirect_url_is_json_encoded():
    url = 'https://rp.example/cb?x="+alert(1)+"'
    script = logout._redirect_script(url)
    assert "window.location.href" in script
    # The raw quote-breakout payload must never appear un-escaped.
    assert '"+alert(1)+"' not in script


def test_frontchannel_redirect_url_blocks_script_breakout():
    url = "https://rp.example/cb?x=</script><script>alert(1)</script>"
    page = logout._render_frontchannel_page([], ISSUER, None, url)
    # Only our own closing tag remains; the payload's "</script>" sequences
    # were escaped ('<' and '/' are both replaced), so they can't break out.
    assert page.count("</script>") == 1
    assert "<script>alert(1)" not in page


def test_no_redirect_script_when_absent():
    page = logout._render_frontchannel_page([], ISSUER, None, None)
    assert "window.location.href" not in page
