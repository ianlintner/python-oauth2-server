"""GET /oauth/logout (full OIDC RP-Initiated Logout) and GET /oauth/check_session.

Ported from `tests/compliance_wave6.rs`, `tests/security_http.rs`, and the
`oidc_logout.rs` unit tests (XSS hardening of the front-channel redirect
script) in the Rust source. `test_logout_with_invalid_aud_id_token_hint_returns_error`
stays in `tests/test_rfc_compliance.py`.
"""

from __future__ import annotations

import base64
import json

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from oauth2_server.routes import logout
from tests.conftest import build_client_app
from tests.helpers import login_admin, login_session, reseed_client, seed_admin, seed_client
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
        params={
            "id_token_hint": _id_token_hint(sub="u1", aud="client1"),
            "post_logout_redirect_uri": "https://example.com/logged-out",
        },
    )
    assert resp.status_code == 302, resp.text
    assert resp.headers["location"].startswith("https://example.com/logged-out")


async def test_logout_redirects_with_exact_state(client_app):
    await reseed_client(
        client_app,
        post_logout_redirect_uris=json.dumps(["https://app.example.com/logged-out"]),
    )

    resp = await client_app.get(
        "/oauth/logout",
        params={
            "id_token_hint": _id_token_hint(sub="u1", aud="client1"),
            "post_logout_redirect_uri": "https://app.example.com/logged-out",
            "state": "xyz",
        },
    )
    assert resp.status_code == 302, resp.text
    assert resp.headers["location"] == "https://app.example.com/logged-out?state=xyz"


async def test_post_logout_redirect_rejected_for_other_clients_redirect_uri(client_app):
    await reseed_client(
        client_app,
        redirect_uris=json.dumps(["https://app.example.com/logged-out"]),
        post_logout_redirect_uris="",
    )

    resp = await client_app.get(
        "/oauth/logout",
        params={"post_logout_redirect_uri": "https://app.example.com/logged-out"},
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_request"
    assert "location" not in resp.headers

    # Even with a hint, a plain redirect_uris entry does not qualify.
    resp = await client_app.get(
        "/oauth/logout",
        params={
            "id_token_hint": _id_token_hint(sub="u1", aud="client1"),
            "post_logout_redirect_uri": "https://app.example.com/logged-out",
        },
    )
    assert resp.status_code == 400, resp.text
    assert "location" not in resp.headers


async def test_post_logout_redirect_requires_hint_client_registration(client_app):
    await reseed_client(client_app)
    await seed_client(
        client_app.storage,
        client_id="client2",
        redirect_uris=json.dumps(["https://b.example/cb"]),
        post_logout_redirect_uris=json.dumps(["https://b.example/bye"]),
    )

    # client2's post-logout URI, but the hint identifies client1.
    resp = await client_app.get(
        "/oauth/logout",
        params={
            "id_token_hint": _id_token_hint(sub="u1", aud="client1"),
            "post_logout_redirect_uri": "https://b.example/bye",
        },
    )
    assert resp.status_code == 400, resp.text
    assert "location" not in resp.headers


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


@pytest.fixture(scope="module")
def rsa_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _rs256_app(rsa_pem: str):
    return build_client_app({"id_token_private_key_pem": rsa_pem, "id_token_kid": "test-rs256-key"})


def _capture_http(app) -> list[httpx.Request]:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    app.state.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=10)
    return captured


def _public_key_from_jwk(jwk: dict):
    def to_int(raw: str) -> int:
        return int.from_bytes(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)), "big")

    return rsa.RSAPublicNumbers(to_int(jwk["e"]), to_int(jwk["n"])).public_key()


async def test_backchannel_logout_posts_valid_token(rsa_pem):
    async with _rs256_app(rsa_pem) as client_app:
        captured = _capture_http(client_app.app)
        await reseed_client(
            client_app,
            backchannel_logout_uri="https://rp.example/bc-logout",
            backchannel_logout_session_required=False,
        )
        await login_session(client_app)

        id_token_hint = _id_token_hint(sub="u1", aud="client1")
        resp = await client_app.get("/oauth/logout", params={"id_token_hint": id_token_hint})
        assert resp.status_code == 200, resp.text

        assert len(captured) == 1
        req = captured[0]
        assert req.headers["content-type"] == "application/x-www-form-urlencoded"
        # Delivered to the resolved public address, addressed to the RP's host.
        assert req.headers["host"] == "rp.example"
        assert req.extensions["sni_hostname"] == "rp.example"
        assert req.url.host == "93.184.216.34"
        assert req.url.path == "/bc-logout"
        body = req.content.decode()
        assert body.startswith("logout_token=")
        logout_token = body.removeprefix("logout_token=")

        header = jwt.get_unverified_header(logout_token)
        assert header["typ"] == "logout+JWT"
        assert header["alg"] == "RS256"
        assert header["kid"] == "test-rs256-key"

        jwks = (await client_app.get("/.well-known/jwks.json")).json()
        public_key = _public_key_from_jwk(
            next(k for k in jwks["keys"] if k["kid"] == header["kid"])
        )
        claims = jwt.decode(logout_token, public_key, algorithms=["RS256"], audience="client1")
        assert claims["iss"] == ISSUER
        assert claims["aud"] == "client1"
        assert isinstance(claims["iat"], int)
        assert isinstance(claims["exp"], int)
        assert isinstance(claims["jti"], str)
        assert claims["events"] == {"http://schemas.openid.net/event/backchannel-logout": {}}
        assert claims["sub"] == "u1"


async def test_backchannel_logout_token_signed_with_published_key(rsa_pem):
    async with _rs256_app(rsa_pem) as client_app:
        captured = _capture_http(client_app.app)
        await reseed_client(client_app, backchannel_logout_uri="https://rp.example/bc")
        await login_session(client_app)
        resp = await client_app.get("/oauth/logout")
        assert resp.status_code == 200, resp.text

        token = captured[0].content.decode().removeprefix("logout_token=")
        assert jwt.get_unverified_header(token)["alg"] == "RS256"
        jwks = (await client_app.get("/.well-known/jwks.json")).json()
        public_key = _public_key_from_jwk(jwks["keys"][0])
        jwt.decode(token, public_key, algorithms=["RS256"], audience="client1")
        # The server-wide secret must not verify (or have produced) the token.
        with pytest.raises(jwt.PyJWTError):
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})


async def test_backchannel_logout_skipped_without_rs256_key(client_app):
    """No RS256 key: nothing verifiable can be sent, and `jwt_secret` is never used."""
    captured = _capture_http(client_app.app)
    await reseed_client(client_app, backchannel_logout_uri="https://rp.example/bc")
    await login_session(client_app)
    resp = await client_app.get("/oauth/logout")
    assert resp.status_code == 200, resp.text
    assert captured == []


@pytest.mark.parametrize(
    "answers",
    [["127.0.0.1"], ["10.0.0.5"], ["169.254.169.254"], ["::1"], ["93.184.216.34", "192.168.1.9"]],
)
async def test_backchannel_logout_skips_targets_resolving_to_non_public_addresses(
    rsa_pem, monkeypatch, answers
):
    async def resolve(host: str, port: int) -> list[str]:
        return answers

    monkeypatch.setattr("oauth2_server.services.outbound.resolve_host", resolve)
    async with _rs256_app(rsa_pem) as client_app:
        captured = _capture_http(client_app.app)
        await reseed_client(client_app, backchannel_logout_uri="https://rp.example/bc")
        await login_session(client_app)
        resp = await client_app.get("/oauth/logout")
        assert resp.status_code == 200, resp.text
        assert captured == []


@pytest.mark.parametrize(
    "uri", ["http://rp.example/bc", "https://127.0.0.1/bc", "https://10.0.0.5/bc"]
)
async def test_backchannel_logout_skips_stored_rows_with_unacceptable_uris(rsa_pem, uri):
    async with _rs256_app(rsa_pem) as client_app:
        captured = _capture_http(client_app.app)
        await reseed_client(client_app, backchannel_logout_uri=uri)
        await login_session(client_app)
        resp = await client_app.get("/oauth/logout")
        assert resp.status_code == 200, resp.text
        assert captured == []


async def test_backchannel_logout_uri_rejects_private_targets():
    async with build_client_app() as client:
        await seed_admin(client.storage)
        await login_admin(client)
        for uri in (
            "http://169.254.169.254/meta",
            "https://10.0.0.5/bc",
            "http://rp.example/bc",
            "https://localhost/bc",
            "https://2130706433/bc",
        ):
            resp = await client.post(
                "/admin/api/clients", json={"name": "Bc", "backchannel_logout_uri": uri}
            )
            assert resp.status_code == 400, (uri, resp.text)


async def test_backchannel_logout_delivers_to_multiple_clients_concurrently(rsa_pem):
    async with _rs256_app(rsa_pem) as client_app:
        await _deliver_to_multiple_clients(client_app)


async def _deliver_to_multiple_clients(client_app):
    captured = _capture_http(client_app.app)

    await reseed_client(
        client_app,
        backchannel_logout_uri="https://rp1.example/bc-logout",
        backchannel_logout_session_required=False,
    )
    await seed_client(
        client_app.storage,
        client_id="client2",
        redirect_uris=json.dumps(["https://b.example/cb"]),
        backchannel_logout_uri="https://rp2.example/bc-logout",
        backchannel_logout_session_required=False,
    )
    await login_session(client_app)

    id_token_hint = _id_token_hint(sub="u1", aud="client1")
    resp = await client_app.get("/oauth/logout", params={"id_token_hint": id_token_hint})
    assert resp.status_code == 200, resp.text

    assert len(captured) == 2
    hosts = {req.headers["host"] for req in captured}
    assert hosts == {"rp1.example", "rp2.example"}
    for req in captured:
        assert req.headers["content-type"] == "application/x-www-form-urlencoded"
        body = req.content.decode()
        assert body.startswith("logout_token=")


async def test_anon_sid_does_not_dispatch_backchannel(client_app):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    client_app.app.state.http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), timeout=10
    )
    await reseed_client(
        client_app,
        backchannel_logout_uri="https://rp.example/bc",
        backchannel_logout_session_required=True,
    )

    resp = await client_app.get("/oauth/logout", params={"sid": "anything"})
    assert resp.status_code == 200, resp.text
    assert captured == []


async def test_hint_without_session_does_not_dispatch_backchannel(client_app):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    client_app.app.state.http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), timeout=10
    )
    await reseed_client(
        client_app,
        backchannel_logout_uri="https://rp.example/bc",
        backchannel_logout_session_required=False,
    )

    resp = await client_app.get(
        "/oauth/logout", params={"id_token_hint": _id_token_hint(sub="u1", aud="client1")}
    )
    assert resp.status_code == 200, resp.text
    assert captured == []


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


async def test_logout_hint_without_matching_session_does_not_revoke(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    # A different browser: no login session.
    client_app.cookies.clear()
    id_token_hint = _id_token_hint(sub="u1", aud="client1")
    logout_resp = await client_app.get("/oauth/logout", params={"id_token_hint": id_token_hint})
    assert logout_resp.status_code == 200, logout_resp.text

    introspect_resp = await post_introspect(client_app, access_token)
    assert introspect_resp.status_code == 200, introspect_resp.text
    assert introspect_resp.json()["active"] is True


async def test_logout_hint_for_other_user_does_not_revoke(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    # Session belongs to u1; the hint names someone else.
    id_token_hint = _id_token_hint(sub="someone-else", aud="client1")
    logout_resp = await client_app.get("/oauth/logout", params={"id_token_hint": id_token_hint})
    assert logout_resp.status_code == 200, logout_resp.text

    introspect_resp = await post_introspect(client_app, access_token)
    assert introspect_resp.json()["active"] is True


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
