"""Phase 4c Task 1 shared infrastructure: mTLS header plumbing (divergence
47 — proxy-supplied client-certificate headers are read ONLY when
`trust_proxy_headers` is enabled) and the shared unverified-claims decoder.

Plumbing only: no request behavior changes yet — the mTLS tuple is threaded
into `ClientService.authenticate` but not acted on (Task 2).
"""

from __future__ import annotations

import json

import pytest
from starlette.requests import Request

from oauth2_server.config import Config
from oauth2_server.security import decode_unverified_claims
from oauth2_server.services.clients import ClientService, is_valid_redirect_uri
from oauth2_server.services.mtls import mtls_headers
from tests.conftest import build_client_app
from tests.helpers import generate_rsa_keypair, post_token, reseed_client

MTLS_HEADERS = {
    "X-Client-Cert-Thumbprint": "abc123",
    "X-SSL-Client-S-DN": "CN=client1,O=Example",
}


def _request(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/oauth/token",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )


def _config(**overrides) -> Config:
    return Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
        **overrides,
    )


def test_mtls_headers_ignored_without_trust_proxy():
    assert mtls_headers(_request(MTLS_HEADERS), _config()) == (None, None)


def test_mtls_headers_read_with_trust_proxy():
    config = _config(trust_proxy_headers=True)
    assert mtls_headers(_request(MTLS_HEADERS), config) == ("abc123", "CN=client1,O=Example")


def test_mtls_headers_empty_values_are_none():
    config = _config(trust_proxy_headers=True)
    headers = {"X-Client-Cert-Thumbprint": "", "X-SSL-Client-S-DN": "   "}
    assert mtls_headers(_request(headers), config) == (None, None)


def test_mtls_headers_absent_headers_are_none():
    assert mtls_headers(_request({}), _config(trust_proxy_headers=True)) == (None, None)


@pytest.mark.parametrize("send_headers", [False, True])
async def test_authenticate_accepts_mtls_kwarg_without_behavior_change(send_headers):
    async with build_client_app(config_overrides={"trust_proxy_headers": True}) as client_app:
        response = await post_token(
            client_app,
            {"grant_type": "client_credentials", "scope": "read"},
            basic_auth=("client1", "s3cret"),
            headers=dict(MTLS_HEADERS) if send_headers else None,
        )
    assert response.status_code == 200
    assert response.json()["access_token"]


async def test_authenticate_accepts_mtls_kwarg_directly():
    async with build_client_app() as client_app:
        service = ClientService.from_app(client_app.app.state)
        client = await service.authenticate(
            {"client_id": "client1", "client_secret": "s3cret"},
            None,
            mtls=("abc123", "CN=client1,O=Example"),
        )
    assert client.client_id == "client1"


def test_is_valid_redirect_uri_is_shared_from_clients_service():
    # Moved verbatim out of `routes/register.py` so the admin routes can
    # reuse it; register keeps a thin alias.
    from oauth2_server.routes.register import _is_valid_redirect_uri

    assert _is_valid_redirect_uri is is_valid_redirect_uri
    assert is_valid_redirect_uri("https://app.example.com/cb") is True
    assert is_valid_redirect_uri("https://app.example.com/cb#frag") is False
    assert is_valid_redirect_uri("ftp://app.example.com/cb") is False
    assert is_valid_redirect_uri("https:///cb") is False


@pytest.mark.parametrize("value", ["", "not-a-jwt", "a.b.c", 123, None])
def test_decode_unverified_claims_returns_empty_on_garbage(value):
    assert decode_unverified_claims(value) == {}


def test_decode_unverified_claims_reads_claims_without_verifying():
    import jwt

    token = jwt.encode({"cnf": {"jkt": "thumb"}, "sub": "u1"}, "some-other-secret")
    claims = decode_unverified_claims(token)
    assert claims["cnf"] == {"jkt": "thumb"}
    assert claims["sub"] == "u1"


# --- Task 2: RFC 8705 client authentication --------------------------------

CERT_THUMBPRINT = "Zm9vYmFyLXRodW1icHJpbnQtMzItYnl0ZXMtYjY0dQ"
CLIENT_DN = "CN=client1,O=Example"
CLIENT_CREDENTIALS = {"grant_type": "client_credentials", "scope": "read"}


def _cert_headers(thumbprint: str | None = CERT_THUMBPRINT, dn: str | None = None) -> dict:
    headers = {}
    if thumbprint is not None:
        headers["X-Client-Cert-Thumbprint"] = thumbprint
    if dn is not None:
        headers["X-SSL-Client-S-DN"] = dn
    return headers


def _trusting_app():
    return build_client_app(config_overrides={"trust_proxy_headers": True})


async def test_vector_p_mtls_subject_dn_validation():
    """RFC 8705 §2.1 `tls_client_auth`: the presented Subject DN must equal
    the registered one exactly."""
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        ok = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn=CLIENT_DN),
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["access_token"]

        bad = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn="CN=attacker,O=Example"),
        )
        assert bad.status_code == 401, bad.text
        assert bad.json() == {
            "error": "invalid_client",
            "error_description": "tls_client_auth: client certificate Subject DN does not match",
        }


async def test_tls_client_auth_missing_certificate_rejected():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        resp = await post_token(client_app, {**CLIENT_CREDENTIALS, "client_id": "client1"})
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"] == (
            "tls_client_auth requires a TLS client certificate "
            "(X-Client-Cert-Thumbprint header missing)"
        )


async def test_tls_client_auth_empty_dn_accepts_any_certificate():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn="",
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn="CN=whoever,O=Anywhere"),
        )
        assert resp.status_code == 200, resp.text


async def test_tls_client_auth_dn_configured_header_missing_rejected():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"] == (
            "tls_client_auth requires X-SSL-Client-S-DN header when Subject DN is configured"
        )


async def test_tls_client_auth_ignores_form_client_secret():
    """A form `client_secret` never substitutes for a certificate: the row
    still carries a secret, but the registered method is certificate-bound."""
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="s3cret",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1", "client_secret": "s3cret"},
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"].startswith(
            "tls_client_auth requires a TLS client certificate"
        )


async def test_tls_client_auth_rejected_without_trust_proxy():
    """Divergence 47: without `trust_proxy_headers` the headers are not read
    at all, so a forged certificate header authenticates nobody."""
    async with build_client_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn=CLIENT_DN),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"].startswith(
            "tls_client_auth requires a TLS client certificate"
        )


def _self_signed_jwks(thumbprint: str = CERT_THUMBPRINT) -> dict:
    _pem, jwks = generate_rsa_keypair()
    jwks["keys"][0]["x5t#S256"] = thumbprint
    return jwks


async def test_self_signed_matches_registered_jwk():
    jwks = _self_signed_jwks()
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="self_signed_tls_client_auth",
            client_secret="",
            jwks=json.dumps(jwks),
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["access_token"]


async def test_self_signed_unknown_thumbprint_rejected():
    jwks = _self_signed_jwks("some-other-thumbprint")
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="self_signed_tls_client_auth",
            client_secret="",
            jwks=json.dumps(jwks),
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json() == {
            "error": "invalid_client",
            "error_description": (
                "self_signed_tls_client_auth: certificate does not match a registered JWK"
            ),
        }
        # The presented thumbprint is never echoed back.
        assert CERT_THUMBPRINT not in resp.text


async def test_self_signed_without_certificate_rejected():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="self_signed_tls_client_auth",
            client_secret="",
            jwks=json.dumps(_self_signed_jwks()),
        )
        resp = await post_token(client_app, {**CLIENT_CREDENTIALS, "client_id": "client1"})
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"] == (
            "self_signed_tls_client_auth requires a TLS client certificate "
            "(X-Client-Cert-Thumbprint header missing)"
        )


async def test_self_signed_without_jwks_rejected():
    """A legacy row with no key material cannot match any certificate, and
    says so with the same fixed message as a mismatch."""
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="self_signed_tls_client_auth",
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"] == (
            "self_signed_tls_client_auth: certificate does not match a registered JWK"
        )


async def test_mtls_authenticates_at_par_and_introspect():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        headers = _cert_headers(dn=CLIENT_DN)

        par = await client_app.post(
            "/oauth/par",
            content="client_id=client1&response_type=code&scope=read",
            headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
        )
        assert par.status_code == 201, par.text
        assert par.json()["request_uri"].startswith("urn:ietf:params:oauth:request-uri:")

        token = await post_token(
            client_app, {**CLIENT_CREDENTIALS, "client_id": "client1"}, headers=headers
        )
        assert token.status_code == 200, token.text
        access_token = token.json()["access_token"]

        introspect = await client_app.post(
            "/oauth/introspect",
            data={"token": access_token, "client_id": "client1"},
            headers=headers,
        )
        assert introspect.status_code == 200, introspect.text
        assert introspect.json()["active"] is True
