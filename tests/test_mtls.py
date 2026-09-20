"""Phase 4c Task 1 shared infrastructure: mTLS header plumbing (divergence
47 — proxy-supplied client-certificate headers are read ONLY when
`trust_proxy_headers` is enabled) and the shared unverified-claims decoder.

Plumbing only: no request behavior changes yet — the mTLS tuple is threaded
into `ClientService.authenticate` but not acted on (Task 2).
"""

from __future__ import annotations

import pytest
from starlette.requests import Request

from oauth2_server.config import Config
from oauth2_server.security import decode_unverified_claims
from oauth2_server.services.clients import ClientService, is_valid_redirect_uri
from oauth2_server.services.mtls import mtls_headers
from tests.conftest import build_client_app
from tests.helpers import post_token

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
