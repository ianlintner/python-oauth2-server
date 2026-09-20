"""RFC 9701 — JWT-secured introspection responses.

A caller that asks for `Accept: application/token-introspection+jwt` gets
the introspection result as a signed JWT whose `token_introspection` claim
holds the body RFC 7662 would have returned as JSON.

Divergence 34 (deliberate): BOTH the active and the inactive result are
wrapped, where Rust only wraps the active path — an inactive result is
still an introspection result, and a caller that negotiated JWT should not
have to parse two different media types depending on the answer.
"""

from __future__ import annotations

import base64
import logging

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.conftest import build_client_app
from tests.helpers import post_token

JWT_MEDIA_TYPE = "application/token-introspection+jwt"
ISSUER = "https://auth.example.com"
# Mirrors `tests/conftest.py::build_client_app`'s default override.
JWT_SECRET = "unit-test-secret-not-for-production-0123456789abcdef"


@pytest.fixture(scope="module")
def rsa_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _basic_auth(client_id: str = "client1", secret: str = "s3cret") -> dict[str, str]:
    raw = f"{client_id}:{secret}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


async def _client_credentials_token(client_app) -> str:
    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


async def _introspect(client_app, token: str, accept: str | None = None):
    headers = _basic_auth()
    if accept is not None:
        headers["Accept"] = accept
    return await client_app.post("/oauth/introspect", data={"token": token}, headers=headers)


async def test_rfc9701_jwt_accept_header_returns_jwt_introspection_response(client_app):
    access_token = await _client_credentials_token(client_app)
    resp = await _introspect(client_app, access_token, accept=JWT_MEDIA_TYPE)

    assert resp.status_code == 200, resp.text
    assert JWT_MEDIA_TYPE in resp.headers["content-type"]
    header = jwt.get_unverified_header(resp.text)
    assert header["typ"] == "token-introspection+jwt"


async def test_rfc9701_standard_accept_returns_json_introspection_response(client_app):
    access_token = await _client_credentials_token(client_app)
    resp = await _introspect(client_app, access_token, accept="application/json")

    assert resp.status_code == 200, resp.text
    assert "application/json" in resp.headers["content-type"]
    assert resp.json()["active"] is True


async def test_rfc9701_jwt_payload_contains_token_introspection_claim(client_app):
    access_token = await _client_credentials_token(client_app)
    resp = await _introspect(client_app, access_token, accept=JWT_MEDIA_TYPE)
    assert resp.status_code == 200, resp.text

    payload = jwt.decode(resp.text, JWT_SECRET, algorithms=["HS256"], audience="client1")
    assert payload["iss"] == ISSUER
    assert payload["aud"] == "client1"
    assert isinstance(payload["iat"], int)

    introspection = payload["token_introspection"]
    assert introspection["active"] is True
    assert introspection["client_id"] == "client1"


async def test_rfc9701_inactive_result_is_also_wrapped(client_app):
    """Divergence 34: the inactive result is wrapped too (Rust only wraps active)."""
    resp = await _introspect(client_app, "not-a-real-token", accept=JWT_MEDIA_TYPE)

    assert resp.status_code == 200, resp.text
    assert JWT_MEDIA_TYPE in resp.headers["content-type"]
    payload = jwt.decode(resp.text, JWT_SECRET, algorithms=["HS256"], audience="client1")
    assert payload["token_introspection"] == {"active": False}


async def test_rfc9701_hs256_signature_verifies_with_jwt_secret(client_app):
    access_token = await _client_credentials_token(client_app)
    resp = await _introspect(client_app, access_token, accept=JWT_MEDIA_TYPE)
    assert resp.status_code == 200, resp.text

    header = jwt.get_unverified_header(resp.text)
    assert header["alg"] == "HS256"
    assert "kid" not in header

    payload = jwt.decode(resp.text, JWT_SECRET, algorithms=["HS256"], audience="client1")
    assert payload["token_introspection"]["active"] is True

    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(resp.text, "the-wrong-secret", algorithms=["HS256"], audience="client1")


async def test_rfc9701_rs256_uses_keyset_kid(rsa_pem):
    async with build_client_app(
        {"id_token_private_key_pem": rsa_pem, "id_token_kid": "test-rs256-key"}
    ) as client:
        assert client.app.state.config.id_token_alg == "RS256"
        access_token = await _client_credentials_token(client)
        resp = await _introspect(client, access_token, accept=JWT_MEDIA_TYPE)
        assert resp.status_code == 200, resp.text

        header = jwt.get_unverified_header(resp.text)
        assert header["alg"] == "RS256"
        assert header["typ"] == "token-introspection+jwt"
        assert header["kid"] == "test-rs256-key"

        jwks = await client.get("/.well-known/jwks.json")
        assert jwks.status_code == 200, jwks.text
        jwk = next(k for k in jwks.json()["keys"] if k["kid"] == header["kid"])
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)

        payload = jwt.decode(resp.text, public_key, algorithms=["RS256"], audience="client1")
        assert payload["iss"] == ISSUER
        assert payload["token_introspection"]["active"] is True


async def test_rfc9701_response_has_no_store(client_app):
    access_token = await _client_credentials_token(client_app)
    resp = await _introspect(client_app, access_token, accept=JWT_MEDIA_TYPE)

    assert resp.status_code == 200, resp.text
    assert JWT_MEDIA_TYPE in resp.headers["content-type"]
    assert resp.headers["cache-control"] == "no-store"


def test_rs256_without_a_current_key_warns_on_the_hs256_fallback(caplog):
    """`encode_introspection_jwt` silently downgrades RS256 -> HS256 when
    the keyset has no current RS256 key. The downgrade is deliberate (a 500
    would be worse), but it must not be silent — an operator who configured
    RS256 and is being served HS256 needs a way to notice."""
    from oauth2_server.config import Config
    from oauth2_server.keys import KeySet
    from oauth2_server.security import encode_introspection_jwt

    config = Config(jwt_secret=JWT_SECRET, issuer=ISSUER, id_token_alg="RS256")
    with caplog.at_level(logging.WARNING, logger="oauth2_server.security"):
        token = encode_introspection_jwt({"iss": ISSUER}, config, KeySet())

    assert jwt.get_unverified_header(token)["alg"] == "HS256"
    assert any(
        record.levelno == logging.WARNING and "HS256" in record.getMessage()
        for record in caplog.records
    ), caplog.text
