"""RFC 9701 — JWT-secured introspection responses.

A caller that asks for `Accept: application/token-introspection+jwt` gets
the introspection result as a signed JWT whose `token_introspection` claim
holds the body RFC 7662 would have returned as JSON.

Divergence 34 (deliberate): BOTH the active and the inactive result are
wrapped, where Rust only wraps the active path — an inactive result is
still an introspection result, and a caller that negotiated JWT should not
have to parse two different media types depending on the answer.

Signing-key selection is security-over-parity (divergence 34): the response
must be verifiable by the client that asked for it, so it is RS256 from the
JWKS-published keyset key when one exists, else HS256 under the requesting
client's own `client_secret` (OIDC Core §10.1), never the server-internal
`jwt_secret`.
"""

from __future__ import annotations

import base64

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.conftest import build_client_app
from tests.helpers import post_token, reseed_client

JWT_MEDIA_TYPE = "application/token-introspection+jwt"
ISSUER = "https://auth.example.com"
# Mirrors `tests/conftest.py::build_client_app`'s default override. Only
# used here to assert the response is NOT signed with it.
JWT_SECRET = "unit-test-secret-not-for-production-0123456789abcdef"
# The seeded `client1` secret is `s3cret` (6 bytes); PyJWT emits
# `InsecureKeyLengthWarning` for HMAC keys shorter than 32 bytes, so every
# test here reseeds `client1` with a `client_secret_jwt`-length secret.
CLIENT_SECRET = "client1-introspection-secret-0123456789abcdef"


@pytest.fixture(scope="module")
def rsa_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture
async def jwt_client_app(client_app):
    """`client_app` with `client1`'s secret long enough for HS256 signing."""
    await reseed_client(client_app, client_secret=CLIENT_SECRET)
    return client_app


def _basic_auth(client_id: str = "client1", secret: str = CLIENT_SECRET) -> dict[str, str]:
    raw = f"{client_id}:{secret}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


async def _client_credentials_token(client_app) -> str:
    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", CLIENT_SECRET)
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


async def _introspect(client_app, token: str, accept: str | None = None, **auth):
    headers = _basic_auth(**auth)
    if accept is not None:
        headers["Accept"] = accept
    return await client_app.post("/oauth/introspect", data={"token": token}, headers=headers)


async def test_rfc9701_jwt_accept_header_returns_jwt_introspection_response(jwt_client_app):
    access_token = await _client_credentials_token(jwt_client_app)
    resp = await _introspect(jwt_client_app, access_token, accept=JWT_MEDIA_TYPE)

    assert resp.status_code == 200, resp.text
    assert JWT_MEDIA_TYPE in resp.headers["content-type"]
    header = jwt.get_unverified_header(resp.text)
    assert header["typ"] == "token-introspection+jwt"


async def test_rfc9701_standard_accept_returns_json_introspection_response(jwt_client_app):
    access_token = await _client_credentials_token(jwt_client_app)
    resp = await _introspect(jwt_client_app, access_token, accept="application/json")

    assert resp.status_code == 200, resp.text
    assert "application/json" in resp.headers["content-type"]
    assert resp.json()["active"] is True


async def test_rfc9701_jwt_payload_contains_token_introspection_claim(jwt_client_app):
    access_token = await _client_credentials_token(jwt_client_app)
    resp = await _introspect(jwt_client_app, access_token, accept=JWT_MEDIA_TYPE)
    assert resp.status_code == 200, resp.text

    payload = jwt.decode(resp.text, CLIENT_SECRET, algorithms=["HS256"], audience="client1")
    assert payload["iss"] == ISSUER
    assert payload["aud"] == "client1"
    assert isinstance(payload["iat"], int)

    introspection = payload["token_introspection"]
    assert introspection["active"] is True
    assert introspection["client_id"] == "client1"


async def test_rfc9701_inactive_result_is_also_wrapped(jwt_client_app):
    """Divergence 34: the inactive result is wrapped too (Rust only wraps active)."""
    resp = await _introspect(jwt_client_app, "not-a-real-token", accept=JWT_MEDIA_TYPE)

    assert resp.status_code == 200, resp.text
    assert JWT_MEDIA_TYPE in resp.headers["content-type"]
    payload = jwt.decode(resp.text, CLIENT_SECRET, algorithms=["HS256"], audience="client1")
    assert payload["token_introspection"] == {"active": False}


async def test_rfc9701_hs256_signature_verifies_with_the_requesting_client_secret(jwt_client_app):
    """OIDC Core §10.1: the symmetric signing key is the requesting client's
    own secret — never the server's `jwt_secret`, which no client holds and
    therefore no client could verify."""
    access_token = await _client_credentials_token(jwt_client_app)
    resp = await _introspect(jwt_client_app, access_token, accept=JWT_MEDIA_TYPE)
    assert resp.status_code == 200, resp.text

    header = jwt.get_unverified_header(resp.text)
    assert header["alg"] == "HS256"
    assert "kid" not in header

    payload = jwt.decode(resp.text, CLIENT_SECRET, algorithms=["HS256"], audience="client1")
    assert payload["token_introspection"]["active"] is True

    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(resp.text, JWT_SECRET, algorithms=["HS256"], audience="client1")


async def test_rfc9701_rs256_uses_keyset_kid(rsa_pem):
    async with build_client_app(
        {"id_token_private_key_pem": rsa_pem, "id_token_kid": "test-rs256-key"}
    ) as client:
        assert client.app.state.config.id_token_alg == "RS256"
        await reseed_client(client, client_secret=CLIENT_SECRET)
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


async def test_rfc9701_rs256_used_even_when_id_tokens_are_hs256(rsa_pem):
    """The keyset's RS256 key is published in JWKS regardless of
    `id_token_alg`, so it is the most verifiable key available and wins
    even when id_tokens are symmetric."""
    async with build_client_app(
        {
            "id_token_private_key_pem": rsa_pem,
            "id_token_kid": "test-rs256-key",
            "id_token_alg": "HS256",
        }
    ) as client:
        assert client.app.state.config.id_token_alg == "HS256"
        await reseed_client(client, client_secret=CLIENT_SECRET)
        access_token = await _client_credentials_token(client)
        resp = await _introspect(client, access_token, accept=JWT_MEDIA_TYPE)
        assert resp.status_code == 200, resp.text

        header = jwt.get_unverified_header(resp.text)
        assert header["alg"] == "RS256"
        assert header["kid"] == "test-rs256-key"


async def test_rfc9701_public_client_without_rs256_key_is_rejected(client_app):
    """No RS256 key and no client secret means no key the client could
    verify with — a JSON downgrade would be a silent, unauthenticated
    answer, so the request is refused instead."""
    await reseed_client(client_app, client_secret="", token_endpoint_auth_method="none")

    resp = await _introspect(client_app, "not-a-real-token", accept=JWT_MEDIA_TYPE, secret="")

    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert "RS256" in body["error_description"]


async def test_rfc9701_public_client_still_gets_json_without_the_jwt_accept(client_app):
    await reseed_client(client_app, client_secret="", token_endpoint_auth_method="none")

    resp = await _introspect(client_app, "not-a-real-token", accept="application/json", secret="")

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"active": False}


async def test_rfc9701_response_has_no_store(jwt_client_app):
    access_token = await _client_credentials_token(jwt_client_app)
    resp = await _introspect(jwt_client_app, access_token, accept=JWT_MEDIA_TYPE)

    assert resp.status_code == 200, resp.text
    assert JWT_MEDIA_TYPE in resp.headers["content-type"]
    assert resp.headers["cache-control"] == "no-store"
