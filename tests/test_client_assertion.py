"""RFC 7523 §3 JWT client authentication — `client_secret_jwt` /
`private_key_jwt`, the `(client_id, jti)` replay guard, and the `jwks_uri`
TTL cache.

Ported alongside `services/client_assertion.py` + `services/jwks_cache.py`
from the Rust `validate_jwt_client_assertion` / `enforce_jti_replay` /
`resolve_client_jwks` / `JwksCache` implementations.
"""

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from oauth2_server.services.client_assertion import (
    JWT_BEARER_ASSERTION_TYPE,
    JtiReplayGuard,
)
from oauth2_server.services.jwks_cache import (
    DEFAULT_TTL_SECS,
    JWKS_FETCH_TIMEOUT_SECS,
    MAX_TTL_SECS,
    MIN_TTL_SECS,
    JwksCache,
    parse_cache_control_max_age,
)
from tests.helpers import (
    generate_rsa_keypair,
    make_client_assertion,
    post_token,
    reseed_client,
)

# PyJWT warns (`InsecureKeyLengthWarning`, RFC 7518 §3.2) when an HMAC key is
# shorter than 32 bytes, and the shared `seed_client` fixture's `s3cret` is 6.
# Every `client_secret_jwt` test below reseeds `client1` with these instead, so
# the suite stays warning-free without a blanket filter.
CLIENT_SECRET_JWT_SECRET = "client1-secret-jwt-key-0123456789abcdef"
WRONG_CLIENT_SECRET = "wrong-secret-0123456789abcdefghijklmnop"


async def reseed_secret_jwt_client(client_app, **overrides):
    """Reseed `client1` as a `client_secret_jwt` client whose secret is long
    enough for HS256 (see `CLIENT_SECRET_JWT_SECRET`)."""
    return await reseed_client(
        client_app,
        token_endpoint_auth_method="client_secret_jwt",
        client_secret=CLIENT_SECRET_JWT_SECRET,
        **overrides,
    )


def generate_private_rsa_jwks(kid: str = "client-key-1") -> tuple[bytes, dict]:
    """Return `(private_key_pem, jwks_document)` where the JWKS carries the
    PRIVATE key material (`d`/`p`/`q`).

    A plausible client misconfiguration — registration only checks that
    `jwks` is a JSON object — which must be rejected as `invalid_client`
    rather than crashing the token endpoint.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key, as_dict=True)
    private_jwk["kid"] = kid
    return pem, {"keys": [private_jwk]}


def assertion_form(assertion: str, **extra) -> dict:
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": JWT_BEARER_ASSERTION_TYPE,
        "client_assertion": assertion,
        "client_id": "client1",
    }
    form.update(extra)
    return {k: v for k, v in form.items() if v is not None}


# --------------------------------------------------------------------------
# client_secret_jwt (HS256)
# --------------------------------------------------------------------------


async def test_rfc7523_client_secret_jwt_authentication(client_app):
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "Bearer"


async def test_rfc7523_client_secret_jwt_wrong_secret_fails(client_app):
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion("client1", WRONG_CLIENT_SECRET, "HS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"] == "invalid_client"
    assert "client_secret_jwt validation failed" in resp.json()["error_description"]


async def test_client_secret_jwt_rejects_rs256_alg(client_app):
    await reseed_secret_jwt_client(client_app)
    private_pem, _ = generate_rsa_keypair()
    assertion = make_client_assertion("client1", private_pem, "RS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "client_secret_jwt requires HS256 algorithm"


# --------------------------------------------------------------------------
# private_key_jwt (RS256, inline jwks)
# --------------------------------------------------------------------------


async def test_rfc7523_private_key_jwt_authentication(client_app):
    private_pem, jwks = generate_rsa_keypair()
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks=json.dumps(jwks),
    )
    assertion = make_client_assertion(
        "client1", private_pem, "RS256", headers={"kid": "client-key-1"}
    )
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "Bearer"


async def test_private_key_jwt_kid_mismatch_rejected(client_app):
    private_pem, jwks = generate_rsa_keypair()
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks=json.dumps(jwks),
    )
    assertion = make_client_assertion(
        "client1", private_pem, "RS256", headers={"kid": "some-other-kid"}
    )
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "No matching kid in client JWKS"


async def test_private_key_jwt_rejects_hs256_alg(client_app):
    _, jwks = generate_rsa_keypair()
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks=json.dumps(jwks),
    )
    assertion = make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "private_key_jwt requires RS256 algorithm"


async def test_private_key_jwt_private_jwk_rejected(client_app):
    """A registered JWKS carrying private key material must not reach
    `jwt.decode` — `RSAAlgorithm.from_jwk` hands back an `RSAPrivateKey`,
    whose missing `.verify` would escape as an `AttributeError` (500)
    rather than the contracted `invalid_client` body."""
    private_pem, private_jwks = generate_private_rsa_jwks()
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks=json.dumps(private_jwks),
    )
    assertion = make_client_assertion(
        "client1", private_pem, "RS256", headers={"kid": "client-key-1"}
    )
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"] == "invalid_client"
    assert resp.json()["error_description"] == "Client JWKS key is not an RSA public key"


async def test_private_key_jwt_without_jwks_rejected(client_app):
    private_pem, _ = generate_rsa_keypair()
    await reseed_client(client_app, token_endpoint_auth_method="private_key_jwt")
    assertion = make_client_assertion("client1", private_pem, "RS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert (
        resp.json()["error_description"]
        == "Client must register jwks or jwks_uri for private_key_jwt"
    )


# --------------------------------------------------------------------------
# Claim validation
# --------------------------------------------------------------------------


async def test_assertion_wrong_audience_rejected(client_app):
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion(
        "client1", CLIENT_SECRET_JWT_SECRET, "HS256", aud="https://evil.example/oauth/token"
    )
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert "client_secret_jwt validation failed" in resp.json()["error_description"]


async def test_assertion_iss_sub_mismatch_rejected(client_app):
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion(
        "client1", CLIENT_SECRET_JWT_SECRET, "HS256", iss="someone-else"
    )
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "JWT iss/sub must equal client_id"


async def test_assertion_missing_jti_rejected(client_app):
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256", jti=None)
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert (
        resp.json()["error_description"]
        == "client_assertion missing required jti claim (RFC 7523 §3)"
    )


async def test_assertion_expired_rejected(client_app):
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion(
        "client1",
        CLIENT_SECRET_JWT_SECRET,
        "HS256",
        exp=int(time.time()) - 60,
        iat=int(time.time()) - 120,
    )
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert "client_secret_jwt validation failed" in resp.json()["error_description"]


async def test_vector_l_client_assertion_jti_replay(client_app):
    """RFC 7523 §3 / RFC 9700 §2.5: the same `(client_id, jti)` presented
    twice must be rejected the second time."""
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256")

    first = await post_token(client_app, assertion_form(assertion))
    assert first.status_code == 200, first.text

    replay = await post_token(client_app, assertion_form(assertion))
    assert replay.status_code == 401, replay.text
    assert replay.json()["error"] == "invalid_client"
    assert replay.json()["error_description"] == "client_assertion jti has already been used"


# --------------------------------------------------------------------------
# Dispatch / form shape
# --------------------------------------------------------------------------


async def test_assertion_without_form_client_id_resolves_from_sub(client_app):
    """Divergence 36: a form carrying only `client_assertion` (no
    `client_id`) resolves the client from the assertion's unverified `sub`."""
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256")
    resp = await post_token(client_app, assertion_form(assertion, client_id=None))
    assert resp.status_code == 200, resp.text


async def test_missing_client_assertion_type_rejected(client_app):
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256")
    resp = await post_token(client_app, assertion_form(assertion, client_assertion_type=None))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "Missing client_assertion_type"


async def test_unsupported_client_assertion_type_rejected(client_app):
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256")
    resp = await post_token(
        client_app, assertion_form(assertion, client_assertion_type="urn:example:saml2-bearer")
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "Unsupported client_assertion_type"


async def test_missing_client_assertion_rejected(client_app):
    await reseed_secret_jwt_client(client_app)
    resp = await post_token(
        client_app,
        {
            "grant_type": "client_credentials",
            "client_id": "client1",
            "client_assertion_type": JWT_BEARER_ASSERTION_TYPE,
        },
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "Missing client_assertion"


async def test_jwt_client_presenting_basic_auth_is_rejected(client_app):
    """Dispatch is strictly on the REGISTERED method: a `client_secret_jwt`
    client cannot fall back to `client_secret_basic`, even with the correct
    secret."""
    await reseed_secret_jwt_client(client_app)
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("client1", CLIENT_SECRET_JWT_SECRET),
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "Missing client_assertion_type"


# --------------------------------------------------------------------------
# jwks_uri fetch + cache
# --------------------------------------------------------------------------


def _install_mock_jwks_transport(client_app, handler) -> None:
    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client_app.app.state.http_client = mock_client
    client_app.app.state.jwks_cache = JwksCache(mock_client)


async def test_private_key_jwt_jwks_uri_fetched_once_and_cached(client_app):
    private_pem, jwks = generate_rsa_keypair()
    fetches: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetches.append(str(request.url))
        return httpx.Response(200, json=jwks, headers={"Cache-Control": "max-age=300"})

    _install_mock_jwks_transport(client_app, handler)
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks_uri="https://client.example/jwks.json",
    )

    for _ in range(2):
        assertion = make_client_assertion(
            "client1", private_pem, "RS256", headers={"kid": "client-key-1"}
        )
        resp = await post_token(client_app, assertion_form(assertion))
        assert resp.status_code == 200, resp.text

    assert fetches == ["https://client.example/jwks.json"]


async def test_jwks_fetch_uses_explicit_timeout(client_app):
    """The 10 s JWKS fetch budget must be `JwksCache`'s own, not whatever
    timeout the shared outbound client happens to have been built with."""
    private_pem, jwks = generate_rsa_keypair()
    timeouts: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions.get("timeout"))
        return httpx.Response(200, json=jwks)

    _install_mock_jwks_transport(client_app, handler)
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks_uri="https://client.example/jwks.json",
    )
    assertion = make_client_assertion(
        "client1", private_pem, "RS256", headers={"kid": "client-key-1"}
    )
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 200, resp.text
    assert timeouts == [
        dict.fromkeys(("connect", "pool", "read", "write"), JWKS_FETCH_TIMEOUT_SECS)
    ]


async def test_private_key_jwt_jwks_uri_http_error_rejected(client_app):
    """A fetch failure is reported as a fixed string: echoing the URL, the
    upstream status or the transport exception back to the caller would turn
    the token endpoint into a port-scan / SSRF oracle."""
    private_pem, _ = generate_rsa_keypair()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    _install_mock_jwks_transport(client_app, handler)
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks_uri="https://client.example/jwks.json",
    )
    assertion = make_client_assertion("client1", private_pem, "RS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    description = resp.json()["error_description"]
    assert description == "Failed to fetch jwks_uri"
    assert "client.example" not in description
    assert "500" not in description
    assert "boom" not in description


async def test_jwks_uri_transport_error_description_leaks_nothing(client_app):
    private_pem, _ = generate_rsa_keypair()

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("[Errno 61] Connection refused", request=request)

    _install_mock_jwks_transport(client_app, handler)
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks_uri="https://client.example/jwks.json",
    )
    assertion = make_client_assertion("client1", private_pem, "RS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    description = resp.json()["error_description"]
    assert description == "Failed to fetch jwks_uri"
    assert "client.example" not in description
    assert "Connection refused" not in description


async def test_jwks_uri_invalid_json_description_leaks_nothing(client_app):
    private_pem, _ = generate_rsa_keypair()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="{not json")

    _install_mock_jwks_transport(client_app, handler)
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks_uri="https://client.example/jwks.json",
    )
    assertion = make_client_assertion("client1", private_pem, "RS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    description = resp.json()["error_description"]
    assert description == "jwks_uri returned an invalid JWKS document"
    assert "client.example" not in description


@pytest.mark.parametrize(
    ("cache_control", "expected"),
    [
        ("max-age=5", MIN_TTL_SECS),
        ("max-age=999999", MAX_TTL_SECS),
        (None, DEFAULT_TTL_SECS),
        ("public, max-age=600", 600),
        ("no-cache", DEFAULT_TTL_SECS),
    ],
)
def test_jwks_cache_ttl_from_cache_control_clamped(cache_control, expected):
    headers = httpx.Headers({} if cache_control is None else {"Cache-Control": cache_control})
    assert parse_cache_control_max_age(headers) == expected


# --------------------------------------------------------------------------
# JtiReplayGuard unit tests
# --------------------------------------------------------------------------


def test_jti_guard_first_observation_fresh_replay_rejected():
    guard = JtiReplayGuard()
    assert guard.observe("c1", "jti-a", 60) is True
    assert guard.observe("c1", "jti-a", 60) is False


def test_jti_guard_different_clients_do_not_collide():
    guard = JtiReplayGuard()
    assert guard.observe("c1", "jti-x", 60) is True
    assert guard.observe("c2", "jti-x", 60) is True


def test_jti_guard_expired_entry_fresh_again(monkeypatch):
    guard = JtiReplayGuard()
    clock = {"now": 1_000.0}
    monkeypatch.setattr(time, "monotonic", lambda: clock["now"])

    assert guard.observe("c1", "jti-z", 10) is True
    clock["now"] = 1_005.0
    assert guard.observe("c1", "jti-z", 10) is False
    clock["now"] = 1_011.0
    assert guard.observe("c1", "jti-z", 10) is True


def test_jti_guard_ttl_clamped_to_five_minutes(monkeypatch):
    guard = JtiReplayGuard()
    clock = {"now": 1_000.0}
    monkeypatch.setattr(time, "monotonic", lambda: clock["now"])

    assert guard.observe("c1", "jti-long", 86_400) is True
    clock["now"] = 1_000.0 + 301
    assert guard.observe("c1", "jti-long", 86_400) is True


def test_jti_guard_bounded_by_max_entries():
    guard = JtiReplayGuard(max_entries=4)
    for i in range(8):
        assert guard.observe("c", f"j-{i}", 60) is True
    assert len(guard._entries) <= 4


# --------------------------------------------------------------------------
# Other endpoints
# --------------------------------------------------------------------------


async def test_introspection_accepts_client_secret_jwt(client_app):
    """Rust parity: every endpoint expects `aud` = the TOKEN endpoint URL,
    including /oauth/introspect."""
    await reseed_secret_jwt_client(client_app)

    token_resp = await post_token(
        client_app,
        assertion_form(make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256")),
    )
    assert token_resp.status_code == 200, token_resp.text
    access_token = token_resp.json()["access_token"]

    resp = await client_app.post(
        "/oauth/introspect",
        data={
            "token": access_token,
            "client_id": "client1",
            "client_assertion_type": JWT_BEARER_ASSERTION_TYPE,
            "client_assertion": make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256"),
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["active"] is True


async def test_assertion_spent_at_token_endpoint_rejected_at_introspect(client_app):
    """`app.state.jti_guard` is shared across every endpoint that
    authenticates a client, so an assertion already spent at /oauth/token
    cannot be replayed at /oauth/introspect."""
    await reseed_secret_jwt_client(client_app)
    assertion = make_client_assertion("client1", CLIENT_SECRET_JWT_SECRET, "HS256")

    token_resp = await post_token(client_app, assertion_form(assertion))
    assert token_resp.status_code == 200, token_resp.text
    access_token = token_resp.json()["access_token"]

    resp = await client_app.post(
        "/oauth/introspect",
        data={
            "token": access_token,
            "client_id": "client1",
            "client_assertion_type": JWT_BEARER_ASSERTION_TYPE,
            "client_assertion": assertion,
        },
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"] == "invalid_client"
    assert resp.json()["error_description"] == "client_assertion jti has already been used"


async def test_introspection_accepts_private_key_jwt(client_app):
    private_pem, jwks = generate_rsa_keypair()
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks=json.dumps(jwks),
    )

    def fresh_assertion() -> str:
        return make_client_assertion(
            "client1", private_pem, "RS256", headers={"kid": "client-key-1"}
        )

    token_resp = await post_token(client_app, assertion_form(fresh_assertion()))
    assert token_resp.status_code == 200, token_resp.text
    access_token = token_resp.json()["access_token"]

    resp = await client_app.post(
        "/oauth/introspect",
        data={
            "token": access_token,
            "client_id": "client1",
            "client_assertion_type": JWT_BEARER_ASSERTION_TYPE,
            "client_assertion": fresh_assertion(),
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["active"] is True


async def test_revocation_accepts_private_key_jwt(client_app):
    """/oauth/revoke authenticates the client the same way — and the
    expected `aud` is still the TOKEN endpoint URL."""
    private_pem, jwks = generate_rsa_keypair()
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks=json.dumps(jwks),
    )

    def fresh_assertion() -> str:
        return make_client_assertion(
            "client1", private_pem, "RS256", headers={"kid": "client-key-1"}
        )

    token_resp = await post_token(client_app, assertion_form(fresh_assertion()))
    assert token_resp.status_code == 200, token_resp.text
    access_token = token_resp.json()["access_token"]

    resp = await client_app.post(
        "/oauth/revoke",
        data={
            "token": access_token,
            "client_id": "client1",
            "client_assertion_type": JWT_BEARER_ASSERTION_TYPE,
            "client_assertion": fresh_assertion(),
        },
    )
    assert resp.status_code == 200, resp.text

    stored = await client_app.storage.get_token_by_access_token(access_token)
    assert stored.revoked is True


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


async def test_rfc7591_private_key_jwt_requires_jwks(client_app):
    resp = await client_app.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_client_metadata"
    assert "jwks" in resp.json()["error_description"]

    _, jwks = generate_rsa_keypair()
    ok = await client_app.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks,
        },
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["token_endpoint_auth_method"] == "private_key_jwt"
    assert ok.json()["jwks"] == jwks


async def test_rfc7591_jwks_and_jwks_uri_mutually_exclusive(client_app):
    _, jwks = generate_rsa_keypair()
    resp = await client_app.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": jwks,
            "jwks_uri": "https://app.example/jwks.json",
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_client_metadata"
    assert resp.json()["error_description"] == "jwks and jwks_uri are mutually exclusive"


async def test_registration_accepts_client_secret_jwt(client_app):
    resp = await client_app.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "client_secret_jwt",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["token_endpoint_auth_method"] == "client_secret_jwt"


async def test_registration_private_key_jwt_echoes_jwks_uri(client_app):
    resp = await client_app.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": "https://app.example/jwks.json",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["jwks_uri"] == "https://app.example/jwks.json"


@pytest.mark.parametrize(
    "jwks_uri",
    [
        "http://app.example/jwks.json",
        "https://localhost/jwks.json",
        "https://localhost:8443/jwks.json",
        "https://127.0.0.1/jwks.json",
        "https://127.0.0.53:9200/jwks.json",
        "https://[::1]/jwks.json",
        "https://169.254.169.254/latest/meta-data",
        "https://[fe80::1]/jwks.json",
        "/jwks.json",
        "https:///jwks.json",
        "https://app.example/jwks.json#frag",
    ],
)
async def test_registration_rejects_unsafe_jwks_uri(client_app, jwks_uri):
    """SSRF / port-scan guard: `jwks_uri` is the one client-supplied URL the
    server itself dereferences, so it must be an absolute `https` URL that
    does not point back at the host's own network."""
    resp = await client_app.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks_uri": jwks_uri,
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json() == {
        "error": "invalid_client_metadata",
        "error_description": "jwks_uri must be an absolute https URL",
    }


async def test_private_key_jwt_inline_jwks_not_an_object_rejected(client_app):
    """A syntactically-valid inline JWKS that is not a `{"keys": [...]}`
    object must still produce a 401, not an unhandled 500."""
    private_pem, _ = generate_rsa_keypair()
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks=json.dumps([{"kty": "RSA"}]),
    )
    assertion = make_client_assertion("client1", private_pem, "RS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "Client JWKS missing 'keys' array"


async def test_private_key_jwt_inline_jwks_invalid_json_rejected(client_app):
    private_pem, _ = generate_rsa_keypair()
    await reseed_client(client_app, token_endpoint_auth_method="private_key_jwt", jwks="{not json")
    assertion = make_client_assertion("client1", private_pem, "RS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_description"] == "Client inline JWKS is not valid JSON"


async def test_private_key_jwt_jwks_uri_document_missing_keys_rejected(client_app):
    private_pem, _ = generate_rsa_keypair()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not_keys": []})

    _install_mock_jwks_transport(client_app, handler)
    await reseed_client(
        client_app,
        token_endpoint_auth_method="private_key_jwt",
        jwks_uri="https://client.example/jwks.json",
    )
    assertion = make_client_assertion("client1", private_pem, "RS256")
    resp = await post_token(client_app, assertion_form(assertion))
    assert resp.status_code == 401, resp.text
    description = resp.json()["error_description"]
    assert description == "jwks_uri returned an invalid JWKS document"
    assert "client.example" not in description
