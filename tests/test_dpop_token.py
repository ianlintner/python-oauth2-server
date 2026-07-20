"""POST /oauth/token DPoP (RFC 9449) integration — `routes/token.py` DPoP
wiring: proof validation, per-client nonce gating, cnf.jkt binding, and
`token_type: "DPoP"` responses.

This is the e2e-grade coverage the Rust side lacks entirely (research-dpop.md
gotcha #1: "No end-to-end test exists that sends a REAL signed DPoP proof
through POST /oauth/token and asserts cnf.jkt in the issued access token or
token_type == 'DPoP'") — every test below drives the real endpoint with a
real signed ES256 proof via `httpx`/ASGI, not a unit-level call into
`validate_dpop_proof` directly (that's covered by `tests/test_dpop.py`).
"""

from __future__ import annotations

import base64
import json

import jwt
import pytest
from starlette.requests import Request

from oauth2_server.routes.token import _read_dpop_header
from oauth2_server.services.dpop import DpopError, jwk_thumbprint
from tests.conftest import build_client_app
from tests.helpers import generate_dpop_key, make_dpop_proof, post_token, seed_client
from tests.test_token_endpoint import run_code_flow

TOKEN_URL = "https://auth.example.com/oauth/token"


async def _seed_nonce_required_client(client_app, **overrides):
    fields = dict(
        client_id="dpop-client",
        client_secret="dpop-secret",
        dpop_nonce_required=True,
        grant_types=json.dumps(["client_credentials", "authorization_code", "refresh_token"]),
        scope="read openid email profile",
    )
    fields.update(overrides)
    return await seed_client(client_app.storage, **fields)


def _flip_tag_bit(nonce: str) -> str:
    """Corrupt a genuine nonce's HMAC tag (byte 10, inside the 16-byte tag
    region) without touching its bucket id — mirrors
    `tests/test_dpop_nonce.py::_flip_bit`."""
    padded = nonce + "=" * (-len(nonce) % 4)
    raw = bytearray(base64.urlsafe_b64decode(padded))
    raw[10] ^= 0x01
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()


async def test_client_credentials_with_es256_proof_binds_cnf(client_app):
    proof, pub_jwk = make_dpop_proof(TOKEN_URL, "POST")

    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("client1", "s3cret"),
        headers={"DPoP": proof},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "DPoP"
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["cnf"]["jkt"] == jwk_thumbprint(pub_jwk)


async def test_auth_code_flow_with_proof_binds_cnf(client_app):
    proof, pub_jwk = make_dpop_proof(TOKEN_URL, "POST")

    resp, _code = await run_code_flow(client_app, headers={"DPoP": proof})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "DPoP"
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["cnf"]["jkt"] == jwk_thumbprint(pub_jwk)


async def test_invalid_proof_rejected_400(client_app):
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("client1", "s3cret"),
        headers={"DPoP": "not-a-valid-dpop-proof"},
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_dpop_proof"


async def test_nonce_required_client_bootstrap(client_app):
    await _seed_nonce_required_client(client_app)
    key = generate_dpop_key()

    first_proof, _ = make_dpop_proof(TOKEN_URL, "POST", key)
    first_resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("dpop-client", "dpop-secret"),
        headers={"DPoP": first_proof},
    )
    assert first_resp.status_code == 400
    assert first_resp.json()["error"] == "use_dpop_nonce"
    nonce = first_resp.headers["DPoP-Nonce"]

    second_proof, pub_jwk = make_dpop_proof(TOKEN_URL, "POST", key, nonce)
    second_resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("dpop-client", "dpop-secret"),
        headers={"DPoP": second_proof},
    )
    assert second_resp.status_code == 200, second_resp.text
    body = second_resp.json()
    assert body["token_type"] == "DPoP"
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["cnf"]["jkt"] == jwk_thumbprint(pub_jwk)


async def test_forged_nonce_gets_invalid_dpop_proof_no_fresh_nonce(client_app):
    await _seed_nonce_required_client(client_app)
    real_nonce = client_app.app.state.dpop_nonce_issuer.issue()
    forged_nonce = _flip_tag_bit(real_nonce)

    proof, _ = make_dpop_proof(TOKEN_URL, "POST", nonce=forged_nonce)
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("dpop-client", "dpop-secret"),
        headers={"DPoP": proof},
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_dpop_proof"
    # A tamperer must not be handed a fresh nonce to keep guessing against.
    assert "dpop-nonce" not in {k.lower() for k in resp.headers}


async def test_refresh_carries_cnf_forward(client_app):
    proof, pub_jwk = make_dpop_proof(TOKEN_URL, "POST")
    resp, _code = await run_code_flow(client_app, headers={"DPoP": proof})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "DPoP"

    # No DPoP header at all on the refresh request — a fresh proof is not
    # required to keep the binding (documented parity gap).
    refresh_resp = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": body["refresh_token"]},
        basic_auth=("client1", "s3cret"),
    )

    assert refresh_resp.status_code == 200, refresh_resp.text
    refresh_body = refresh_resp.json()
    assert refresh_body["token_type"] == "DPoP"
    new_claims = jwt.decode(refresh_body["access_token"], options={"verify_signature": False})
    assert new_claims["cnf"]["jkt"] == jwk_thumbprint(pub_jwk)


async def test_no_proof_issues_plain_bearer(client_app):
    await _seed_nonce_required_client(client_app)

    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("dpop-client", "dpop-secret"),
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "Bearer"
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert "cnf" not in claims


async def test_opaque_mode_drops_cnf_silently(client_app):
    # Additional coverage beyond the 8 named tests: opaque access tokens
    # (Config(access_tokens_opaque=True)) have nowhere to carry a `cnf`
    # claim, so a presented proof must not upgrade the response to
    # token_type "DPoP" (research-dpop.md-adjacent parity note in
    # services/tokens.py::TokenService.issue's docstring).
    async with build_client_app({"access_tokens_opaque": True}) as opaque_app:
        proof, _pub_jwk = make_dpop_proof(TOKEN_URL, "POST")

        resp = await post_token(
            opaque_app,
            {"grant_type": "client_credentials"},
            basic_auth=("client1", "s3cret"),
            headers={"DPoP": proof},
        )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        # An opaque access token is a bare random string, not a JWT.
        with pytest.raises(jwt.PyJWTError):
            jwt.decode(body["access_token"], options={"verify_signature": False})


async def test_discovery_advertises_dpop_algs(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")

    assert resp.status_code == 200
    assert resp.json()["dpop_signing_alg_values_supported"] == ["ES256", "RS256"]


# --- _read_dpop_header (non-UTF-8 detection) --------------------------------
#
# Additional coverage beyond the 8 named tests above: the non-UTF-8 `DPoP`
# header path documented in routes/token.py's module docstring is exercised
# directly against a raw ASGI scope, since httpx's own header encoding makes
# it impractical to smuggle genuinely invalid UTF-8 bytes through the full
# httpx/ASGITransport stack in an e2e test.


def _request_with_raw_header(name: bytes, value: bytes) -> Request:
    scope = {"type": "http", "method": "POST", "path": "/oauth/token", "headers": [(name, value)]}
    return Request(scope)


def test_read_dpop_header_rejects_non_utf8():
    request = _request_with_raw_header(b"dpop", b"\xff\xfe-not-valid-utf8")

    with pytest.raises(DpopError) as exc_info:
        _read_dpop_header(request)
    assert exc_info.value.error == "invalid_request"
    assert exc_info.value.description == "DPoP header is not valid UTF-8"


def test_read_dpop_header_returns_none_when_absent():
    request = _request_with_raw_header(b"authorization", b"Bearer abc")
    assert _read_dpop_header(request) is None


def test_read_dpop_header_decodes_valid_value():
    request = _request_with_raw_header(b"dpop", b"a-proof-value")
    assert _read_dpop_header(request) == "a-proof-value"
