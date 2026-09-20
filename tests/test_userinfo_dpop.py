"""Phase 4c Task 4: resource-side DPoP / mTLS enforcement at
`GET|POST /oauth/userinfo` (`routes/wellknown.py::userinfo`).

Divergences 50 and 51 (both security-motivated; Rust enforces neither —
its userinfo handler parses `Bearer ` only and ignores `cnf` entirely):

- **50** — the DPoP `ath` claim is REQUIRED where a proof is presented
  alongside an access token (here), and ignored at the token and
  introspection endpoints, which have no access token to bind to.
- **51** — userinfo accepts `Authorization: DPoP <token>` and enforces the
  token's `cnf.jkt`. Every failure is a 401 `{"error": "invalid_token",
  ...}` with `WWW-Authenticate: DPoP error="invalid_token"`; a
  certificate-bound token (`cnf["x5t#S256"]`, divergence 49) keeps the
  `Bearer` challenge. Unbound tokens behave exactly as before
  (`tests/test_wellknown.py`).
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from oauth2_server.security import decode_unverified_claims
from oauth2_server.services.dpop import jwk_thumbprint
from tests.conftest import build_client_app
from tests.helpers import generate_dpop_key, make_dpop_proof
from tests.test_token_endpoint import run_code_flow

TOKEN_URL = "https://auth.example.com/oauth/token"
USERINFO_URL = "https://auth.example.com/oauth/userinfo"

CERT_THUMBPRINT = "Zm9vYmFyLXRodW1icHJpbnQtMzItYnl0ZXMtYjY0dQ"
OTHER_THUMBPRINT = "b3RoZXItdGh1bWJwcmludC0zMi1ieXRlcy1iNjR1Cg"

DPOP_CHALLENGE = 'DPoP error="invalid_token"'
BEARER_CHALLENGE = 'Bearer error="invalid_token"'


def ath_for(access_token: str) -> str:
    """base64url-no-pad(SHA-256(access token as presented))."""
    digest = hashlib.sha256(access_token.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def _bound_token(client_app, key) -> str:
    """Run the authorization-code flow with a DPoP proof at redemption and
    return the resulting `cnf.jkt`-bound, user-bound access token."""
    proof, pub_jwk = make_dpop_proof(TOKEN_URL, "POST", key)
    resp, _code = await run_code_flow(
        client_app, scope="openid email profile", headers={"DPoP": proof}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "DPoP"
    assert decode_unverified_claims(body["access_token"])["cnf"] == {"jkt": jwk_thumbprint(pub_jwk)}
    return body["access_token"]


async def _userinfo(
    client_app,
    token: str,
    *,
    scheme: str = "DPoP",
    proof: str | None = None,
    method: str = "GET",
    extra_headers: dict | None = None,
):
    headers = {"Authorization": f"{scheme} {token}"}
    if proof is not None:
        headers["DPoP"] = proof
    headers.update(extra_headers or {})
    return await client_app.request(method, "/oauth/userinfo", headers=headers)


def _resource_proof(token: str, key=None, *, method: str = "GET", ath: str | None = None):
    proof, _pub = make_dpop_proof(
        USERINFO_URL,
        method,
        key,
        extra_claims={"ath": ath if ath is not None else ath_for(token)},
    )
    return proof


# --- divergence 51: DPoP-bound tokens ------------------------------------


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_bound_token_with_valid_dpop_proof_succeeds_get_and_post(method):
    async with build_client_app() as client_app:
        key = generate_dpop_key()
        token = await _bound_token(client_app, key)

        resp = await _userinfo(
            client_app,
            token,
            proof=_resource_proof(token, key, method=method),
            method=method,
        )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["sub"] == "u1"
        assert body["email"] == "user_rfc@example.test"


async def test_bound_token_as_bearer_rejected_with_dpop_challenge():
    """A `cnf.jkt`-bound token presented as a Bearer token is rejected even
    when a perfectly valid proof rides along — the scheme itself is the
    client's claim about how the token is being presented."""
    async with build_client_app() as client_app:
        key = generate_dpop_key()
        token = await _bound_token(client_app, key)

        resp = await _userinfo(
            client_app, token, scheme="Bearer", proof=_resource_proof(token, key)
        )

        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"
        assert resp.headers["www-authenticate"] == DPOP_CHALLENGE


async def test_bound_token_missing_proof_rejected():
    async with build_client_app() as client_app:
        key = generate_dpop_key()
        token = await _bound_token(client_app, key)

        resp = await _userinfo(client_app, token)

        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"
        assert resp.headers["www-authenticate"] == DPOP_CHALLENGE


async def test_bound_token_wrong_ath_rejected():
    async with build_client_app() as client_app:
        key = generate_dpop_key()
        token = await _bound_token(client_app, key)

        resp = await _userinfo(
            client_app,
            token,
            proof=_resource_proof(token, key, ath=ath_for("a-different-token")),
        )

        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"
        assert resp.headers["www-authenticate"] == DPOP_CHALLENGE


async def test_bound_token_wrong_key_rejected():
    """A proof that is valid in its own right but signed by a DIFFERENT key
    than the one the token is bound to."""
    async with build_client_app() as client_app:
        key = generate_dpop_key()
        token = await _bound_token(client_app, key)

        resp = await _userinfo(client_app, token, proof=_resource_proof(token, generate_dpop_key()))

        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"
        assert resp.headers["www-authenticate"] == DPOP_CHALLENGE


async def test_userinfo_proof_replay_rejected():
    """The resource endpoint shares `app.state.dpop_replay` with the token
    and introspection endpoints, so a proof is single-use here too."""
    async with build_client_app() as client_app:
        key = generate_dpop_key()
        token = await _bound_token(client_app, key)
        proof = _resource_proof(token, key)

        first = await _userinfo(client_app, token, proof=proof)
        assert first.status_code == 200, first.text

        replay = await _userinfo(client_app, token, proof=proof)
        assert replay.status_code == 401
        assert replay.headers["www-authenticate"] == DPOP_CHALLENGE


async def test_userinfo_proof_for_token_endpoint_rejected():
    """htu binding: a proof minted for `/oauth/token` must not be replayable
    against the resource endpoint."""
    async with build_client_app() as client_app:
        key = generate_dpop_key()
        token = await _bound_token(client_app, key)
        proof, _pub = make_dpop_proof(TOKEN_URL, "GET", key, extra_claims={"ath": ath_for(token)})

        resp = await _userinfo(client_app, token, proof=proof)

        assert resp.status_code == 401
        assert resp.headers["www-authenticate"] == DPOP_CHALLENGE


@pytest.mark.parametrize("scheme", ["dpop", "DPOP", "DPoP"])
async def test_dpop_scheme_case_insensitive(scheme):
    async with build_client_app() as client_app:
        key = generate_dpop_key()
        token = await _bound_token(client_app, key)

        resp = await _userinfo(client_app, token, scheme=scheme, proof=_resource_proof(token, key))

        assert resp.status_code == 200, resp.text


async def test_unbound_token_bearer_unchanged():
    """No `cnf` -> the pre-existing Bearer behavior, untouched."""
    async with build_client_app() as client_app:
        resp, _code = await run_code_flow(client_app, scope="openid email")
        token = resp.json()["access_token"]

        ok = await _userinfo(client_app, token, scheme="Bearer")
        assert ok.status_code == 200, ok.text
        assert ok.json()["sub"] == "u1"


async def test_unbound_token_via_dpop_scheme_without_proof_allowed():
    """An unbound token carries no `cnf`, so nothing is enforced regardless
    of the scheme the client used — no new rejection path for tokens the
    server never bound."""
    async with build_client_app() as client_app:
        resp, _code = await run_code_flow(client_app, scope="openid email")
        token = resp.json()["access_token"]

        ok = await _userinfo(client_app, token, scheme="dpop")
        assert ok.status_code == 200, ok.text


async def test_unknown_scheme_still_missing_token():
    async with build_client_app() as client_app:
        resp, _code = await run_code_flow(client_app, scope="openid email")
        token = resp.json()["access_token"]

        rejected = await _userinfo(client_app, token, scheme="Basic")
        assert rejected.status_code == 401
        assert rejected.headers["www-authenticate"] == "Bearer"
        assert rejected.json()["error_description"] == "Missing access token"


# --- divergence 49: certificate-bound tokens at userinfo ------------------


def _cert_headers(thumbprint: str | None = CERT_THUMBPRINT) -> dict:
    return {} if thumbprint is None else {"X-Client-Cert-Thumbprint": thumbprint}


async def _cert_bound_token(client_app) -> str:
    resp, _code = await run_code_flow(
        client_app, scope="openid email profile", headers=_cert_headers()
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


async def test_cert_bound_token_requires_thumbprint_at_userinfo():
    async with build_client_app(config_overrides={"trust_proxy_headers": True}) as client_app:
        token = await _cert_bound_token(client_app)

        matching = await _userinfo(
            client_app, token, scheme="Bearer", extra_headers=_cert_headers()
        )
        assert matching.status_code == 200, matching.text
        assert matching.json()["sub"] == "u1"

        missing = await _userinfo(client_app, token, scheme="Bearer")
        assert missing.status_code == 401
        assert missing.json()["error"] == "invalid_token"
        assert missing.headers["www-authenticate"] == BEARER_CHALLENGE

        wrong = await _userinfo(
            client_app, token, scheme="Bearer", extra_headers=_cert_headers(OTHER_THUMBPRINT)
        )
        assert wrong.status_code == 401
        assert wrong.headers["www-authenticate"] == BEARER_CHALLENGE


async def test_cert_bound_token_thumbprint_ignored_without_trust_proxy():
    """Divergence 47: a token minted behind an UNTRUSTED proxy never gets a
    `cnf`, so userinfo has nothing to enforce (and the forged header on the
    userinfo request reads as absent either way)."""
    async with build_client_app() as client_app:
        resp, _code = await run_code_flow(client_app, scope="openid email", headers=_cert_headers())
        token = resp.json()["access_token"]

        ok = await _userinfo(client_app, token, scheme="Bearer", extra_headers=_cert_headers())
        assert ok.status_code == 200, ok.text
