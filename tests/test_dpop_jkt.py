"""Divergence 52: the RFC 9449 §10 `dpop_jkt` authorization-request parameter.

`/oauth/authorize` accepts `dpop_jkt` from the query string, from a PAR-pushed
body, and from a JAR overlay; it must be a 43-character base64url SHA-256 JWK
thumbprint (anything else is an `invalid_request` through the redirect
channel). The accepted value is recorded in `app.state.dpop_code_bindings`
(`services/dpop_bindings.py`) against the issued authorization code, and
`/oauth/token` refuses to redeem that code unless the request carries a DPoP
proof from the SAME key.

The Rust server implements none of this — it parses `dpop_jkt` nowhere, so
there is no parity constraint here and no Rust test to port.

**Single-process caveat**: the binding lives in process memory (the
`AuthorizationCode` table is Rust-owned and may not grow a column), so a code
redeemed on a different instance from the one that issued it finds no binding
and skips the check. Same limitation as `ParStore` and `DpopReplayStore`.
"""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlparse

from oauth2_server.services.dpop import jwk_thumbprint
from tests.helpers import (
    generate_dpop_key,
    login_session,
    make_dpop_proof,
    post_token,
)
from tests.test_jar import _signed_claims, make_hs256_jar
from tests.test_token_endpoint import _pkce_pair

TOKEN_URL = "https://auth.example.com/oauth/token"
REDIRECT_URI = "https://a.example/cb"
BASIC = ("client1", "s3cret")


async def _authorize_code(client_app, **extra_params) -> tuple[str, str]:
    """Log in, GET /oauth/authorize with PKCE + `extra_params`, return
    `(code, code_verifier)`."""
    await login_session(client_app)
    verifier, challenge = _pkce_pair()
    params = {
        "response_type": "code",
        "client_id": "client1",
        "redirect_uri": REDIRECT_URI,
        "scope": "read",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    params.update(extra_params)
    resp = await client_app.get("/oauth/authorize", params=params)
    assert resp.status_code == 302, resp.text
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert "code" in query, query
    return query["code"][0], verifier


async def _push_par(client_app, data: dict):
    """POST /oauth/par as client1 (client_secret_basic)."""
    raw = base64.b64encode(b"client1:s3cret").decode()
    return await client_app.post("/oauth/par", data=data, headers={"Authorization": "Basic " + raw})


async def _redeem(client_app, code: str, verifier: str, proof: str | None = None):
    headers = {"DPoP": proof} if proof is not None else None
    return await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "client1",
            "code_verifier": verifier,
        },
        basic_auth=BASIC,
        headers=headers,
    )


# --- the three request channels `dpop_jkt` can arrive through ----------------


async def test_dpop_jkt_via_query_binds_code_and_matching_proof_redeems(client_app):
    key = generate_dpop_key()
    jkt = jwk_thumbprint(key[1])

    code, verifier = await _authorize_code(client_app, dpop_jkt=jkt)
    assert client_app.app.state.dpop_code_bindings.take(code) == jkt
    # `take` above consumed it; re-bind so the redemption below sees it.
    client_app.app.state.dpop_code_bindings.bind(code, jkt)

    proof, _ = make_dpop_proof(TOKEN_URL, "POST", key)
    resp = await _redeem(client_app, code, verifier, proof)

    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "DPoP"


async def test_dpop_jkt_via_par(client_app):
    key = generate_dpop_key()
    jkt = jwk_thumbprint(key[1])
    verifier, challenge = _pkce_pair()

    par = await _push_par(
        client_app,
        {
            "client_id": "client1",
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "dpop_jkt": jkt,
        },
    )
    assert par.status_code == 201, par.text

    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "request_uri": par.json()["request_uri"],
            "client_id": "client1",
            "response_type": "code",
        },
    )
    assert resp.status_code == 302, resp.text
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]

    # The PAR-pushed `dpop_jkt` survived the merge onto the authorize request.
    assert client_app.app.state.dpop_code_bindings.take(code) == jkt
    client_app.app.state.dpop_code_bindings.bind(code, jkt)
    proof, _ = make_dpop_proof(TOKEN_URL, "POST", key)
    assert (await _redeem(client_app, code, verifier, proof)).status_code == 200


async def test_dpop_jkt_via_jar_overlay(client_app):
    key = generate_dpop_key()
    jkt = jwk_thumbprint(key[1])
    verifier, challenge = _pkce_pair()

    jar = make_hs256_jar(
        _signed_claims(
            "client1",
            redirect_uri=REDIRECT_URI,
            scope="read",
            code_challenge=challenge,
            code_challenge_method="S256",
            dpop_jkt=jkt,
        ),
        "s3cret",
    )
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": REDIRECT_URI,
            "request": jar,
        },
    )
    assert resp.status_code == 302, resp.text
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]

    assert client_app.app.state.dpop_code_bindings.take(code) == jkt
    client_app.app.state.dpop_code_bindings.bind(code, jkt)
    proof, _ = make_dpop_proof(TOKEN_URL, "POST", key)
    assert (await _redeem(client_app, code, verifier, proof)).status_code == 200


# --- redemption enforcement --------------------------------------------------


async def test_dpop_jkt_redemption_without_proof_invalid_grant(client_app):
    key = generate_dpop_key()
    code, verifier = await _authorize_code(client_app, dpop_jkt=jwk_thumbprint(key[1]))

    resp = await _redeem(client_app, code, verifier)

    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["error"] == "invalid_grant"
    assert body["error_description"] == "authorization code is bound to a different DPoP key"


async def test_dpop_jkt_redemption_wrong_key_invalid_grant(client_app):
    code, verifier = await _authorize_code(
        client_app, dpop_jkt=jwk_thumbprint(generate_dpop_key()[1])
    )

    # A perfectly valid proof — from the wrong key.
    proof, _ = make_dpop_proof(TOKEN_URL, "POST")
    resp = await _redeem(client_app, code, verifier, proof)

    assert resp.status_code == 400, resp.text
    assert resp.json()["error_description"] == (
        "authorization code is bound to a different DPoP key"
    )


async def test_dpop_jkt_binding_consumed_once(client_app):
    """A rejected redemption consumes BOTH the binding and the code.

    `take()` is destructive, so the binding is gone after the first attempt.
    To keep the guarantee that a mismatch cannot simply be retried with a
    different key, the failing branch also marks the code used — so the
    second attempt fails as a replay rather than sailing through unbound.
    """
    key = generate_dpop_key()
    code, verifier = await _authorize_code(client_app, dpop_jkt=jwk_thumbprint(key[1]))

    first = await _redeem(client_app, code, verifier)
    assert first.status_code == 400
    assert first.json()["error_description"] == (
        "authorization code is bound to a different DPoP key"
    )

    # Retry with an unrelated key now that the binding is spent.
    other_proof, _ = make_dpop_proof(TOKEN_URL, "POST")
    second = await _redeem(client_app, code, verifier, other_proof)
    assert second.status_code == 400, second.text
    assert second.json()["error_description"] == "authorization code has already been used"


async def test_pkce_mismatch_leaves_dpop_jkt_binding_unconsumed(client_app):
    """A PKCE failure must not spend the `dpop_jkt` binding.

    The PKCE check runs before the binding is taken, so a wrong
    `code_verifier` is rejected without consuming it — otherwise an attacker
    holding a stolen code could burn the binding with a junk verifier and
    then redeem the code with no DPoP proof at all.
    """
    key = generate_dpop_key()
    code, verifier = await _authorize_code(client_app, dpop_jkt=jwk_thumbprint(key[1]))

    wrong = await _redeem(client_app, code, "a" * len(verifier))
    assert wrong.status_code == 400, wrong.text
    assert wrong.json()["error"] == "invalid_grant"
    assert wrong.json()["error_description"] == "code_verifier does not match code_challenge"

    # Binding survived: the correct verifier with NO proof still fails on it.
    second = await _redeem(client_app, code, verifier)
    assert second.status_code == 400, second.text
    assert second.json()["error_description"] == (
        "authorization code is bound to a different DPoP key"
    )


# --- validation --------------------------------------------------------------


async def test_dpop_jkt_malformed_rejected_via_redirect(client_app):
    await login_session(client_app)
    _, challenge = _pkce_pair()

    for bad in ("short", "A" * 44, "A" * 42, "+" * 43, "A" * 42 + "=", "A" * 42 + "/"):
        resp = await client_app.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "client1",
                "redirect_uri": REDIRECT_URI,
                "scope": "read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "dpop_jkt": bad,
            },
        )
        assert resp.status_code == 302, f"{bad!r}: {resp.text}"
        query = parse_qs(urlparse(resp.headers["location"]).query)
        assert query["error"] == ["invalid_request"], bad
        assert query["error_description"] == [
            "dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint"
        ], bad


async def test_no_dpop_jkt_leaves_code_unbound(client_app):
    """Regression guard: without `dpop_jkt` nothing is bound, so a plain
    redemption (no proof) keeps working exactly as before."""
    code, verifier = await _authorize_code(client_app)
    assert client_app.app.state.dpop_code_bindings.take(code) is None
    assert (await _redeem(client_app, code, verifier)).status_code == 200


async def test_dpop_jkt_binding_is_per_code(client_app):
    """The store is keyed by code value: a bound code and an unbound one
    issued to the same client do not interfere."""
    key = generate_dpop_key()
    bound_code, bound_verifier = await _authorize_code(client_app, dpop_jkt=jwk_thumbprint(key[1]))
    unbound_code, unbound_verifier = await _authorize_code(client_app)

    assert (await _redeem(client_app, unbound_code, unbound_verifier)).status_code == 200

    proof, _ = make_dpop_proof(TOKEN_URL, "POST", key)
    assert (await _redeem(client_app, bound_code, bound_verifier, proof)).status_code == 200
