"""RFC 9449 §8 stateless DPoP nonce issuer — `services/dpop_nonce.py` unit
tests.

Ported by name from the Rust unit tests in `tests/rfc9700_dpop_nonce.rs`
(`missing_nonce_returns_use_dpop_nonce`, `valid_nonce_accepted`,
`forged_nonce_rejected_as_invalid_proof`, `stale_nonce_returns_use_dpop_nonce`,
`use_dpop_nonce_response_includes_header_and_body`) and
`crates/oauth2-actix/src/handlers/dpop_nonce.rs` unit tests
(`previous_bucket_accepted_current_plus_one_rejected`,
`nonce_from_different_secret_rejected`, `malformed_nonce_rejected`) — see
`.superpowers/sdd/research-dpop.md` `storage_methods` (`DpopNonceIssuer`
entry) and `tests_to_port`. `test_secret_decoding_formats` is new coverage
for the Python-only typed `DpopNonceError`/config-decoding surface that has
no direct Rust unit-test analogue (Rust's `from_env` decode order isn't
unit-tested there either).
"""

from __future__ import annotations

import base64
import logging
import struct
from urllib.parse import parse_qs, urlsplit

import pytest

from oauth2_server.services.dpop import DpopError, DpopValidated
from oauth2_server.services.dpop_nonce import (
    DpopNonceError,
    DpopNonceIssuer,
    decode_dpop_nonce_secret,
    enforce_dpop_nonce,
    use_dpop_nonce_response,
)
from tests.helpers import (
    generate_dpop_key,
    login_session,
    make_dpop_proof,
    post_token,
    seed_client,
)
from tests.test_token_endpoint import _pkce_pair, run_code_flow
from tests.test_userinfo_dpop import ath_for

SECRET_A = b"\x01" * 32
SECRET_B = b"\x02" * 32


def _flip_bit(nonce: str, byte_index: int) -> str:
    padded = nonce + "=" * (-len(nonce) % 4)
    raw = bytearray(base64.urlsafe_b64decode(padded))
    raw[byte_index] ^= 0x01
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()


# --- DpopNonceIssuer.issue / verify -----------------------------------------


def test_valid_nonce_accepted():
    issuer = DpopNonceIssuer(SECRET_A, lifetime_secs=300)
    nonce = issuer.issue()
    issuer.verify(nonce)  # must not raise


def test_forged_nonce_rejected_as_invalid_proof():
    issuer = DpopNonceIssuer(SECRET_A, lifetime_secs=300)
    nonce = issuer.issue()
    # Byte 10 sits inside the 16-byte HMAC tag (bytes 8-23) — flipping it
    # forges the tag without touching the bucket id.
    forged = _flip_bit(nonce, 10)

    with pytest.raises(DpopNonceError) as exc_info:
        issuer.verify(forged)
    assert exc_info.value.kind == "invalid"

    validated = DpopValidated(jkt="jkt", nonce=forged)
    with pytest.raises(DpopError) as dpop_exc_info:
        enforce_dpop_nonce(validated, issuer)
    assert dpop_exc_info.value.error == "invalid_dpop_proof"


def test_stale_nonce_returns_use_dpop_nonce(monkeypatch):
    import oauth2_server.services.dpop_nonce as dpop_nonce_module

    issuer = DpopNonceIssuer(SECRET_A, lifetime_secs=1)
    base_time = 1_000_000.0
    monkeypatch.setattr(dpop_nonce_module.time, "time", lambda: base_time)
    nonce = issuer.issue()

    # Two buckets later (2s, at 1s/bucket): current-1 no longer covers the
    # bucket the nonce was issued in.
    monkeypatch.setattr(dpop_nonce_module.time, "time", lambda: base_time + 2)

    with pytest.raises(DpopNonceError) as exc_info:
        issuer.verify(nonce)
    assert exc_info.value.kind == "stale"

    response = enforce_dpop_nonce(DpopValidated(jkt="jkt", nonce=nonce), issuer)
    assert response is not None
    assert response.status_code == 400
    assert response.headers["DPoP-Nonce"]
    assert response.body is not None


def test_previous_bucket_accepted_current_plus_one_rejected(monkeypatch):
    import oauth2_server.services.dpop_nonce as dpop_nonce_module

    issuer = DpopNonceIssuer(SECRET_A, lifetime_secs=1)
    base_time = 2_000_000.0
    monkeypatch.setattr(dpop_nonce_module.time, "time", lambda: base_time)
    nonce = issuer.issue()

    # current - 1: still within the accepted window.
    monkeypatch.setattr(dpop_nonce_module.time, "time", lambda: base_time + 1)
    issuer.verify(nonce)  # must not raise

    # current - 2 (from the nonce's perspective, one bucket further stale).
    monkeypatch.setattr(dpop_nonce_module.time, "time", lambda: base_time + 2)
    with pytest.raises(DpopNonceError) as exc_info:
        issuer.verify(nonce)
    assert exc_info.value.kind == "stale"

    # A nonce encoded for a future bucket (current + 1 relative to "now")
    # must also be rejected as stale, not accepted early.
    monkeypatch.setattr(dpop_nonce_module.time, "time", lambda: base_time)
    future_nonce = issuer.issue()
    monkeypatch.setattr(dpop_nonce_module.time, "time", lambda: base_time - 1)
    with pytest.raises(DpopNonceError) as exc_info:
        issuer.verify(future_nonce)
    assert exc_info.value.kind == "stale"


def test_nonce_from_different_secret_rejected():
    issuer_a = DpopNonceIssuer(SECRET_A, lifetime_secs=300)
    issuer_b = DpopNonceIssuer(SECRET_B, lifetime_secs=300)
    nonce = issuer_a.issue()

    with pytest.raises(DpopNonceError) as exc_info:
        issuer_b.verify(nonce)
    assert exc_info.value.kind == "invalid"
    assert "signature" in exc_info.value.description


def test_malformed_nonce_rejected():
    issuer = DpopNonceIssuer(SECRET_A, lifetime_secs=300)

    with pytest.raises(DpopNonceError) as exc_info:
        issuer.verify("not-valid-base64url!!!")
    assert exc_info.value.kind == "invalid"

    # Valid base64url that decodes to far fewer than the required 24 bytes.
    short = base64.urlsafe_b64encode(b"abc").rstrip(b"=").decode()
    with pytest.raises(DpopNonceError) as exc_info:
        issuer.verify(short)
    assert exc_info.value.kind == "invalid"
    assert "length" in exc_info.value.description


# --- use_dpop_nonce_response -------------------------------------------------


def test_use_dpop_nonce_response_includes_header_and_body():
    issuer = DpopNonceIssuer(SECRET_A, lifetime_secs=300)

    response = use_dpop_nonce_response(issuer, "DPoP proof must include a server-issued nonce")

    assert response.status_code == 400
    nonce_header = response.headers["DPoP-Nonce"]
    issuer.verify(nonce_header)  # must not raise — the header nonce is genuine

    import json

    body = json.loads(bytes(response.body))
    assert body == {
        "error": "use_dpop_nonce",
        "error_description": "DPoP proof must include a server-issued nonce",
    }


# --- enforce_dpop_nonce -------------------------------------------------------


def test_missing_nonce_returns_use_dpop_nonce():
    issuer = DpopNonceIssuer(SECRET_A, lifetime_secs=300)
    validated = DpopValidated(jkt="jkt", nonce=None)

    response = enforce_dpop_nonce(validated, issuer)

    assert response is not None
    assert response.status_code == 400
    assert response.headers["DPoP-Nonce"]

    import json

    body = json.loads(bytes(response.body))
    assert body["error"] == "use_dpop_nonce"
    assert body["error_description"] == "DPoP proof must include a server-issued nonce"


def test_valid_nonce_accepted_by_enforce():
    issuer = DpopNonceIssuer(SECRET_A, lifetime_secs=300)
    nonce = issuer.issue()
    validated = DpopValidated(jkt="jkt", nonce=nonce)

    assert enforce_dpop_nonce(validated, issuer) is None


# --- decode_dpop_nonce_secret -------------------------------------------------


def test_secret_decoding_formats(caplog):
    raw_secret = bytes(range(32))

    b64url = base64.urlsafe_b64encode(raw_secret).rstrip(b"=").decode()
    assert decode_dpop_nonce_secret(b64url) == raw_secret

    b64std = base64.b64encode(raw_secret).decode()
    assert decode_dpop_nonce_secret(b64std) == raw_secret

    hex_secret = raw_secret.hex()
    assert len(hex_secret) == 64
    assert decode_dpop_nonce_secret(hex_secret) == raw_secret

    with caplog.at_level(logging.WARNING):
        garbage_result = decode_dpop_nonce_secret("not-a-valid-secret-at-all")
    assert len(garbage_result) == 32
    assert any("OAUTH2_DPOP_NONCE_SECRET" in record.message for record in caplog.records)

    with caplog.at_level(logging.WARNING):
        unset_result = decode_dpop_nonce_secret(None)
    assert len(unset_result) == 32
    assert any("OAUTH2_DPOP_NONCE_SECRET" in record.message for record in caplog.records)

    # Different garbage inputs must not collide on the same random fallback.
    assert decode_dpop_nonce_secret("garbage-one") != decode_dpop_nonce_secret("garbage-two")


def test_secret_decoding_wrong_length_falls_back(caplog):
    # 16 bytes, validly base64url-encoded — decodes fine but is the wrong
    # length, so it must fall back rather than being accepted short.
    short = base64.urlsafe_b64encode(b"\x00" * 16).rstrip(b"=").decode()
    with caplog.at_level(logging.WARNING):
        result = decode_dpop_nonce_secret(short)
    assert len(result) == 32
    assert any("OAUTH2_DPOP_NONCE_SECRET" in record.message for record in caplog.records)


def test_garbled_secret_falls_back_loudly_not_leniently(caplog):
    """urlsafe_b64decode is lenient (silently strips non-alphabet chars), so a
    valid secret with trailing garbage — stray quotes/whitespace from a
    secrets manager — must NOT silently decode via character-stripping; it
    must hit the loud random-fallback path instead."""
    raw_secret = bytes(range(32))
    clean = base64.urlsafe_b64encode(raw_secret).rstrip(b"=").decode()

    for garbled in (clean + "!!", clean + "###", f'"{clean}"', clean + " "):
        with caplog.at_level(logging.WARNING):
            caplog.clear()
            result = decode_dpop_nonce_secret(garbled)
        assert result != raw_secret, f"garbled secret {garbled!r} silently decoded"
        assert any("OAUTH2_DPOP_NONCE_SECRET" in record.message for record in caplog.records), (
            f"no fallback warning for {garbled!r}"
        )


# --- bucket-id wire format ----------------------------------------------------


def test_issue_encodes_current_bucket_as_big_endian_u64(monkeypatch):
    import oauth2_server.services.dpop_nonce as dpop_nonce_module

    lifetime = 300
    now = 1_700_000_000.0
    monkeypatch.setattr(dpop_nonce_module.time, "time", lambda: now)
    issuer = DpopNonceIssuer(SECRET_A, lifetime_secs=lifetime)

    nonce = issuer.issue()
    padded = nonce + "=" * (-len(nonce) % 4)
    raw = base64.urlsafe_b64decode(padded)

    assert len(raw) == 24
    (bucket_id,) = struct.unpack(">Q", raw[:8])
    assert bucket_id == int(now) // lifetime


# --- divergence 53: DPoP-Nonce on SUCCESSFUL responses ------------------------
#
# RFC 9449 §8 lets the AS hand out a fresh nonce on any response, not only on
# the `use_dpop_nonce` challenge. Rust (and Python through phase 4b) only ever
# set the header on the 400 challenge, so a client that got one nonce had to
# wait for it to go stale and eat a 400 to get the next one. Every 2xx token
# response — and userinfo — now carries a fresh nonce whenever the client has
# `dpop_nonce_required` AND presented a valid proof.

TOKEN_URL = "https://auth.example.com/oauth/token"
USERINFO_URL = "https://auth.example.com/oauth/userinfo"
NONCE_CLIENT = ("nonce-client", "nonce-secret")


async def _seed_nonce_client(client_app, **overrides):

    fields = dict(
        client_id=NONCE_CLIENT[0],
        client_secret=NONCE_CLIENT[1],
        dpop_nonce_required=True,
        redirect_uris='["https://a.example/cb"]',
        scope="read openid email profile",
    )
    fields.update(overrides)
    return await seed_client(client_app.storage, **fields)


async def _bootstrap_nonce(client_app, key) -> str:
    """Burn one `use_dpop_nonce` challenge to obtain a fresh server nonce."""

    proof, _pub = make_dpop_proof(TOKEN_URL, "POST", key)
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=NONCE_CLIENT,
        headers={"DPoP": proof},
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "use_dpop_nonce"
    return resp.headers["dpop-nonce"]


async def test_dpop_nonce_header_on_successful_token_response(client_app):

    await _seed_nonce_client(client_app)
    key = generate_dpop_key()
    nonce = await _bootstrap_nonce(client_app, key)

    proof, _pub = make_dpop_proof(TOKEN_URL, "POST", key, nonce=nonce)
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=NONCE_CLIENT,
        headers={"DPoP": proof},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "DPoP"
    fresh = resp.headers["dpop-nonce"]
    # A genuine, currently-valid nonce — not an echo of the one presented.
    client_app.app.state.dpop_nonce_issuer.verify(fresh)


async def test_dpop_nonce_absent_when_not_required(client_app):
    """`client1` does not require nonces: a perfectly valid proof still gets
    no `DPoP-Nonce` header (issuing one would invite clients to start
    sending nonces the AS never asked for)."""

    proof, _pub = make_dpop_proof(TOKEN_URL, "POST")
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("client1", "s3cret"),
        headers={"DPoP": proof},
    )

    assert resp.status_code == 200, resp.text
    assert "dpop-nonce" not in resp.headers


async def test_dpop_nonce_absent_without_a_proof(client_app):
    """A nonce-requiring client that presents NO proof gets a plain Bearer
    token and no nonce — the header must never be emitted for a request that
    was not proof-of-possession at all."""

    await _seed_nonce_client(client_app)
    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=NONCE_CLIENT
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "Bearer"
    assert "dpop-nonce" not in resp.headers


async def test_dpop_nonce_on_successful_userinfo(client_app):
    await _seed_nonce_client(client_app)
    key = generate_dpop_key()
    nonce = await _bootstrap_nonce(client_app, key)

    await login_session(client_app)
    verifier, challenge = _pkce_pair()
    authorize = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": NONCE_CLIENT[0],
            "redirect_uri": "https://a.example/cb",
            "scope": "openid email",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert authorize.status_code == 302, authorize.text
    code = _query_param(authorize.headers["location"], "code")

    proof, _pub = make_dpop_proof(TOKEN_URL, "POST", key, nonce=nonce)
    token_resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": NONCE_CLIENT[0],
            "code_verifier": verifier,
        },
        basic_auth=NONCE_CLIENT,
        headers={"DPoP": proof},
    )
    assert token_resp.status_code == 200, token_resp.text
    access_token = token_resp.json()["access_token"]

    # The resource-server proof needs `ath` (divergence 50) and, for a
    # nonce-requiring client, a fresh nonce (divergence 62).
    resource_proof, _pub2 = make_dpop_proof(
        USERINFO_URL, "GET", key, nonce=nonce, extra_claims={"ath": ath_for(access_token)}
    )
    userinfo = await client_app.get(
        "/oauth/userinfo",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": resource_proof},
    )

    assert userinfo.status_code == 200, userinfo.text
    client_app.app.state.dpop_nonce_issuer.verify(userinfo.headers["dpop-nonce"])


async def test_no_dpop_nonce_on_unbound_userinfo(client_app):
    """A Bearer (unbound) token at userinfo never triggers a nonce, whatever
    the client's `dpop_nonce_required` setting — there is no proof."""
    await _seed_nonce_client(client_app)
    resp, _code = await run_code_flow(
        client_app,
        client_id=NONCE_CLIENT[0],
        client_secret=NONCE_CLIENT[1],
        scope="openid email",
    )
    assert resp.status_code == 200, resp.text

    userinfo = await client_app.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {resp.json()['access_token']}"},
    )
    assert userinfo.status_code == 200, userinfo.text
    assert "dpop-nonce" not in userinfo.headers


def _query_param(location: str, name: str) -> str:
    return parse_qs(urlsplit(location).query)[name][0]


async def test_userinfo_requires_nonce_for_nonce_client(client_app):
    """Divergence 62 (RFC 9449 §9): a nonce-requiring client's DPoP-bound token
    is refused at userinfo without a nonce — 401 `use_dpop_nonce` carrying a
    fresh `DPoP-Nonce` — and accepted once the client retries with it."""
    await _seed_nonce_client(client_app)
    key = generate_dpop_key()
    nonce = await _bootstrap_nonce(client_app, key)

    await login_session(client_app)
    verifier, challenge = _pkce_pair()
    authorize = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": NONCE_CLIENT[0],
            "redirect_uri": "https://a.example/cb",
            "scope": "openid email",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    code = _query_param(authorize.headers["location"], "code")
    proof, _ = make_dpop_proof(TOKEN_URL, "POST", key, nonce=nonce)
    token_resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": NONCE_CLIENT[0],
            "code_verifier": verifier,
        },
        basic_auth=NONCE_CLIENT,
        headers={"DPoP": proof},
    )
    access_token = token_resp.json()["access_token"]

    no_nonce, _ = make_dpop_proof(
        USERINFO_URL, "GET", key, extra_claims={"ath": ath_for(access_token)}
    )
    refused = await client_app.get(
        "/oauth/userinfo",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": no_nonce},
    )
    assert refused.status_code == 401
    assert refused.json()["error"] == "use_dpop_nonce"
    assert refused.headers["www-authenticate"] == 'DPoP error="use_dpop_nonce"'
    fresh = refused.headers["dpop-nonce"]
    client_app.app.state.dpop_nonce_issuer.verify(fresh)

    retry, _ = make_dpop_proof(
        USERINFO_URL, "GET", key, nonce=fresh, extra_claims={"ath": ath_for(access_token)}
    )
    ok = await client_app.get(
        "/oauth/userinfo",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": retry},
    )
    assert ok.status_code == 200, ok.text
