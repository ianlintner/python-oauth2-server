"""DPoP (RFC 9449) proof validation + replay store — `services/dpop.py` unit
tests.

Ported by name from the Rust unit tests in
`crates/oauth2-actix/src/handlers/dpop.rs` (`strip_query`, replay-store
duplicate/distinct-jti cases) and `tests/rfc9700_compliance.rs` test vectors
N (`test_vector_n_dpop_invalid_typ`) and O (`test_vector_o_dpop_jti_replay`)
— see `.superpowers/sdd/research-dpop.md` `key_behaviors` / `tests_to_port`
for the exact validation order and error strings this module reproduces
verbatim. The Rust suite only exercises units in isolation (garbage JWTs,
the bare replay store); the e2e-grade unit tests below (a real signed proof
round-tripping through `validate_dpop_proof`) are new coverage the Rust side
lacks.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from oauth2_server.services.dpop import (
    REPLAY_TTL_SECS,
    DpopError,
    DpopReplayStore,
    jwk_thumbprint,
    strip_query,
    validate_dpop_proof,
)

DEFAULT_METHOD = "POST"
DEFAULT_URL = "https://as.example/oauth/token"


def _b64u_fixed(value: int, length: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _b64u_uint(value: int) -> str:
    length = max((value.bit_length() + 7) // 8, 1)
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _generate_ec_keypair() -> tuple[bytes, dict]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u_fixed(numbers.x, 32),
        "y": _b64u_fixed(numbers.y, 32),
    }
    return pem, jwk


def _generate_rsa_keypair() -> tuple[bytes, dict]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwk = {"kty": "RSA", "n": _b64u_uint(numbers.n), "e": _b64u_uint(numbers.e)}
    return pem, jwk


def _independent_thumbprint(subset: dict) -> str:
    """RFC 7638 thumbprint computed independently of `jwk_thumbprint`, to
    assert the implementation against rather than duplicate it."""
    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _build_proof(
    private_key_pem: bytes,
    public_jwk: dict,
    *,
    alg: str = "ES256",
    typ: str = "dpop+jwt",
    method: str = DEFAULT_METHOD,
    url: str = DEFAULT_URL,
    iat: float | None = None,
    jti: str = "proof-jti",
) -> str:
    claims = {
        "htm": method,
        "htu": url,
        "iat": int(iat if iat is not None else time.time()),
        "jti": jti,
    }
    headers = {"typ": typ, "jwk": public_jwk}
    return jwt.encode(claims, private_key_pem, algorithm=alg, headers=headers)


# --- strip_query ---------------------------------------------------------


def test_strip_query_removes_query_string():
    assert (
        strip_query("https://example.com/oauth/token?foo=bar") == "https://example.com/oauth/token"
    )


def test_strip_query_removes_fragment_and_trailing_slash():
    assert strip_query("https://example.com/oauth/token/") == "https://example.com/oauth/token"
    assert (
        strip_query("https://example.com/oauth/token?a=1#frag") == "https://example.com/oauth/token"
    )


# --- jwk_thumbprint (RFC 7638) --------------------------------------------


def test_thumbprint_rsa_and_ec_match_rfc7638():
    _, ec_jwk = _generate_ec_keypair()
    ec_expected = _independent_thumbprint(
        {"crv": "P-256", "kty": "EC", "x": ec_jwk["x"], "y": ec_jwk["y"]}
    )
    assert jwk_thumbprint(ec_jwk) == ec_expected

    _, rsa_jwk = _generate_rsa_keypair()
    rsa_expected = _independent_thumbprint({"e": rsa_jwk["e"], "kty": "RSA", "n": rsa_jwk["n"]})
    assert jwk_thumbprint(rsa_jwk) == rsa_expected


def test_thumbprint_unsupported_kty_rejected():
    with pytest.raises(DpopError) as exc_info:
        jwk_thumbprint({"kty": "oct", "k": "irrelevant"})
    assert exc_info.value.error == "invalid_dpop_proof"
    assert exc_info.value.description == "Unsupported JWK key type"


# --- DpopReplayStore -------------------------------------------------------


def test_dpop_jti_replay():
    store = DpopReplayStore()
    store.check_and_insert("dup-jti")
    with pytest.raises(DpopError) as exc_info:
        store.check_and_insert("dup-jti")
    assert exc_info.value.error == "invalid_dpop_proof"
    assert "replay" in exc_info.value.description


def test_replay_store_accepts_different_jti():
    store = DpopReplayStore()
    store.check_and_insert("jti-a")
    store.check_and_insert("jti-b")  # must not raise


def test_expired_replay_entries_swept(monkeypatch):
    import oauth2_server.services.dpop as dpop_module

    real_monotonic = dpop_module.time.monotonic
    store = DpopReplayStore()
    store.check_and_insert("old-jti")

    monkeypatch.setattr(
        dpop_module.time, "monotonic", lambda: real_monotonic() + REPLAY_TTL_SECS + 1
    )

    # A later insert sweeps every expired entry dict-wide (ParStore /
    # FixedWindowLimiter precedent) — re-inserting the swept jti must
    # succeed rather than raise replay.
    store.check_and_insert("new-jti")
    store.check_and_insert("old-jti")


# --- validate_dpop_proof ---------------------------------------------------


def test_dpop_invalid_typ():
    proof = jwt.encode(
        {"htm": "POST", "htu": DEFAULT_URL, "iat": int(time.time()), "jti": "typ-jti"},
        "shared-secret-at-least-32-bytes-long-000000",
        algorithm="HS256",
        headers={"typ": "JWT"},
    )
    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert exc_info.value.error == "invalid_dpop_proof"
    assert "typ" in exc_info.value.description


def test_dpop_missing_jwk_header_rejected():
    proof = jwt.encode(
        {"htm": DEFAULT_METHOD, "htu": DEFAULT_URL, "iat": int(time.time()), "jti": "no-jwk"},
        "shared-secret-at-least-32-bytes-long-000000",
        algorithm="HS256",
        headers={"typ": "dpop+jwt"},
    )
    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert "jwk" in exc_info.value.description


@pytest.mark.parametrize("bad_jwk", ["foo", 123, ["a"]])
def test_dpop_non_dict_jwk_header_rejected(bad_jwk):
    proof = jwt.encode(
        {"htm": DEFAULT_METHOD, "htu": DEFAULT_URL, "iat": int(time.time()), "jti": "bad-jwk"},
        "shared-secret-at-least-32-bytes-long-000000",
        algorithm="HS256",
        headers={"typ": "dpop+jwt", "jwk": bad_jwk},
    )
    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert exc_info.value.error == "invalid_dpop_proof"
    assert "jwk" in exc_info.value.description


def test_dpop_malformed_proof_rejected():
    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof("not-a-jwt", DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert exc_info.value.error == "invalid_dpop_proof"


def test_valid_es256_proof_validates():
    priv_pem, pub_jwk = _generate_ec_keypair()
    proof = _build_proof(priv_pem, pub_jwk, alg="ES256", jti="es256-jti")

    result = validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())

    assert result.jkt == jwk_thumbprint(pub_jwk)
    assert result.nonce is None


def test_valid_rs256_proof_validates():
    priv_pem, pub_jwk = _generate_rsa_keypair()
    proof = _build_proof(priv_pem, pub_jwk, alg="RS256", jti="rs256-jti")

    result = validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())

    assert result.jkt == jwk_thumbprint(pub_jwk)


def test_wrong_htu_rejected():
    priv_pem, pub_jwk = _generate_ec_keypair()
    proof = _build_proof(priv_pem, pub_jwk, url=DEFAULT_URL, jti="wrong-htu-jti")

    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(
            proof, DEFAULT_METHOD, "https://as.example/oauth/other", DpopReplayStore()
        )
    assert "htu" in exc_info.value.description


def test_stale_iat_rejected():
    priv_pem, pub_jwk = _generate_ec_keypair()
    proof = _build_proof(priv_pem, pub_jwk, iat=time.time() - 1000, jti="stale-iat-jti")

    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert "iat" in exc_info.value.description


def test_future_iat_within_skew_window_validates():
    # PyJWT's own iat check has zero leeway and would reject this at
    # decode time with "not yet valid" if verify_iat weren't disabled,
    # before the manual +/-300s window ever runs.
    priv_pem, pub_jwk = _generate_ec_keypair()
    proof = _build_proof(priv_pem, pub_jwk, iat=time.time() + 200, jti="future-iat-ok-jti")

    result = validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert result.jkt == jwk_thumbprint(pub_jwk)


def test_future_iat_outside_skew_window_rejected():
    priv_pem, pub_jwk = _generate_ec_keypair()
    proof = _build_proof(priv_pem, pub_jwk, iat=time.time() + 301, jti="future-iat-bad-jti")

    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert exc_info.value.error == "invalid_dpop_proof"
    assert exc_info.value.description == "DPoP proof iat is outside the acceptance window"


def test_string_iat_rejected():
    # A numeric *string* iat (e.g. `"1690000000"`) used to sail through
    # `float(claims["iat"])` and be treated as a valid timestamp — tightened
    # to a strict int/float type check.
    priv_pem, pub_jwk = _generate_ec_keypair()
    claims = {
        "htm": DEFAULT_METHOD,
        "htu": DEFAULT_URL,
        "iat": str(int(time.time())),
        "jti": "string-iat-jti",
    }
    proof = jwt.encode(
        claims, priv_pem, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": pub_jwk}
    )

    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert exc_info.value.error == "invalid_dpop_proof"
    assert exc_info.value.description == "DPoP proof iat must be a number"


def test_non_string_nonce_rejected():
    # A validly-signed proof with a non-str `nonce` claim (e.g. an int) must
    # not reach `DpopNonceIssuer.verify`'s string slicing, which would raise
    # an unhandled TypeError instead of a clean 400 `invalid_dpop_proof`.
    priv_pem, pub_jwk = _generate_ec_keypair()
    claims = {
        "htm": DEFAULT_METHOD,
        "htu": DEFAULT_URL,
        "iat": int(time.time()),
        "jti": "int-nonce-jti",
        "nonce": 12345,
    }
    proof = jwt.encode(
        claims, priv_pem, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": pub_jwk}
    )

    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert exc_info.value.error == "invalid_dpop_proof"
    assert exc_info.value.description == "DPoP proof nonce must be a string"


def test_unsupported_alg_rejected():
    _, pub_jwk = _generate_ec_keypair()
    claims = {
        "htm": DEFAULT_METHOD,
        "htu": DEFAULT_URL,
        "iat": int(time.time()),
        "jti": "hs256-jti",
    }
    proof = jwt.encode(
        claims,
        "shared-secret-at-least-32-bytes-long-000000",
        algorithm="HS256",
        headers={"typ": "dpop+jwt", "jwk": pub_jwk},
    )

    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert "algorithm" in exc_info.value.description


def test_proof_signed_with_different_key_rejected():
    # Sign with key A's private key but embed key B's public JWK in the
    # header — the signature must not verify against the wrong key.
    priv_pem_a, _ = _generate_ec_keypair()
    _, pub_jwk_b = _generate_ec_keypair()
    proof = _build_proof(priv_pem_a, pub_jwk_b, jti="mismatched-key-jti")

    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, DpopReplayStore())
    assert exc_info.value.error == "invalid_dpop_proof"
    assert "signature invalid" in exc_info.value.description


def test_replayed_jti_rejected_on_second_proof():
    priv_pem, pub_jwk = _generate_ec_keypair()
    store = DpopReplayStore()
    proof = _build_proof(priv_pem, pub_jwk, jti="same-jti")

    validate_dpop_proof(proof, DEFAULT_METHOD, DEFAULT_URL, store)

    replay_proof = _build_proof(priv_pem, pub_jwk, jti="same-jti")
    with pytest.raises(DpopError) as exc_info:
        validate_dpop_proof(replay_proof, DEFAULT_METHOD, DEFAULT_URL, store)
    assert "replay" in exc_info.value.description
