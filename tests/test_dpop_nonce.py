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

import pytest

from oauth2_server.services.dpop import DpopError, DpopValidated
from oauth2_server.services.dpop_nonce import (
    DpopNonceError,
    DpopNonceIssuer,
    decode_dpop_nonce_secret,
    enforce_dpop_nonce,
    use_dpop_nonce_response,
)

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
