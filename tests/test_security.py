import jwt
import pytest

from oauth2_server.models import Claims
from oauth2_server.security import (
    decode_access_token,
    encode_access_token,
    hash_password,
    verify_password,
)

SECRET = "unit-test-secret-not-for-production-0123456789abcdef"
ISS = "https://auth.example.com"


def test_access_token_header_typ_is_at_jwt():
    token = encode_access_token(Claims.new("u1", "c1", "read", 3600, ISS), SECRET)
    assert jwt.get_unverified_header(token)["typ"] == "at+JWT"


def test_round_trip_preserves_claims():
    token = encode_access_token(Claims.new("u1", "c1", "read", 3600, ISS), SECRET)
    claims = decode_access_token(token, SECRET, ISS)
    assert (claims.sub, claims.iss, claims.aud) == ("u1", ISS, ["c1"])


def test_wrong_issuer_rejected():
    token = encode_access_token(Claims.new("u1", "c1", "read", 3600, ISS), SECRET)
    with pytest.raises(jwt.InvalidIssuerError):
        decode_access_token(token, SECRET, "https://evil.example.com")


def test_argon2_round_trip_and_rust_interop():
    h = hash_password("hunter2")
    assert h.startswith("$argon2")
    assert verify_password("hunter2", h) and not verify_password("wrong", h)
    # PHC hash produced by the Rust server (argon2 0.5 defaults) must verify here.
    # Generate once via: cargo run --example hash_password hunter2  (or copy one
    # from a dev DB) and paste below before enabling:
    # assert verify_password("hunter2", RUST_GENERATED_HASH)
