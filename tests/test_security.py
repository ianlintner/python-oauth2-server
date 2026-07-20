from datetime import datetime, timezone

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
# PHC hash produced by the Rust server's argon2 0.5 crate (Argon2::default()) for "hunter2".
RUST_GENERATED_HASH = "$argon2id$v=19$m=19456,t=2,p=1$Peb5OaW+pSRgARNgYUN8Qg$FJNH7OWMAhAJXowV3e7yk3+Bp4PynKdOsfR1qc3i6aY"


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
    assert verify_password("hunter2", RUST_GENERATED_HASH)


def test_session_key_is_derived_not_verbatim():
    from oauth2_server.security import derive_session_key

    key = derive_session_key(SECRET)
    assert key != SECRET
    assert key == derive_session_key(SECRET)  # deterministic
    assert len(bytes.fromhex(key)) == 32


def test_id_token_rejected_as_access_token():
    from oauth2_server.security import encode_id_token
    from oauth2_server.models import IdTokenClaims

    now = int(datetime.now(timezone.utc).timestamp())
    idt = encode_id_token(
        IdTokenClaims(iss=ISS, sub="u1", aud="c1", exp=now + 600, iat=now), SECRET
    )
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(idt, SECRET, ISS)


async def test_verify_password_async_round_trip():
    from oauth2_server.security import hash_password_async, verify_password_async

    h = await hash_password_async("hunter2")
    assert await verify_password_async("hunter2", h)
    assert not await verify_password_async("wrong", h)
