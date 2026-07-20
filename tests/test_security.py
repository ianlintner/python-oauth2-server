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


# ---------------------------------------------------------------------------
# encode_id_token RS256 matrix (Task 3a-4) — the "RS256 configured but
# private key is missing" 500 must survive the switch to signing from the
# keyset's current RS256 key when one exists.
# ---------------------------------------------------------------------------


def test_encode_id_token_rs256_missing_key_still_raises_without_keyset_rs256_key():
    from oauth2_server.config import Config
    from oauth2_server.keys import seed_keyset
    from oauth2_server.security import encode_id_token
    from oauth2_server.models import IdTokenClaims

    now = int(datetime.now(timezone.utc).timestamp())
    claims = IdTokenClaims(iss=ISS, sub="u1", aud="c1", exp=now + 600, iat=now)
    # id_token_alg forced to RS256 with no PEM configured: seed_keyset can't
    # seed an RS256 key either, so the keyset has none — the pre-existing
    # 500 (via ValueError) must still fire, not a crash trying to sign with
    # a missing key.
    config = Config(jwt_secret=SECRET, id_token_alg="RS256")
    keyset = seed_keyset(config)
    assert keyset.current_for_alg("RS256") is None

    with pytest.raises(ValueError, match="RS256 configured but private key is missing"):
        encode_id_token(claims, SECRET, config=config, keyset=keyset)


def test_encode_id_token_uses_keyset_rs256_key_even_without_pem_once_one_exists():
    from oauth2_server.config import Config
    from oauth2_server.keys import generate_signing_key, seed_keyset
    from oauth2_server.security import encode_id_token
    from oauth2_server.models import IdTokenClaims

    now = int(datetime.now(timezone.utc).timestamp())
    claims = IdTokenClaims(iss=ISS, sub="u1", aud="c1", exp=now + 600, iat=now)
    config = Config(jwt_secret=SECRET, id_token_alg="RS256")
    keyset = seed_keyset(config)
    # An admin rotation can create an RS256 key even on a config that never
    # had a PEM -- once the keyset has a current RS256 key, id_tokens sign
    # with it instead of raising, regardless of the (still-unset) PEM.
    keyset.rotate(generate_signing_key("RS256", "rs256-manual"), 3600)

    token = encode_id_token(claims, SECRET, config=config, keyset=keyset)
    assert jwt.get_unverified_header(token)["kid"] == "rs256-manual"


def test_encode_id_token_hs256_config_unaffected_by_stray_keyset_rs256_key():
    from oauth2_server.config import Config
    from oauth2_server.keys import generate_signing_key, seed_keyset
    from oauth2_server.security import encode_id_token
    from oauth2_server.models import IdTokenClaims

    now = int(datetime.now(timezone.utc).timestamp())
    claims = IdTokenClaims(iss=ISS, sub="u1", aud="c1", exp=now + 600, iat=now)
    # HS256 config (no PEM, default id_token_alg): an admin RS256 rotation
    # (rotate defaults to RS256 regardless of the server's key mix) must not
    # flip id_token signing to RS256 -- only config.id_token_alg gates that.
    config = Config(jwt_secret=SECRET)
    assert config.id_token_alg == "HS256"
    keyset = seed_keyset(config)
    keyset.rotate(generate_signing_key("RS256", "rs256-surprise"), 3600)

    token = encode_id_token(claims, SECRET, config=config, keyset=keyset)
    assert jwt.get_unverified_header(token)["alg"] == "HS256"
