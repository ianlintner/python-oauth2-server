import anyio.to_thread
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from oauth2_server.models import Claims, IdTokenClaims

_hasher = PasswordHasher()

# RFC 9068 access-token JOSE header typ. Must match the `typ` set by
# encode_access_token below and the value decode_access_token requires.
_ACCESS_TOKEN_TYP = "at+JWT"

# Context string for the session-cookie signing-key derivation. Distinct from
# the JWT-signing use of `jwt_secret` so a leaked session cookie key (or vice
# versa) doesn't directly hand over the other secret.
_SESSION_KEY_INFO = b"oauth2-session-cookie"


def derive_session_key(jwt_secret: str) -> str:
    """Derive a session-cookie signing key from `jwt_secret` via HKDF-SHA256.

    Keeps `SessionMiddleware`'s signing key independent from the raw JWT
    secret (defense in depth / key separation) while remaining deterministic
    across process restarts, since both are sourced from the same config.
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=_SESSION_KEY_INFO)
    return hkdf.derive(jwt_secret.encode()).hex()


def encode_access_token(claims: Claims, secret: str) -> str:
    return jwt.encode(
        claims.to_payload(), secret, algorithm="HS256", headers={"typ": _ACCESS_TOKEN_TYP}
    )


def encode_id_token(claims: IdTokenClaims, secret: str) -> str:
    return jwt.encode(claims.model_dump(exclude_none=True), secret, algorithm="HS256")


def decode_access_token(token: str, secret: str, issuer: str) -> Claims:
    # RFC 9068 typ enforcement: reject any JWT whose header `typ` isn't the
    # access-token type before spending a signature-verification cycle on it
    # (e.g. an id_token signed with the same secret must not decode here).
    # get_unverified_header does not check the signature, so this check does
    # not weaken the cryptographic verification jwt.decode performs below.
    header = jwt.get_unverified_header(token)
    if header.get("typ") != _ACCESS_TOKEN_TYP:
        raise jwt.InvalidTokenError(f"unexpected token typ: {header.get('typ')!r}")

    payload = jwt.decode(
        token, secret, algorithms=["HS256"], issuer=issuer, options={"verify_aud": False}
    )
    aud = payload.get("aud")
    if isinstance(aud, str):
        payload["aud"] = [aud]
    return Claims(**payload)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, phc_hash: str) -> bool:
    try:
        return _hasher.verify(phc_hash, password)
    except VerifyMismatchError:
        return False


async def hash_password_async(password: str) -> str:
    """Argon2 hashing is CPU-bound and takes tens of milliseconds; run it off
    the event loop so one login doesn't stall every other in-flight request."""
    return await anyio.to_thread.run_sync(hash_password, password)


async def verify_password_async(password: str, phc_hash: str) -> bool:
    return await anyio.to_thread.run_sync(verify_password, password, phc_hash)
