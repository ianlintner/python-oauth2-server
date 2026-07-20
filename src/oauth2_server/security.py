from typing import TYPE_CHECKING

import anyio.to_thread
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from oauth2_server.keys import KeySet, SigningKey
from oauth2_server.models import Claims, IdTokenClaims

if TYPE_CHECKING:
    from oauth2_server.config import Config

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


def encode_access_token(claims: Claims, secret: str, *, key: SigningKey | None = None) -> str:
    """Sign an access token. With `key` (from `app.state.keyset`), signs
    using that key's algorithm/material and sets a `kid` header alongside
    `typ`; RS256 key material is a PKCS#8 PEM, which PyJWT accepts directly
    for signing. Without `key` (legacy/no-keyset path), falls back to the
    original kid-less HS256(`secret`) encoding."""
    if key is not None:
        return jwt.encode(
            claims.to_payload(),
            key.key_material,
            algorithm=key.algorithm,
            headers={"typ": _ACCESS_TOKEN_TYP, "kid": key.kid},
        )
    return jwt.encode(
        claims.to_payload(), secret, algorithm="HS256", headers={"typ": _ACCESS_TOKEN_TYP}
    )


def encode_id_token(claims: IdTokenClaims, secret: str, *, config: "Config | None" = None) -> str:
    """Sign an id_token. RS256 when `config.id_token_alg == "RS256"` — signs
    directly with `config.id_token_private_key_pem` (never via the rotating
    `KeySet`; Rust parity, see research gotchas) and sets a `kid` header when
    `config.id_token_kid` is set. Otherwise (or without `config`) falls back
    to the original HS256(`secret`) encoding."""
    if config is not None and config.id_token_alg == "RS256":
        if not config.id_token_private_key_pem:
            raise ValueError("RS256 configured but private key is missing")
        headers = {"kid": config.id_token_kid} if config.id_token_kid else None
        return jwt.encode(
            claims.model_dump(exclude_none=True),
            config.id_token_private_key_pem,
            algorithm="RS256",
            headers=headers,
        )
    return jwt.encode(claims.model_dump(exclude_none=True), secret, algorithm="HS256")


def _rsa_public_key(pem_material: bytes):
    private_key = serialization.load_pem_private_key(pem_material, password=None)
    return private_key.public_key()


def decode_access_token(
    token: str, secret: str, issuer: str, *, keyset: KeySet | None = None
) -> Claims:
    # RFC 9068 typ enforcement: reject any JWT whose header `typ` isn't the
    # access-token type before spending a signature-verification cycle on it
    # (e.g. an id_token signed with the same secret must not decode here).
    # get_unverified_header does not check the signature, so this check does
    # not weaken the cryptographic verification jwt.decode performs below.
    header = jwt.get_unverified_header(token)
    if header.get("typ") != _ACCESS_TOKEN_TYP:
        raise jwt.InvalidTokenError(f"unexpected token typ: {header.get('typ')!r}")

    signing_key: SigningKey | None = None
    if keyset is not None:
        kid = header.get("kid")
        if kid:
            signing_key = keyset.find(kid)

    if signing_key is not None:
        algorithm = signing_key.algorithm
        verify_key = (
            _rsa_public_key(signing_key.key_material)
            if algorithm == "RS256"
            else signing_key.key_material
        )
    else:
        algorithm = "HS256"
        verify_key = secret

    # divergence 1 (see research-keys-rs256.md gotchas): the Rust
    # jsonwebtoken v10 default validator rejects any token carrying an `aud`
    # claim when no expected audience is configured — every Claims token has
    # one, so a faithful port of that default would reject every access
    # token. verify_aud=False is a deliberate fix, not a copied bug.
    payload = jwt.decode(
        token, verify_key, algorithms=[algorithm], issuer=issuer, options={"verify_aud": False}
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
