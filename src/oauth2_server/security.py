import base64
import hashlib
from typing import TYPE_CHECKING

import anyio.to_thread
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from oauth2_server.errors import OAuthError
from oauth2_server.keys import KeySet, SigningKey, rsa_public_key
from oauth2_server.models import Claims, Client, IdTokenClaims

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


def decode_unverified_claims(token: str) -> dict:
    """Decode a JWT's claims WITHOUT verifying its signature.

    Shared by the handful of deliberate unverified reads this server makes
    (the refresh grant's `cnf` carry-over in `routes/token.py`, introspection's
    `cnf`/`authorization_details` echo). Every caller already gated the token
    on something else — a storage row, a stored refresh token — and only needs
    to read claims back out of it, so a decode failure is never an error:
    anything that isn't a parseable JWT (an opaque token, a non-string) simply
    yields no claims.

    Never use this to make a trust decision about a token's contents.
    """
    if not isinstance(token, str):
        return {}
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}
    return claims if isinstance(claims, dict) else {}


def half_hash(value: str) -> str:
    """OIDC Core §3.3.2.11 / §3.1.3.6: base64url-no-pad(left-half(SHA-256(value))).

    The `at_hash`/`c_hash` construction, shared by the token endpoint and the
    authorize endpoint's hybrid branch (via `services/id_token.py`).
    """
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()


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


def encode_id_token(
    claims: IdTokenClaims,
    secret: str,
    *,
    config: "Config | None" = None,
    keyset: KeySet | None = None,
) -> str:
    """Sign an id_token. RS256 when `config.id_token_alg == "RS256"` — signs
    with `keyset.current_for_alg("RS256")` (kid header from that key) when
    the keyset has a current RS256 key, so id_tokens automatically follow
    key rotation and stay verifiable via JWKS after the pre-rotation key's
    grace period expires and it's pruned. This closes the Rust divergence
    documented in research-keys-rs256.md gotchas, where id_tokens are always
    signed from the static env PEM and JWKS publication breaks for them
    after rotation.

    Falls back to `config.id_token_private_key_pem` directly (kid header
    from `config.id_token_kid` when set) when the keyset has no current
    RS256 key — e.g. `keyset` not supplied, or `config.id_token_alg` was
    forced to RS256 without ever seeding a keyset key. This is also what
    keeps pre-rotation output byte-identical to the old config-PEM-only
    behavior: `seed_keyset` seeds the keyset's RS256 key from that exact PEM
    with kid `config.id_token_kid or "rs256-initial"`, so whenever
    `id_token_kid` is set (every current RS256-mode caller) both paths sign
    the same claims with the same key and the same `kid` header — and
    RSASSA-PKCS1-v1_5 (RS256) is deterministic, so the signature bytes match
    too.

    Otherwise (or without `config`) falls back to the original
    HS256(`secret`) encoding."""
    if config is not None and config.id_token_alg == "RS256":
        signing_key = keyset.current_for_alg("RS256") if keyset is not None else None
        if signing_key is not None:
            return jwt.encode(
                claims.model_dump(exclude_none=True),
                signing_key.key_material,
                algorithm="RS256",
                headers={"kid": signing_key.kid},
            )
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


# RFC 9701 §4 JOSE header typ for a JWT-secured introspection response. Also
# the response's Content-Type — a caller negotiates the format by sending it
# in `Accept` (see routes/introspect.py).
INTROSPECTION_JWT_TYP = "token-introspection+jwt"


def encode_introspection_jwt(payload: dict, *, keyset: KeySet | None, client: Client) -> str:
    """Sign an RFC 9701 JWT-secured introspection response with a key the
    REQUESTING CLIENT can actually verify.

    Divergence 34 (security over parity): Rust signs this response with the
    server's own `jwt_secret`, which no client holds — the signature is then
    decorative, and a relying party cannot tell a genuine introspection
    result from a forged one. The rule here instead follows RFC 9701 §5 and
    the OIDC Core §10.1 symmetric-key convention:

    1. RS256 with `keyset.current_for_alg("RS256")` whenever the keyset has
       one — regardless of `config.id_token_alg`, because that key's public
       half is published in JWKS, so any client can verify it and it follows
       key rotation via the `kid` header.
    2. Otherwise HS256 with the requesting client's own `client_secret`
       (OIDC Core §10.1: the symmetric signing key is the client secret).
       Only the server and that client hold it, and `aud` is that client, so
       the response is both verifiable and unforgeable by third parties.
    3. A public client holds no key at all, so with no RS256 key there is no
       verifiable JWT to produce. Silently answering in JSON instead would
       hand a JWT-negotiating caller an unauthenticated result it cannot
       distinguish from a downgrade attack — so this raises `OAuthError` and
       the caller turns it into a 400.

    Step 2 dispatches on `client.is_public()` (the REGISTERED
    `token_endpoint_auth_method`), the same predicate client authentication
    uses, rather than on whether the secret column happens to be non-empty:
    a confidential row with an empty secret is a misconfiguration, and
    HMAC-signing under an empty key would be the worst possible answer to
    it. Such a row raises here too, which the error description covers.
    """
    signing_key = keyset.current_for_alg("RS256") if keyset is not None else None
    if signing_key is not None:
        return jwt.encode(
            payload,
            signing_key.key_material,
            algorithm="RS256",
            headers={"typ": INTROSPECTION_JWT_TYP, "kid": signing_key.kid},
        )
    if not client.is_public() and client.client_secret:
        return jwt.encode(
            payload,
            client.client_secret,
            algorithm="HS256",
            headers={"typ": INTROSPECTION_JWT_TYP},
        )
    raise OAuthError(
        "invalid_request",
        "JWT introspection responses require an RS256 signing key or a client secret",
        400,
    )


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

    # divergence 1 (see research-keys-rs256.md gotchas): the Rust
    # jsonwebtoken v10 default validator rejects any token carrying an `aud`
    # claim when no expected audience is configured — every Claims token has
    # one, so a faithful port of that default would reject every access
    # token. verify_aud=False is a deliberate fix, not a copied bug.
    if signing_key is not None:
        algorithm = signing_key.algorithm
        verify_key = (
            rsa_public_key(signing_key.key_material)
            if algorithm == "RS256"
            else signing_key.key_material
        )
        payload = jwt.decode(
            token, verify_key, algorithms=[algorithm], issuer=issuer, options={"verify_aud": False}
        )
    else:
        # `kid` missing or unresolvable (unknown/pruned): before trusting
        # the single static `secret`, try every active HS256 keyset key —
        # otherwise rotating the HS256 key is a no-op for any token that
        # doesn't carry a resolvable kid (e.g. minted via the legacy
        # no-keyset path). Falls back to `secret` (and its own error) only
        # when no active keyset key verifies it, so the exception a caller
        # sees on total failure is unchanged from before this fallback.
        payload = _decode_with_any_active_hs256_key(token, issuer, keyset)
        if payload is None:
            payload = jwt.decode(
                token, secret, algorithms=["HS256"], issuer=issuer, options={"verify_aud": False}
            )

    aud = payload.get("aud")
    if isinstance(aud, str):
        payload["aud"] = [aud]
    return Claims(**payload)


def _decode_with_any_active_hs256_key(
    token: str, issuer: str, keyset: KeySet | None
) -> dict | None:
    """Try every active HS256 key in `keyset`, returning the first payload
    that verifies, or `None` (never raises) if `keyset` is absent or no
    active HS256 key verifies the token."""
    if keyset is None:
        return None
    for key in keyset.active_keys_for_alg("HS256"):
        try:
            return jwt.decode(
                token,
                key.key_material,
                algorithms=["HS256"],
                issuer=issuer,
                options={"verify_aud": False},
            )
        except jwt.PyJWTError:
            continue
    return None


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
