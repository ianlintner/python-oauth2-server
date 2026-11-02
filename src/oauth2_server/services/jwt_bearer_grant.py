"""RFC 7523 §2.1 JWT authorization grant
(`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`).

Port of `crates/oauth2-actix/src/handlers/jwt_bearer.rs` (trusted-issuer
registry model). An external IdP signs an assertion about a subject; the
authenticated confidential client presents it as `assertion`. The `iss` must
name an enabled `TrustedIssuer`, whose `jwks_uri` supplies the verification
key. EVERY failure is `invalid_grant` (RFC 7523 §3.1) — including a JWKS fetch
failure, which the shared `JwksCache` reports as `invalid_client` and is
remapped here.

Out of scope (separate cards): ID-JAG (`typ: oauth-id-jag+jwt` assertions are
refused, as Rust does with `id_jag_enabled=false`), CIMD clients, trusted-
issuer admin APIs.

The assertion's `jti` replay is tracked in the shared in-memory
`JtiReplayGuard`, namespaced `jwt-bearer:<iss>` so it cannot collide with a
client-assertion `jti`.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import ECAlgorithm, RSAAlgorithm, RSAPSSAlgorithm

from oauth2_server.errors import OAuthError
from oauth2_server.models import Client, TrustedIssuer, User
from oauth2_server.services.client_assertion import MAX_JTI_TTL_SECS, JtiReplayGuard
from oauth2_server.services.jwks_cache import JwksCache
from oauth2_server.storage.base import Storage

logger = logging.getLogger(__name__)

JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"

# Asymmetric only: the verification key comes from the issuer's public JWKS.
ALLOWED_ALGS = ("RS256", "ES256", "PS256")
_ID_JAG_TYP = "oauth-id-jag+jwt"
_IAT_SKEW_SECS = 60
_REQUIRED = ["iss", "sub", "aud", "exp", "iat", "jti"]


def _grant_error(description: str) -> OAuthError:
    return OAuthError("invalid_grant", description)


def _unverified_header_and_iss(assertion: str) -> tuple[dict, str]:
    if assertion.count(".") != 2:
        raise _grant_error("assertion is not a well-formed JWS Compact Serialization")
    try:
        header = jwt.get_unverified_header(assertion)
    except jwt.PyJWTError as exc:
        raise _grant_error("Malformed assertion JWT header") from exc
    try:
        claims = jwt.decode(assertion, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        raise _grant_error("assertion payload is not valid") from exc
    iss = claims.get("iss")
    if not isinstance(iss, str) or not iss:
        raise _grant_error("assertion is missing the iss claim")
    return header, iss


def _select_key(jwks: dict, header: dict):
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise _grant_error("trusted issuer JWKS has no 'keys' array")
    alg = header["alg"]
    wanted_kty = "EC" if alg == "ES256" else "RSA"
    kid = header.get("kid")
    if kid is not None:
        match = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
        if match is None:
            raise _grant_error("no key with the assertion's kid in the issuer JWKS")
    else:
        match = next((k for k in keys if isinstance(k, dict) and k.get("kty") == wanted_kty), None)
        if match is None:
            raise _grant_error("no usable key in the trusted issuer's JWKS")
    if match.get("kty") != wanted_kty:
        raise _grant_error("issuer JWKS key type does not match the assertion algorithm")
    try:
        algo = {"RS256": RSAAlgorithm, "PS256": RSAPSSAlgorithm, "ES256": ECAlgorithm}[alg]
        key = algo.from_jwk(match)
    except Exception as exc:
        raise _grant_error("issuer JWKS key is malformed") from exc
    # `from_jwk` returns a private key when the JWK carries `d`; a published
    # JWKS must hold public keys only.
    if not isinstance(key, (RSAPublicKey, EllipticCurvePublicKey)):
        raise _grant_error("issuer JWKS key is not a public key")
    return key


async def verify_assertion(
    assertion: str,
    trusted: TrustedIssuer,
    header: dict,
    *,
    our_issuer: str,
    token_endpoint_url: str,
    jwks_cache: JwksCache,
) -> dict:
    if header.get("alg") not in ALLOWED_ALGS:
        raise _grant_error("assertion uses an unsupported signature algorithm")
    try:
        jwks = await jwks_cache.fetch(trusted.jwks_uri.strip())
    except OAuthError as exc:
        raise _grant_error(f"could not fetch the trusted issuer's JWKS: {exc.description}") from exc
    key = _select_key(jwks, header)

    # `aud` may name this AS (issuer id or token endpoint URL) or any audience
    # the registry allows this issuer to target.
    audiences = [our_issuer, token_endpoint_url, *trusted.allowed_audiences_list()]
    try:
        return jwt.decode(
            assertion,
            key,
            algorithms=[header["alg"]],
            audience=audiences,
            issuer=trusted.issuer,
            options={"require": _REQUIRED},
        )
    except jwt.PyJWTError as exc:
        raise _grant_error(f"assertion validation failed: {exc}") from exc


def _enforce_replay(iss: str, claims: dict, guard: JtiReplayGuard) -> None:
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise _grant_error("assertion missing required jti claim (RFC 7523 §3)")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise _grant_error("assertion missing exp claim")
    ttl = min(max(float(exp) - time.time(), 0.0), float(MAX_JTI_TTL_SECS))
    if not guard.observe(f"jwt-bearer:{iss}", jti, ttl):
        logger.warning("RFC 7523 §3: rejected replayed jwt-bearer jti (iss=%s)", iss)
        raise _grant_error("assertion jti has already been used")


async def _resolve_subject(storage: Storage, trusted: TrustedIssuer, claims: dict) -> str:
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise _grant_error("assertion sub claim is not a string")
    email = claims.get("email") if isinstance(claims.get("email"), str) else ""

    is_email_mapping = trusted.subject_mapping == "email"
    if is_email_mapping:
        if not email:
            raise _grant_error(
                "trusted issuer maps subjects by email but the assertion has no email claim"
            )
        matches = await storage.get_users_by_email(email)
        existing = matches[0] if matches else None
    else:
        existing = await storage.get_user_by_id(sub)

    if existing is not None:
        if not existing.enabled:
            raise _grant_error("subject user is disabled")
        return existing.id
    if is_email_mapping:
        raise _grant_error("unknown subject")
    if not trusted.jit_provision:
        raise _grant_error(
            "assertion subject has no local user and the issuer does not allow provisioning"
        )

    now = datetime.now(UTC)
    user = User(
        id=sub,
        username=sub,
        password_hash="",
        email=email,
        enabled=True,
        role="user",
        created_at=now,
        updated_at=now,
    )
    try:
        await storage.save_user(user)
    except Exception:
        # Racing first-use assertion (or `sub` colliding with an existing row):
        # re-read once; still a grant failure, never a 500.
        logger.warning("RFC 7523: JIT provisioning insert failed (iss=%s)", trusted.issuer)
        try:
            raced = await storage.get_user_by_id(sub)
        except Exception:
            raced = None
        if raced is not None and raced.enabled:
            return raced.id
        raise _grant_error(
            "subject user is disabled"
            if raced is not None
            else "could not provision a local user for the assertion subject"
        ) from None
    return user.id


async def redeem_jwt_bearer_assertion(
    assertion: str,
    client: Client,
    *,
    storage: Storage,
    jwks_cache: JwksCache,
    guard: JtiReplayGuard,
    our_issuer: str,
    token_endpoint_url: str,
) -> str:
    """Validate `assertion` for the authenticated `client` and return the local
    user id the access token is issued for. Raises `invalid_grant`."""
    header, iss = _unverified_header_and_iss(assertion)

    trusted = await storage.get_trusted_issuer(iss)
    if trusted is None or not trusted.enabled:
        raise _grant_error("assertion iss is not a trusted issuer")
    if not trusted.allows_client(client.client_id):
        raise _grant_error("client is not allowed to use this trusted issuer")

    if header.get("typ") == _ID_JAG_TYP:
        raise _grant_error("ID-JAG assertions are not accepted by this authorization server")

    claims = await verify_assertion(
        assertion,
        trusted,
        header,
        our_issuer=our_issuer,
        token_endpoint_url=token_endpoint_url,
        jwks_cache=jwks_cache,
    )

    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        raise _grant_error("assertion iat claim is not a number")
    if iat > time.time() + _IAT_SKEW_SECS:
        raise _grant_error("assertion iat is in the future")

    _enforce_replay(iss, claims, guard)
    return await _resolve_subject(storage, trusted, claims)
