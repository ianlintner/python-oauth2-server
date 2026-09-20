"""RFC 7523 §3 JWT client authentication — `client_secret_jwt` (HS256) and
`private_key_jwt` (RS256) client assertions, plus the `(client_id, jti)`
replay guard that stops a captured assertion being re-presented.

Ported from `validate_jwt_client_assertion` / `enforce_jti_replay`
(`crates/oauth2-actix/src/handlers/oauth.rs`) and `JtiReplayGuard`
(`crates/oauth2-actix/src/security/jti_replay.rs`); the
`invalid_client` descriptions below are reproduced verbatim from those
functions so the two servers' error bodies match.

**Single-process only** — like `DpopReplayStore` (services/dpop.py) and
`ParStore` (services/par.py), `JtiReplayGuard` keeps its state in a plain
`dict` on the instance rather than in shared storage. A multi-worker or
multi-instance deployment needs this backed by e.g. Redis before the
replay guarantee holds across replicas; the Rust implementation has the
same limitation (an in-process `Mutex<HashMap>` behind a `OnceLock`).
"""

from __future__ import annotations

import logging
import time

import jwt
from jwt.algorithms import RSAAlgorithm

from oauth2_server.errors import OAuthError
from oauth2_server.models import Client

logger = logging.getLogger(__name__)

# RFC 7523 §2.2 assertion type URI.
JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# Upper bound on how long a single `(client_id, jti)` entry may live. RFC
# 7523 §3 does not cap `exp`, so an assertion with a multi-day window would
# otherwise turn the guard into a near-permanent store (jti_replay.rs
# `MAX_TTL_SECS`).
MAX_JTI_TTL_SECS = 300

# Hard cap on in-memory entries so a client rotating `jti` values cannot
# exhaust memory (jti_replay.rs `DEFAULT_MAX_ENTRIES`).
DEFAULT_MAX_ENTRIES = 100_000

# Signature algorithm each registered auth method is pinned to. The
# assertion header's `alg` must match EXACTLY — `algorithms=` below is
# always a one-element list, never a permissive set, so a client cannot
# downgrade `private_key_jwt` to an HMAC signed with the client secret.
_ALG_FOR_METHOD = {"client_secret_jwt": "HS256", "private_key_jwt": "RS256"}

_REQUIRED_CLAIMS = ["exp", "sub", "iss", "aud"]


class JtiReplayGuard:
    """In-memory `(client_id, jti)` -> monotonic-expiry map guarding against
    client-assertion replay (RFC 7523 §3 / RFC 9700 §2.5).

    Mirrors `DpopReplayStore` (services/dpop.py): `time.monotonic()` clock,
    a full sweep of expired entries on every call, and no external
    dependencies. **Single-process only** — see the module docstring.
    """

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._entries: dict[str, float] = {}
        self._max_entries = max(1, max_entries)

    def _sweep_expired(self, now: float) -> None:
        expired = [key for key, expiry in self._entries.items() if expiry <= now]
        for key in expired:
            del self._entries[key]

    def observe(self, client_id: str, jti: str, ttl_secs: float) -> bool:
        """Record `(client_id, jti)` for `ttl_secs` (clamped to
        `MAX_JTI_TTL_SECS`). Returns True when the pair is fresh, False when
        it has already been seen within its validity window."""
        ttl = min(max(float(ttl_secs), 0.0), float(MAX_JTI_TTL_SECS))
        now = time.monotonic()
        self._sweep_expired(now)

        key = f"{client_id}\0{jti}"
        if key in self._entries:
            return False

        # Hard cap — drop an arbitrary entry before inserting when full. The
        # sweep above normally keeps the map well under the cap.
        if len(self._entries) >= self._max_entries:
            del self._entries[next(iter(self._entries))]

        self._entries[key] = now + ttl
        return True


def unverified_assertion_subject(assertion: str) -> str | None:
    """Best-effort read of a client assertion's `sub` WITHOUT verifying its
    signature.

    Two callers, both of which need only a lookup key rather than a trusted
    identity: `ClientService.authenticate` resolving the client for a form
    that carries `client_assertion` but no `client_id` (divergence 36), and
    `routes/token.py::_extract_client_id_for_penalty` picking the
    `invalid_client` penalty bucket. The value is always re-checked against
    the verified `sub`/`iss` in `validate_client_assertion` before it can
    authenticate anything.
    """
    if not assertion:
        return None
    try:
        claims = jwt.decode(assertion, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    sub = claims.get("sub")
    return sub if isinstance(sub, str) and sub else None


def validate_client_assertion(
    client: Client,
    assertion: str,
    token_endpoint_url: str,
    *,
    jwks: dict | None,
    guard: JtiReplayGuard,
) -> None:
    """Validate an RFC 7523 §3 client assertion for `client`, raising
    `OAuthError("invalid_client", ...)` on any failure.

    `jwks` must be pre-resolved by the caller (`jwks_cache.
    resolve_client_jwks`) for `private_key_jwt`; it is ignored for
    `client_secret_jwt`. `token_endpoint_url` is the expected `aud` — the
    TOKEN endpoint URL for *every* endpoint that authenticates a client
    this way (introspect, revoke, PAR, device authorization included),
    matching Rust.
    """
    method = client.token_endpoint_auth_method
    expected_alg = _ALG_FOR_METHOD.get(method)
    if expected_alg is None:
        raise OAuthError("invalid_client", "Client is not configured for JWT authentication")

    try:
        header = jwt.get_unverified_header(assertion)
    except jwt.PyJWTError as exc:
        raise OAuthError("invalid_client", "Malformed client_assertion JWT") from exc

    if header.get("alg") != expected_alg:
        raise OAuthError("invalid_client", f"{method} requires {expected_alg} algorithm")

    if method == "client_secret_jwt":
        key: object = client.client_secret
    else:
        key = _rsa_key_from_jwks(jwks, header.get("kid"))

    try:
        claims = jwt.decode(
            assertion,
            key,
            algorithms=[expected_alg],
            audience=token_endpoint_url,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        raise OAuthError("invalid_client", f"{method} validation failed: {exc}") from exc

    # RFC 7523 §3: `iss` and `sub` MUST both equal the client_id.
    if claims.get("iss") != client.client_id or claims.get("sub") != client.client_id:
        raise OAuthError("invalid_client", "JWT iss/sub must equal client_id")

    _enforce_jti_replay(client.client_id, claims, guard)


def _rsa_key_from_jwks(jwks: dict | None, kid: str | None):
    """Select the JWKS key the assertion header points at (by `kid`, else
    the first RSA key) and build a PyJWT verification key from it.

    `jwks` is whatever `resolve_client_jwks` parsed out of the client's
    inline `jwks` column, so it is arbitrary client-controlled JSON — a
    bare array or string parses fine and would otherwise reach `.get()` as
    an unhandled `AttributeError` (500). Everything that is not an object
    with a `keys` array is rejected as `invalid_client` here instead, which
    is also what Rust's `Value::get("keys")` does for a non-object.
    """
    if jwks is None:
        raise OAuthError(
            "invalid_client", "Client must register jwks or jwks_uri for private_key_jwt"
        )
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise OAuthError("invalid_client", "Client JWKS missing 'keys' array")

    if kid is not None:
        match = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
        if match is None:
            raise OAuthError("invalid_client", "No matching kid in client JWKS")
    else:
        match = next((k for k in keys if isinstance(k, dict) and k.get("kty") == "RSA"), None)
        if match is None:
            raise OAuthError("invalid_client", "No RSA key found in client JWKS")

    try:
        return RSAAlgorithm.from_jwk(match)
    except Exception as exc:
        raise OAuthError("invalid_client", "Failed to construct RSA key from client JWKS") from exc


def _enforce_jti_replay(client_id: str, claims: dict, guard: JtiReplayGuard) -> None:
    """RFC 7523 §3 / RFC 9700 §2.5: record the validated assertion's `jti`
    against the client, rejecting a pair already seen in its window.

    `exp` has already been checked by `jwt.decode` (it is in `_REQUIRED_
    CLAIMS` and PyJWT verifies it), so the remaining lifetime is only ever
    used to size the guard entry.
    """
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise OAuthError(
            "invalid_client", "client_assertion missing required jti claim (RFC 7523 §3)"
        )

    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise OAuthError("invalid_client", "client_assertion missing exp claim")

    ttl = max(float(exp) - time.time(), 0.0)
    if not guard.observe(client_id, jti, ttl):
        logger.warning(
            "RFC 7523 §3: rejected replayed client_assertion jti (client_id=%s)", client_id
        )
        raise OAuthError("invalid_client", "client_assertion jti has already been used")
