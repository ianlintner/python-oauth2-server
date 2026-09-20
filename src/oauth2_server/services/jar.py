"""RFC 9101 §4 JWT-Secured Authorization Requests — the `request` parameter.

Ported from `process_jar` (`crates/oauth2-actix/src/handlers/oauth.rs`) and
its call site in `authorize`; the descriptions below are reproduced verbatim
from those functions so the two servers' error bodies match.

**Dispatch is on the client's REGISTERED `token_endpoint_auth_method`, never
on the JWT's own `alg` header.** That is the whole security property of this
module: the request object's signature is checked with the algorithm the
client registered for, and `algorithms=` is always a one-element list, so a
`private_key_jwt` client's JAR can never be downgraded to an HMAC (nor to
`alg=none`) by an attacker who only controls the JOSE header. The `none`
branch never reaches `jwt.decode` at all — the payload is base64url-decoded
by hand, so there is no code path in which PyJWT is asked to "verify" an
unsigned token.

**Divergence 41 — error codes.** Rust returns a flat `invalid_request` for
every JAR failure. RFC 9101 §5 defines `invalid_request_object` for a
request object that "is not valid", so *verification* failures (signature,
`exp`, `aud`, `alg` mismatch, `iss` not equal to `client_id`) carry that
code here, while structural and unsupported-configuration failures (not a
JWT, bad base64url/JSON, an auth method with no JAR signing rule) stay
`invalid_request`. The same divergence adds the `client_id` binding check
below: RFC 9101 §4 requires the request object's `client_id`, when present,
to equal the one in the query string, which Rust never checks.

Everything this returns is a *verified* value that the authorize handler
overlays on top of the query string and any PAR-pushed parameters, so the
return type is deliberately narrow: only `JAR_OVERLAY_KEYS`, and only string
values (Rust reads each claim through `Value::as_str()`, which silently
ignores numbers, objects and arrays — an overlay is a query parameter, and a
query parameter is a string).
"""

from __future__ import annotations

import base64
import binascii
import json

import jwt

from oauth2_server.errors import OAuthError
from oauth2_server.models import Client
from oauth2_server.services.client_assertion import rsa_key_from_jwks
from oauth2_server.services.jwks_cache import JwksCache, resolve_client_jwks

# The authorization-request parameters a JAR payload may supply. `client_id`
# is deliberately absent: it always comes from the query string (it is what
# locates the client, and hence the verification key, in the first place) and
# is only *cross-checked* against the payload below. `request_uri`, `prompt`,
# `max_age` and `login_hint` are likewise never read from the payload (Rust
# parity).
JAR_OVERLAY_KEYS = (
    "redirect_uri",
    "response_type",
    "response_mode",
    "scope",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "resource",
    "state",
    "authorization_details",
    "claims",
    "acr_values",
)

# Signature algorithm each registered auth method pins its JAR to, mirroring
# `client_assertion._ALG_FOR_METHOD`. `none` is handled separately (it is not
# an algorithm PyJWT may ever be handed).
_ALG_FOR_METHOD = {
    "client_secret_basic": "HS256",
    "client_secret_post": "HS256",
    "client_secret_jwt": "HS256",
    "private_key_jwt": "RS256",
}

# Both mandatory for a signed JAR (Rust `set_required_spec_claims`). `aud` is
# required implicitly: `jwt.decode` is always given an `audience`, so a
# payload without one fails as a missing-claim error.
_REQUIRED_CLAIMS = ["exp", "iss"]

_URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")


async def process_jar(
    client: Client,
    request_jwt: str,
    *,
    authorize_url: str,
    jwks_cache: JwksCache | None,
) -> dict[str, str]:
    """Verify a `request=` JAR for `client` and return its overlayable claims.

    `authorize_url` is the expected `aud` — `f"{issuer}/oauth/authorize"`,
    built by the caller. `jwks_cache` is the app's `JwksCache` (only touched
    for `private_key_jwt` clients, and only when they registered a
    `jwks_uri` rather than inline `jwks`).

    Raises `OAuthError` (always 400 at the authorize endpoint, which calls
    this before any `redirect_uri` is trusted).
    """
    # Rust's `splitn(3, '.')`: a 4-segment string is not rejected here, it
    # simply carries the extra dot into the signature segment and fails
    # verification (and, for `alg=none`, the empty-signature check).
    parts = request_jwt.split(".", 2)
    if len(parts) < 3:
        raise OAuthError(
            "invalid_request", "JAR request is not a valid JWT (expected header.payload.signature)"
        )

    method = client.token_endpoint_auth_method
    if method == "none":
        claims = _decode_unsigned_jar(parts)
    elif method in _ALG_FOR_METHOD:
        claims = await _decode_signed_jar(
            client, request_jwt, method=method, authorize_url=authorize_url, jwks_cache=jwks_cache
        )
    else:
        raise OAuthError(
            "invalid_request", f"Unsupported token_endpoint_auth_method '{method}' for JAR signing"
        )

    # RFC 9101 §4 (divergence 41): a request object that names a client must
    # name *this* one. Without this, a JAR legitimately issued for client A
    # could be replayed on an authorization request for client B whose key
    # happens to verify it (e.g. two public clients, both unsigned).
    payload_client_id = claims.get("client_id")
    if payload_client_id is not None and payload_client_id != client.client_id:
        raise OAuthError("invalid_request_object", "JAR client_id does not match")

    return {
        key: claims[key]
        for key in JAR_OVERLAY_KEYS
        if isinstance(claims.get(key), str)  # Rust `as_str()`: non-strings vanish
    }


def _b64url_decode(segment: str, what: str) -> bytes:
    """Decode one JWS segment, accepting both the unpadded form RFC 7515
    mandates and a padded one (Rust falls back to `URL_SAFE` the same way)."""
    padded = segment.translate(_URLSAFE_TO_STANDARD) + "=" * (-len(segment) % 4)
    try:
        # validate=True so a segment with non-base64 characters is an error
        # rather than being silently stripped down to something decodable.
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OAuthError("invalid_request", f"JAR JWT {what} is not valid base64url") from exc


def _decode_unsigned_jar(parts: list[str]) -> dict:
    """Public clients (`token_endpoint_auth_method = "none"`) have no key to
    verify against, so the JAR must be *structurally* unsigned: `alg=none`
    and an empty signature segment.

    Without both checks any JWT-shaped string would have its payload trusted
    — a signature-bypass primitive. The payload is therefore decoded by hand
    rather than through `jwt.decode(..., algorithms=["none"])`, which would
    mean enabling the `none` algorithm inside PyJWT for this process.

    Nothing else is checked: an unsigned JAR carries no `iss`/`aud`/`exp`
    requirement (there is no signature for those claims to protect).
    """
    header_bytes = _b64url_decode(parts[0], "header")
    try:
        header = json.loads(header_bytes)
    except ValueError as exc:
        raise OAuthError("invalid_request", "JAR JWT header is not valid JSON") from exc
    if not isinstance(header, dict) or header.get("alg") != "none":
        raise OAuthError(
            "invalid_request",
            "JAR from public client must use alg=none; signed JARs require a "
            "confidential client authentication method",
        )
    # RFC 7515 §6: with alg=none the JWS signature MUST be the empty string.
    if parts[2] != "":
        raise OAuthError("invalid_request", "JAR with alg=none must have an empty signature")

    payload_bytes = _b64url_decode(parts[1], "payload")
    try:
        payload = json.loads(payload_bytes)
    except ValueError as exc:
        raise OAuthError("invalid_request", "JAR JWT payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise OAuthError("invalid_request", "JAR JWT payload is not valid JSON")
    return payload


async def _decode_signed_jar(
    client: Client,
    request_jwt: str,
    *,
    method: str,
    authorize_url: str,
    jwks_cache: JwksCache | None,
) -> dict:
    """Verify an HS256 (shared-secret) or RS256 (`private_key_jwt`) JAR.

    `algorithms=[expected_alg]` is what pins the algorithm: PyJWT rejects a
    header `alg` outside that one-element list before it looks at the key,
    so the JOSE header can never pick the verification algorithm.
    """
    expected_alg = _ALG_FOR_METHOD[method]

    key: object
    if expected_alg == "HS256":
        if not client.client_secret:
            # A confidential auth method with no stored secret would hand
            # `jwt.decode` an empty HMAC key, i.e. a signature anyone can
            # forge. Rust has the same hole; refuse instead of verifying
            # against nothing.
            raise OAuthError(
                "invalid_request", f"Client has no client_secret registered for {method} JAR"
            )
        key = client.client_secret
    else:
        jwks = await resolve_client_jwks(client, jwks_cache)
        try:
            header = jwt.get_unverified_header(request_jwt)
        except jwt.PyJWTError as exc:
            raise OAuthError("invalid_request", "JAR JWT header is malformed") from exc
        key = rsa_key_from_jwks(
            jwks, header.get("kid"), error="invalid_request", context=" for JAR"
        )

    try:
        claims = jwt.decode(
            request_jwt,
            key,
            algorithms=[expected_alg],
            audience=authorize_url,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        raise OAuthError(
            "invalid_request_object", f"JAR {expected_alg} verification failed: {exc}"
        ) from exc

    if claims.get("iss") != client.client_id:
        raise OAuthError("invalid_request_object", "JAR 'iss' claim must equal client_id")
    return claims
