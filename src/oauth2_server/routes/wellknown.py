"""Discovery metadata, JWKS, and OIDC UserInfo.

- `GET /.well-known/openid-configuration` and
  `GET /.well-known/oauth-authorization-server` (RFC 8414 / OIDC Discovery 1.0)
- `GET /.well-known/jwks.json` — publishes every active RS256 key in
  `app.state.keyset` (Task 13); `{"keys": []}` when only HS256 keys exist
  (HS256 secrets are never published).
- `GET|POST /oauth/userinfo` (OIDC Core §5.3), including resource-side
  proof-of-possession enforcement: a DPoP-bound (`cnf.jkt`) or
  certificate-bound (`cnf["x5t#S256"]`) access token is only accepted when
  the request re-demonstrates that binding (divergences 49/51).
"""

from __future__ import annotations

import hmac
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse
from pydantic import ValidationError

from oauth2_server.keys import SigningKey, jwk_from_rs256_key
from oauth2_server.security import decode_access_token, decode_unverified_claims
from oauth2_server.services.dpop import (
    DpopError,
    DpopValidated,
    read_dpop_header,
    validate_dpop_proof,
)
from oauth2_server.services.claims_request import ClaimsSelection, select_userinfo_claims
from oauth2_server.services.dpop_nonce import enforce_dpop_nonce
from oauth2_server.services.mtls import mtls_headers

router = APIRouter()

# Client-authentication methods the introspection and revocation endpoints
# accept — the token endpoint's list minus `none`, since neither endpoint
# is reachable by an unauthenticated (public) client.
_CONFIDENTIAL_AUTH_METHODS = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    # RFC 8705 §3.3 — implemented in `services/clients.py` and gated on
    # `trust_proxy_headers` (divergence 47).
    "tls_client_auth",
    "self_signed_tls_client_auth",
]

# Shared between the discovery document's `scopes_supported` and the RFC
# 9728 protected-resource metadata's `scopes_supported` — the two must stay
# in lockstep, so this is the single source of truth for both.
SCOPES_SUPPORTED = ["openid", "profile", "email", "read", "write", "admin"]

# RFC 9449 §10: narrower than what services/dpop.py actually accepts
# (RS256/384/512, PS256/384/512, ES256/384) — Rust parity, shared between
# discovery and the RFC 9728 protected-resource metadata.
_DPOP_SIGNING_ALG_VALUES_SUPPORTED = ["ES256", "RS256"]

# Token status-list stub (Task 3, phase 4a). This is a fixed, non-functional
# placeholder — no real token revocation status is tracked via status
# lists — kept only for byte-for-byte parity with the Rust server's
# `/.well-known/oauth-authorization-server/status` handler.
_STATUS_LIST_STUB = {"bits": 1, "lst": "eNrb2FgAAQABAAE"}


def _discovery_document(
    issuer: str,
    id_token_alg: str,
    rar_types_supported: list[str],
    *,
    has_rs256_key: bool,
    acr_values_supported: list[str],
    mtls_base: str | None = None,
) -> dict:
    base = issuer.rstrip("/")
    doc = _discovery_body(
        base, id_token_alg, rar_types_supported, has_rs256_key, acr_values_supported
    )
    if mtls_base:
        m = mtls_base.rstrip("/")
        # RFC 8705 §5: only endpoints that authenticate a client / bind a
        # token are aliased; browser-facing endpoints stay on the issuer host.
        doc["mtls_endpoint_aliases"] = {
            "token_endpoint": f"{m}/oauth/token",
            "revocation_endpoint": f"{m}/oauth/revoke",
            "introspection_endpoint": f"{m}/oauth/introspect",
            "userinfo_endpoint": f"{m}/oauth/userinfo",
            "device_authorization_endpoint": f"{m}/oauth/device_authorization",
            "pushed_authorization_request_endpoint": f"{m}/oauth/par",
        }
    return doc


def _discovery_body(
    base: str,
    id_token_alg: str,
    rar_types_supported: list[str],
    has_rs256_key: bool,
    acr_values_supported: list[str],
) -> dict:
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "introspection_endpoint": f"{base}/oauth/introspect",
        "revocation_endpoint": f"{base}/oauth/revoke",
        # Aliases for the two endpoints above — Rust parity (some client
        # libraries look for the `token_` prefixed names instead of the
        # RFC 8414 field names).
        "token_introspection_endpoint": f"{base}/oauth/introspect",
        "token_revocation_endpoint": f"{base}/oauth/revoke",
        "userinfo_endpoint": f"{base}/oauth/userinfo",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "registration_endpoint": f"{base}/connect/register",
        "service_documentation": f"{base}/docs",
        "device_authorization_endpoint": f"{base}/oauth/device_authorization",
        "pushed_authorization_request_endpoint": f"{base}/oauth/par",
        "require_pushed_authorization_requests": False,
        "request_uri_parameter_supported": True,
        # RFC 9101 (JAR): `request=` JWT-encoded authorization requests are
        # supported (`services/jar.py::process_jar`) — `none`/HS256/RS256,
        # dispatched on the client's registered `token_endpoint_auth_method`.
        # `request_uri=` (RFC 9101 §5.2, a JAR fetched from a URL) remains
        # unsupported; only PAR's own `request_uri` value is accepted there.
        "request_parameter_supported": True,
        "claims_parameter_supported": True,
        "end_session_endpoint": f"{base}/oauth/logout",
        "check_session_iframe": f"{base}/oauth/check_session",
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
        "frontchannel_logout_supported": True,
        "frontchannel_logout_session_supported": True,
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "response_types_supported": ["code", "code id_token"],
        "response_modes_supported": ["query", "form_post", "fragment"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [*_CONFIDENTIAL_AUTH_METHODS, "none"],
        # RFC 8705 §3.3: the token endpoint binds `cnf["x5t#S256"]` onto
        # access tokens issued over mTLS, and introspection enforces it
        # (divergence 49).
        "tls_client_certificate_bound_access_tokens": True,
        # RFC 8414 §2: introspection/revocation accept the same client-auth
        # methods as the token endpoint, minus `none` — those endpoints
        # always require an authenticated client.
        "introspection_endpoint_auth_methods_supported": list(_CONFIDENTIAL_AUTH_METHODS),
        "revocation_endpoint_auth_methods_supported": list(_CONFIDENTIAL_AUTH_METHODS),
        "authorization_response_iss_parameter_supported": True,
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        # Divergence 43: what `services/jar.py::process_jar` actually
        # implements (`none` dispatched for `token_endpoint_auth_method=none`
        # clients, HS256 for `client_secret_*`, RS256 for `private_key_jwt`)
        # — not Rust's `["RS256", "ES256", "HS256"]` (ES256 unimplemented
        # there, `none` implemented but unadvertised).
        "request_object_signing_alg_values_supported": ["RS256", "HS256", "none"],
        # RFC 9470 step-up: only values this server can actually attest to
        # at login (divergence 42) — config-driven, default bronze.
        "acr_values_supported": acr_values_supported,
        "scopes_supported": SCOPES_SUPPORTED,
        "subject_types_supported": ["public"],
        # RFC 9701 §7: the algorithms a JWT-secured introspection response
        # may actually be signed with here — RS256 (the JWKS-published
        # keyset key) is only advertised when the keyset holds one, because
        # without it `security.py::encode_introspection_jwt` can never
        # produce RS256; every response then falls to HS256 under the
        # requesting client's own secret.
        "introspection_signing_alg_values_supported": (
            ["RS256", "HS256"] if has_rs256_key else ["HS256"]
        ),
        "id_token_signing_alg_values_supported": (
            ["RS256"] if id_token_alg == "RS256" else ["HS256"]
        ),
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "nonce",
            "at_hash",
            "email",
            "preferred_username",
            "c_hash",
            "acr",
            "amr",
            "auth_time",
        ],
        # RFC 9449 §10: narrower than what services/dpop.py actually accepts
        # (RS256/384/512, PS256/384/512, ES256/384) — Rust parity
        # (research-dpop.md key_behaviors: "Discovery advertises ...
        # narrower than the 8 algs the validator actually accepts").
        "dpop_signing_alg_values_supported": _DPOP_SIGNING_ALG_VALUES_SUPPORTED,
        # RFC 9396 §18.2 — config-driven (`config.rar_types_supported`) and
        # actually enforced by `services/rar.py`, unlike the Rust server's
        # hardcoded, unenforced ["openid"] (research-rar-token-exchange.md
        # gotchas).
        "authorization_details_types_supported": rar_types_supported,
        # RFC 8707 §3: the `resource` parameter is accepted at /oauth/authorize
        # and /oauth/token and binds the issued access token's `aud`.
        "resource_indicators_supported": True,
    }


@router.get("/.well-known/openid-configuration")
@router.get("/.well-known/oauth-authorization-server")
async def openid_configuration(request: Request) -> ORJSONResponse:
    config = request.app.state.config
    keyset = request.app.state.keyset
    return ORJSONResponse(
        _discovery_document(
            config.issuer,
            config.id_token_alg,
            config.rar_types_supported,
            has_rs256_key=keyset.current_for_alg("RS256") is not None,
            acr_values_supported=config.acr_values_supported,
            mtls_base=config.mtls_endpoint_base_url if config.trust_proxy_headers else None,
        )
    )


@router.get("/.well-known/jwks.json")
async def jwks(request: Request) -> ORJSONResponse:
    config = request.app.state.config
    keyset = request.app.state.keyset

    keys = [jwk_from_rs256_key(key) for key in keyset.active_keys() if key.algorithm == "RS256"]

    if not keys and config.id_token_alg == "RS256" and config.id_token_private_key_pem:
        # Fallback: the keyset holds zero RS256 keys (e.g. the seeded
        # rs256-initial key was rotated out and pruned) but RS256 id_tokens
        # are still being signed straight from the env PEM — publish that
        # key's public half so OIDC clients can keep verifying id_tokens.
        # `kid` is included only when OAUTH2_ID_TOKEN_KID is configured
        # (Rust parity).
        fallback = SigningKey(
            kid=config.id_token_kid or "",
            algorithm="RS256",
            key_material=config.id_token_private_key_pem.encode(),
            is_current=True,
            created_at=datetime.now(timezone.utc),
        )
        jwk = jwk_from_rs256_key(fallback)
        if not config.id_token_kid:
            del jwk["kid"]
        keys = [jwk]

    response = ORJSONResponse({"keys": keys})
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@router.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request) -> ORJSONResponse:
    """RFC 9728 OAuth 2.0 Protected Resource Metadata."""
    config = request.app.state.config
    base = config.issuer.rstrip("/")
    response = ORJSONResponse(
        {
            "resource": base,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "dpop_signing_alg_values_supported": _DPOP_SIGNING_ALG_VALUES_SUPPORTED,
            "token_introspection_endpoint": f"{base}/oauth/introspect",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "scopes_supported": SCOPES_SUPPORTED,
            "tls_client_certificate_bound_access_tokens": True,
        }
    )
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@router.get("/.well-known/oauth-authorization-server/status")
async def token_status_list(request: Request) -> ORJSONResponse:
    """Token status-list stub (Task 3, phase 4a) — Rust handler parity.

    This is a fixed, non-functional placeholder: no real per-token
    revocation status is tracked or encoded here.
    """
    config = request.app.state.config
    base = config.issuer.rstrip("/")
    return ORJSONResponse(
        {
            "status_list": _STATUS_LIST_STUB,
            "issuer": base,
            "status_list_uri": f"{base}/.well-known/oauth-authorization-server/status",
        }
    )


def _missing_token_response() -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_token", "error_description": "Missing access token"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _invalid_token_response(description: str) -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_token", "error_description": description},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def _dpop_invalid_token_response(description: str) -> ORJSONResponse:
    """RFC 9449 §7.1: a DPoP-bound token's failures are challenged with the
    `DPoP` scheme, so a client knows to retry with a proof rather than
    re-sending the same Bearer request."""
    return ORJSONResponse(
        {"error": "invalid_token", "error_description": description},
        status_code=401,
        headers={"WWW-Authenticate": 'DPoP error="invalid_token"'},
    )


def _resource_nonce_challenge(as_challenge: ORJSONResponse) -> ORJSONResponse:
    """Re-shape the AS-side `use_dpop_nonce` 400 (which carries the fresh
    `DPoP-Nonce`) into the RFC 9449 §9 resource-server 401."""
    return ORJSONResponse(
        {"error": "use_dpop_nonce", "error_description": "DPoP proof nonce required or stale"},
        status_code=401,
        headers={
            "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
            "DPoP-Nonce": as_challenge.headers["DPoP-Nonce"],
        },
    )


# Authorization schemes `/oauth/userinfo` understands, compared ASCII
# case-insensitively (RFC 9110 §11.1: the scheme token is case-insensitive;
# Rust matches `"Bearer "` exactly — divergence 51).
_USERINFO_AUTH_SCHEMES = frozenset({"bearer", "dpop"})


def _enforce_token_binding(
    request: Request, config, token_str: str
) -> tuple[ORJSONResponse | None, DpopValidated | None]:
    """Divergences 49/51: enforce an access token's `cnf` confirmation at the
    resource endpoint. Returns `(failure, dpop_validated)` — a 401 response on
    failure and `None` for the proof, or `(None, proof_or_None)` on success
    (including the no-`cnf` case, which is every token this server issued
    before phase 4b/4c and every token issued without a proof or a client
    certificate).

    `cnf` is read with `decode_unverified_claims` — the storage row, not the
    signature, is userinfo's authority for whether a token is valid at all
    (see `userinfo` below), and this only reads a binding back out of a token
    that already passed that gate. Opaque tokens decode to no claims and so
    carry no binding, exactly as at introspection.

    Each failure carries a DISTINCT `error_description`. That is deliberate
    and safe here: unlike introspection (an unauthenticated-ish oracle that
    collapses everything to `{"active": false}`), reaching this code already
    required presenting a live access token, so the caller learns nothing
    about a token they do not already hold. The descriptions never echo the
    expected `jkt`/thumbprint.
    """
    cnf = decode_unverified_claims(token_str).get("cnf")
    if not isinstance(cnf, dict):
        return None, None

    # The validated proof, carried back out so the caller can decide whether
    # a `DPoP-Nonce` belongs on the successful response (divergence 53).
    validated: DpopValidated | None = None

    # `isinstance` guards throughout: these claims come from an UNVERIFIED
    # decode, so they need not be strings at all.
    jkt = cnf.get("jkt")
    if isinstance(jkt, str) and jkt:
        scheme = request.headers.get("authorization", "").partition(" ")[0].lower()
        if scheme != "dpop":
            return (
                _dpop_invalid_token_response(
                    "DPoP-bound access token must be presented with the DPoP scheme"
                ),
                None,
            )

        try:
            proof = read_dpop_header(request)
        except DpopError:
            # Non-UTF-8 DPoP header; at the token endpoint this is a 400
            # `invalid_request`, but here it is simply an unusable proof.
            proof = None
        if proof is None:
            return (
                _dpop_invalid_token_response("DPoP proof required for this access token"),
                None,
            )

        try:
            validated = validate_dpop_proof(
                proof,
                request.method,
                config.issuer.rstrip("/") + "/oauth/userinfo",
                # The SHARED per-app replay store (`app.state.dpop_replay`),
                # the same one the token and introspection endpoints use, so
                # a proof is single-use across every endpoint.
                request.app.state.dpop_replay,
                # Divergence 50: `ath` is required here, bound to the token
                # exactly AS PRESENTED in the Authorization header.
                access_token=token_str,
            )
        except DpopError:
            return _dpop_invalid_token_response("DPoP proof validation failed"), None

        # Compare UTF-8 bytes: `jkt` came off an unverified decode and may be
        # non-ASCII, which makes `hmac.compare_digest` raise TypeError on
        # `str` — same hazard/fix as `routes/introspect.py` (Task 3).
        if not hmac.compare_digest(validated.jkt.encode("utf-8"), jkt.encode("utf-8")):
            return (
                _dpop_invalid_token_response(
                    "DPoP proof key does not match the access token binding"
                ),
                None,
            )

    thumb = cnf.get("x5t#S256")
    if isinstance(thumb, str) and thumb:
        # Divergence 49: the presented thumbprint comes from `mtls_headers`,
        # which returns `None` unless `trust_proxy_headers` is set
        # (divergence 47) — a forged header behind an untrusted proxy reads
        # as MISSING, not as a match. Certificate binding keeps the `Bearer`
        # challenge: there is no proof for the client to add.
        presented = mtls_headers(request, config)[0]
        if presented is None or not hmac.compare_digest(
            presented.encode("utf-8"), thumb.encode("utf-8")
        ):
            return (
                _invalid_token_response(
                    "Certificate-bound access token requires a matching client certificate"
                ),
                None,
            )

    return None, validated


@router.get("/oauth/userinfo")
@router.post("/oauth/userinfo")
async def userinfo(request: Request) -> ORJSONResponse:
    auth_header = request.headers.get("authorization", "")
    scheme, _, rest = auth_header.partition(" ")
    token_str = None
    if scheme.lower() in _USERINFO_AUTH_SCHEMES:
        candidate = rest.strip()
        if candidate:
            token_str = candidate

    if token_str is None:
        return _missing_token_response()

    config = request.app.state.config
    storage = request.app.state.storage

    # Try the JWT path first (verifies signature, issuer, and expiry); fall
    # back to an opaque-token storage lookup on any decode failure.
    # Note: the storage row lookup is the authoritative gate for token validity.
    try:
        decode_access_token(
            token_str, config.jwt_secret, config.issuer, keyset=request.app.state.keyset
        )
    except (jwt.PyJWTError, ValidationError):
        pass

    row = await storage.get_token_by_access_token(token_str)
    if row is None or row.revoked or row.expires_at <= datetime.now(timezone.utc):
        return _invalid_token_response("Invalid or expired access token")

    binding_failure, dpop_validated = _enforce_token_binding(request, config, token_str)
    if binding_failure is not None:
        return binding_failure

    subject = row.user_id
    if subject is None:
        return _invalid_token_response("Access token does not represent an authenticated user")

    scopes = set(row.scope.split())
    response: dict[str, str] = {"sub": subject, "iss": config.issuer, "aud": row.client_id}

    token_client = None
    if dpop_validated is not None:
        # Divergences 53/62: userinfo has no client row of its own — look one
        # up only on the proof path (at most once per request). A deleted
        # client simply yields no nonce handling.
        token_client = await storage.get_client(row.client_id)
        if token_client is not None and token_client.dpop_nonce_required:
            # RFC 9449 §9: a resource server that requires nonces answers a
            # missing/stale one with 401 `use_dpop_nonce` + a fresh
            # `DPoP-Nonce` (the token endpoint's 400 is the AS-side shape).
            try:
                challenge = enforce_dpop_nonce(dpop_validated, request.app.state.dpop_nonce_issuer)
            except DpopError:
                return _dpop_invalid_token_response("DPoP proof validation failed")
            if challenge is not None:
                return _resource_nonce_challenge(challenge)

    # Divergence 63: the `userinfo` member of the `claims` request stored on
    # the authorization code this token descends from. Only ever subtracts.
    selection = ClaimsSelection()
    if row.token_family:
        code = await storage.get_authorization_code_by_token_family(row.token_family)
        if code is not None:
            selection = select_userinfo_claims(code.claims_request, scope=row.scope)

    user = await storage.get_user_by_id(subject)
    if user is not None:
        if "email" in scopes and selection.allows("email", user.email):
            response["email"] = user.email
        if "profile" in scopes and selection.allows("preferred_username", user.username):
            response["preferred_username"] = user.username

    result = ORJSONResponse(response)
    if token_client is not None and token_client.dpop_nonce_required:
        result.headers["DPoP-Nonce"] = request.app.state.dpop_nonce_issuer.issue()
    return result
