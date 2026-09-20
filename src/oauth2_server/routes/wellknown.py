"""Discovery metadata, JWKS, and OIDC UserInfo.

- `GET /.well-known/openid-configuration` and
  `GET /.well-known/oauth-authorization-server` (RFC 8414 / OIDC Discovery 1.0)
- `GET /.well-known/jwks.json` — publishes every active RS256 key in
  `app.state.keyset` (Task 13); `{"keys": []}` when only HS256 keys exist
  (HS256 secrets are never published).
- `GET|POST /oauth/userinfo` (OIDC Core §5.3)
"""

from __future__ import annotations

from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse
from pydantic import ValidationError

from oauth2_server.keys import SigningKey, jwk_from_rs256_key
from oauth2_server.security import decode_access_token

router = APIRouter()

# Client-authentication methods the introspection and revocation endpoints
# accept — the token endpoint's list minus `none`, since neither endpoint
# is reachable by an unauthenticated (public) client.
_CONFIDENTIAL_AUTH_METHODS = [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
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


def _discovery_document(issuer: str, id_token_alg: str, rar_types_supported: list[str]) -> dict:
    base = issuer.rstrip("/")
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
        # Divergence: JAR (`request=`/`request_uri=` JWT-encoded authorization
        # requests, RFC 9101) was not ported — only PAR's own `request_uri`
        # value is supported.
        "request_parameter_supported": False,
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
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
            "none",
        ],
        # RFC 8414 §2: introspection/revocation accept the same client-auth
        # methods as the token endpoint, minus `none` — those endpoints
        # always require an authenticated client.
        "introspection_endpoint_auth_methods_supported": list(_CONFIDENTIAL_AUTH_METHODS),
        "revocation_endpoint_auth_methods_supported": list(_CONFIDENTIAL_AUTH_METHODS),
        "authorization_response_iss_parameter_supported": True,
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        "scopes_supported": SCOPES_SUPPORTED,
        "subject_types_supported": ["public"],
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
    return ORJSONResponse(
        _discovery_document(config.issuer, config.id_token_alg, config.rar_types_supported)
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
    """RFC 9728 OAuth 2.0 Protected Resource Metadata.

    Divergence 33: `tls_client_certificate_bound_access_tokens` is omitted —
    mTLS (RFC 8705) is not implemented by this server.
    """
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


@router.get("/oauth/userinfo")
@router.post("/oauth/userinfo")
async def userinfo(request: Request) -> ORJSONResponse:
    auth_header = request.headers.get("authorization", "")
    token_str = None
    if auth_header.startswith("Bearer "):
        candidate = auth_header[len("Bearer ") :].strip()
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

    subject = row.user_id
    if subject is None:
        return _invalid_token_response("Access token does not represent an authenticated user")

    scopes = set(row.scope.split())
    response: dict[str, str] = {"sub": subject, "iss": config.issuer, "aud": row.client_id}

    user = await storage.get_user_by_id(subject)
    if user is not None:
        if "email" in scopes:
            response["email"] = user.email
        if "profile" in scopes:
            response["preferred_username"] = user.username

    return ORJSONResponse(response)
