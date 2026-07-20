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


def _discovery_document(issuer: str, id_token_alg: str) -> dict:
    base = issuer.rstrip("/")
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "introspection_endpoint": f"{base}/oauth/introspect",
        "revocation_endpoint": f"{base}/oauth/revoke",
        "userinfo_endpoint": f"{base}/oauth/userinfo",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "registration_endpoint": f"{base}/connect/register",
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
        ],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "authorization_response_iss_parameter_supported": True,
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        "scopes_supported": ["openid", "profile", "email", "read", "write", "admin"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": (
            ["RS256"] if id_token_alg == "RS256" else ["HS256"]
        ),
        "claims_supported": ["sub", "email", "preferred_username"],
    }


@router.get("/.well-known/openid-configuration")
@router.get("/.well-known/oauth-authorization-server")
async def openid_configuration(request: Request) -> ORJSONResponse:
    config = request.app.state.config
    return ORJSONResponse(_discovery_document(config.issuer, config.id_token_alg))


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
    response: dict[str, str] = {"sub": subject}

    user = await storage.get_user_by_id(subject)
    if user is not None:
        if "email" in scopes:
            response["email"] = user.email
        if "profile" in scopes:
            response["preferred_username"] = user.username

    return ORJSONResponse(response)
