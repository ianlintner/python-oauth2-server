"""POST /oauth/token — RFC 6749 §3.2 token endpoint."""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.errors import OAuthError, oauth_error
from oauth2_server.models import IdTokenClaims
from oauth2_server.security import encode_id_token
from oauth2_server.services.auth import scope_is_subset
from oauth2_server.services.clients import ClientService
from oauth2_server.services.tokens import TokenService

router = APIRouter()

_MIN_VERIFIER_LEN = 43
_MAX_VERIFIER_LEN = 128


def _half_hash(value: str) -> str:
    """OIDC Core §3.3.2.11 / §3.1.3.6: base64url-no-pad(left-half(SHA-256(value)))."""
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@router.post("/token")
async def token(request: Request) -> ORJSONResponse:
    form = dict(await request.form())
    storage = request.app.state.storage
    config = request.app.state.config

    try:
        client = await ClientService(storage).authenticate(
            form, request.headers.get("authorization")
        )
    except OAuthError as exc:
        return oauth_error(exc.error, exc.description, exc.status)

    grant_type = form.get("grant_type")

    if grant_type == "client_credentials":
        if client.is_public():
            return oauth_error(
                "invalid_client", "Public clients cannot use the client_credentials grant"
            )

        if "client_credentials" not in client.grant_type_list():
            return oauth_error(
                "unauthorized_client", "client is not authorized for this grant type"
            )

        requested_scope = form.get("scope") or ""
        if requested_scope:
            client_scopes = set(client.scope.split())
            scope = " ".join(s for s in requested_scope.split() if s in client_scopes)
        else:
            scope = client.scope

        token_response = await TokenService(storage, config).issue(
            client, None, scope, with_refresh=False
        )
        response = ORJSONResponse(token_response.model_dump(exclude_none=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    if grant_type == "authorization_code":
        code_value = form.get("code")
        auth_code = await storage.get_authorization_code(code_value) if code_value else None
        if auth_code is None:
            return oauth_error("invalid_grant", "authorization code not found")

        if auth_code.client_id != client.client_id:
            return oauth_error("invalid_grant", "authorization code was not issued to this client")

        if auth_code.expires_at < datetime.now(timezone.utc):
            return oauth_error("invalid_grant", "authorization code has expired")

        if auth_code.used:
            # RFC 9700 §2.1.5: replaying a used code revokes the whole token family.
            if auth_code.token_family:
                await storage.revoke_token_family(auth_code.token_family)
            return oauth_error("invalid_grant", "authorization code has already been used")

        if form.get("redirect_uri") != auth_code.redirect_uri:
            return oauth_error(
                "invalid_grant", "redirect_uri does not match the authorization request"
            )

        if auth_code.code_challenge:
            verifier = form.get("code_verifier")
            if not verifier or not (_MIN_VERIFIER_LEN <= len(verifier) <= _MAX_VERIFIER_LEN):
                return oauth_error(
                    "invalid_request", "code_verifier must be between 43 and 128 characters"
                )
            if not secrets.compare_digest(_pkce_challenge(verifier), auth_code.code_challenge):
                return oauth_error("invalid_grant", "code_verifier does not match code_challenge")
        elif client.is_public():
            return oauth_error("invalid_grant", "public clients must use PKCE")

        await storage.mark_authorization_code_used(auth_code.code)

        token_response = await TokenService(storage, config).issue(
            client,
            auth_code.user_id,
            auth_code.scope,
            with_refresh=True,
            token_family=auth_code.token_family,
        )

        scope_set = set(auth_code.scope.split())
        if "openid" in scope_set:
            now = int(datetime.now(timezone.utc).timestamp())
            id_claims = IdTokenClaims(
                iss=config.issuer,
                sub=auth_code.user_id,
                aud=client.client_id,
                exp=now + config.access_token_ttl_secs,
                iat=now,
                nonce=auth_code.nonce,
                c_hash=_half_hash(auth_code.code),
                at_hash=_half_hash(token_response.access_token),
            )
            if "email" in scope_set or "profile" in scope_set:
                user = await storage.get_user_by_id(auth_code.user_id)
                if user is not None:
                    if "email" in scope_set:
                        id_claims.email = user.email
                    if "profile" in scope_set:
                        id_claims.preferred_username = user.username
            token_response.id_token = encode_id_token(id_claims, config.jwt_secret)

        response = ORJSONResponse(token_response.model_dump(exclude_none=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    if grant_type == "refresh_token":
        refresh_token_value = form.get("refresh_token")
        old_token = (
            await storage.get_token_by_refresh_token(refresh_token_value)
            if refresh_token_value
            else None
        )
        if old_token is None:
            return oauth_error("invalid_grant", "refresh token not found")

        if old_token.client_id != client.client_id:
            return oauth_error("invalid_grant", "refresh token does not belong to this client")

        if old_token.revoked:
            # OAuth 2.0 Security BCP §4.13.2: reuse of a rotated refresh token
            # revokes the whole token family.
            if old_token.token_family:
                await storage.revoke_token_family(old_token.token_family)
            return oauth_error("invalid_grant", "refresh token has been revoked")

        requested_scope = form.get("scope")
        if requested_scope:
            if not scope_is_subset(requested_scope, old_token.scope):
                return oauth_error("invalid_scope", "requested scope exceeds the original grant")
            scope = requested_scope
        else:
            scope = old_token.scope

        family = old_token.token_family or uuid.uuid4().hex
        await storage.revoke_token(old_token.access_token)

        token_response = await TokenService(storage, config).issue(
            client, old_token.user_id, scope, with_refresh=True, token_family=family
        )
        response = ORJSONResponse(token_response.model_dump(exclude_none=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        device_code = form.get("device_code")
        device = (
            await storage.get_device_authorization_by_device_code(device_code)
            if device_code
            else None
        )
        if device is None or device.client_id != client.client_id:
            return oauth_error("invalid_grant", "device_code not found for this client")

        if device.expires_at <= datetime.now(timezone.utc):
            return oauth_error("expired_token", "device_code has expired")

        if device.denied:
            return oauth_error("access_denied", "user denied the device authorization request")

        if device.used:
            return oauth_error("invalid_grant", "device_code has already been redeemed")

        if not device.approved:
            return oauth_error("authorization_pending", "authorization request is still pending")

        await storage.mark_device_authorization_used(device.device_code)

        token_response = await TokenService(storage, config).issue(
            client,
            device.user_id,
            device.scope,
            with_refresh=True,
            token_family=uuid.uuid4().hex,
        )
        response = ORJSONResponse(token_response.model_dump(exclude_none=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    return oauth_error("unsupported_grant_type", f"grant_type '{grant_type}' is not supported")
