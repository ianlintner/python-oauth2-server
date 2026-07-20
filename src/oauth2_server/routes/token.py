"""POST /oauth/token — RFC 6749 §3.2 token endpoint.

RFC 9449 DPoP notes (see `.superpowers/sdd/research-dpop.md` for the Rust
source this is ported from):

- **htu is issuer-based, not Host-header-reconstructed.** The Rust handler
  rebuilds the compared URL from `connection_info()` (scheme/host, honoring
  `Forwarded`/`X-Forwarded-*` per actix config) + `req.path()`. This port
  instead compares against `config.issuer.rstrip("/") + "/oauth/token"` —
  simpler and arguably more secure (immune to a spoofed/misconfigured Host
  header) but strictly less flexible: a deployment fronted by a proxy whose
  externally-visible scheme/host doesn't match `OAUTH2_ISSUER` exactly would
  reject every DPoP-bound token request that Rust would accept. Documented,
  deliberate hardening simplification.
- **Non-UTF-8 `DPoP` header detection.** Starlette's `request.headers.get`
  hands back a `str` that has already been latin-1-decoded from the raw ASGI
  bytes — latin-1 maps every byte 0-255 to a codepoint, so it can never
  observe a decode failure the way Rust's `HeaderValue::to_str()` (which
  requires valid UTF-8) does. To reproduce that check, `_read_dpop_header`
  (an alias for `services.dpop.read_dpop_header`, shared with
  `routes/introspect.py`) reads `request.headers.raw` directly and
  UTF-8-decodes the value itself instead of going through `.get`.
- **Client auth runs BEFORE DPoP proof validation** (Rust validates the
  proof first). Deliberate ordering divergence: an unauthenticated caller
  can neither burn replay-store jti entries nor farm nonces here, closing a
  DoS surface the Rust ordering exposes. Observable consequence: a request
  with both a bad client secret and a bad/replayed proof gets 401
  `invalid_client` (Rust: 400 `invalid_dpop_proof`) and its jti is NOT
  recorded.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.config import Config
from oauth2_server.errors import OAuthError, oauth_error
from oauth2_server.keys import KeySet
from oauth2_server.models import Client, IdTokenClaims, User
from oauth2_server.security import encode_id_token
from oauth2_server.services.auth import scope_is_subset
from oauth2_server.services.clients import ClientService
from oauth2_server.services.dpop import (
    DpopError,
    DpopValidated,
    read_dpop_header as _read_dpop_header,
    validate_dpop_proof,
)
from oauth2_server.services.dpop_nonce import enforce_dpop_nonce
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


def _salvage_old_cnf(access_token: str) -> dict | None:
    """Refresh-grant cnf carry-over (RFC 9449 parity gap, documented in
    research-dpop.md `key_behaviors`: the refresh grant "does not demand or
    verify a fresh DPoP proof on the refresh request"). Decodes the OLD
    access token WITHOUT verifying its signature and returns its `cnf` claim
    verbatim, so a DPoP-bound token stays bound across a refresh with no
    fresh proof required. Returns `None` for an opaque old access token (not
    a JWT — `jwt.decode` raises) or a JWT with no (or non-dict) `cnf` claim.
    """
    try:
        old_claims = jwt.decode(access_token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    cnf = old_claims.get("cnf")
    return cnf if isinstance(cnf, dict) else None


def _mint_id_token(
    config: Config,
    client: Client,
    user_id: str,
    user: User | None,
    scope: str,
    access_token: str,
    keyset: KeySet | None,
    *,
    nonce: str | None = None,
    code: str | None = None,
) -> str:
    """Build and encode an OIDC id_token (OIDC Core §2).

    Shared by the authorization_code and refresh_token grant branches. Callers
    must check `"openid" in scope` before calling; the id_token is minted
    unconditionally for openid scope, using `user_id` as `sub`. `user` is an
    optional best-effort lookup (`get_user_by_id`) — when the user row is
    missing (e.g. the user was deleted after the token was issued), `sub` is
    still set from `user_id` and email/preferred_username are simply omitted.
    `nonce`/`code` are only supplied on the initial code exchange — OIDC Core
    §12.2 forbids echoing `nonce` on a refreshed id_token, and there is no
    code to hash on refresh. `keyset` (from `app.state.keyset`) lets RS256
    id_tokens sign with the current rotated key instead of always the static
    env PEM — see `encode_id_token`. Raises `ValueError` (caught by both call
    sites, turned into a 500 `server_error`) when `config.id_token_alg ==
    "RS256"` but neither the keyset nor `config.id_token_private_key_pem`
    can supply a signing key.
    """
    scope_set = set(scope.split())
    now = int(datetime.now(timezone.utc).timestamp())
    id_claims = IdTokenClaims(
        iss=config.issuer,
        sub=user_id,
        aud=client.client_id,
        exp=now + config.access_token_ttl_secs,
        iat=now,
        nonce=nonce,
        at_hash=_half_hash(access_token),
    )
    if code is not None:
        id_claims.c_hash = _half_hash(code)
    if user is not None:
        if "email" in scope_set:
            id_claims.email = user.email
        if "profile" in scope_set:
            id_claims.preferred_username = user.username
    return encode_id_token(id_claims, config.jwt_secret, config=config, keyset=keyset)


@router.post("/token")
async def token(request: Request) -> ORJSONResponse:
    form = dict(await request.form())
    storage = request.app.state.storage
    config = request.app.state.config
    keyset = request.app.state.keyset

    try:
        client = await ClientService(storage).authenticate(
            form, request.headers.get("authorization")
        )
    except OAuthError as exc:
        return oauth_error(exc.error, exc.description, exc.status)

    # RFC 9449 DPoP: read + validate an optional proof once, before dispatching
    # on grant_type, mirroring the Rust handler's shared pre-grant block
    # (research-dpop.md `endpoints` POST /oauth/token entry). `cnf` below is
    # what authorization_code/client_credentials bind onto the new token;
    # refresh_token instead salvages the OLD token's cnf (`_salvage_old_cnf`)
    # and device_code never binds regardless of `cnf`'s value.
    try:
        dpop_header = _read_dpop_header(request)
    except DpopError as exc:
        return oauth_error(exc.error, exc.description)

    dpop_validated: DpopValidated | None = None
    if dpop_header is not None:
        try:
            dpop_validated = validate_dpop_proof(
                dpop_header,
                "POST",
                config.issuer.rstrip("/") + "/oauth/token",
                request.app.state.dpop_replay,
            )
        except DpopError as exc:
            return oauth_error(exc.error, exc.description)

        if client.dpop_nonce_required:
            try:
                nonce_response = enforce_dpop_nonce(
                    dpop_validated, request.app.state.dpop_nonce_issuer
                )
            except DpopError as exc:
                return oauth_error(exc.error, exc.description)
            if nonce_response is not None:
                return nonce_response

    cnf = {"jkt": dpop_validated.jkt} if dpop_validated is not None else None

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
            if not scope_is_subset(requested_scope, client.scope):
                return oauth_error("invalid_scope", "requested scope exceeds client scope")
            scope = requested_scope
        else:
            scope = client.scope

        token_response = await TokenService(storage, config, keyset).issue(
            client, None, scope, with_refresh=False, cnf=cnf
        )
        response = ORJSONResponse(token_response.model_dump(exclude_none=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    if grant_type == "authorization_code":
        if "authorization_code" not in client.grant_type_list():
            return oauth_error(
                "unauthorized_client", "client is not authorized for this grant type"
            )

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

        claimed = await storage.mark_authorization_code_used(auth_code.code)
        if claimed == 0:
            # Lost the race to a concurrent request that already claimed this code.
            if auth_code.token_family:
                await storage.revoke_token_family(auth_code.token_family)
            return oauth_error("invalid_grant", "authorization code has already been used")

        token_response = await TokenService(storage, config, keyset).issue(
            client,
            auth_code.user_id,
            auth_code.scope,
            with_refresh=True,
            token_family=auth_code.token_family,
            cnf=cnf,
        )

        scope_set = set(auth_code.scope.split())
        if "openid" in scope_set:
            user = await storage.get_user_by_id(auth_code.user_id)
            try:
                token_response.id_token = _mint_id_token(
                    config,
                    client,
                    auth_code.user_id,
                    user,
                    auth_code.scope,
                    token_response.access_token,
                    keyset,
                    nonce=auth_code.nonce,
                    code=auth_code.code,
                )
            except ValueError as exc:
                return oauth_error("server_error", str(exc), status=500)

        response = ORJSONResponse(token_response.model_dump(exclude_none=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    if grant_type == "refresh_token":
        if "refresh_token" not in client.grant_type_list():
            return oauth_error(
                "unauthorized_client", "client is not authorized for this grant type"
            )

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

        refresh_deadline = old_token.created_at + timedelta(seconds=config.refresh_token_ttl_secs)
        if datetime.now(timezone.utc) >= refresh_deadline:
            return oauth_error("invalid_grant", "refresh token has expired")

        requested_scope = form.get("scope")
        if requested_scope:
            if not scope_is_subset(requested_scope, old_token.scope):
                return oauth_error("invalid_scope", "requested scope exceeds the original grant")
            scope = requested_scope
        else:
            scope = old_token.scope

        family = old_token.token_family or uuid.uuid4().hex
        # Refresh carries the OLD access token's cnf forward regardless of
        # whether this request presented a fresh DPoP proof — `cnf` (from
        # this request's own header, if any) is deliberately unused here;
        # see `_salvage_old_cnf` and the module docstring.
        refresh_cnf = _salvage_old_cnf(old_token.access_token)
        await storage.revoke_token(old_token.access_token)

        token_response = await TokenService(storage, config, keyset).issue(
            client,
            old_token.user_id,
            scope,
            with_refresh=True,
            token_family=family,
            cnf=refresh_cnf,
        )

        scope_set = set(scope.split())
        if "openid" in scope_set and old_token.user_id:
            user = await storage.get_user_by_id(old_token.user_id)
            try:
                token_response.id_token = _mint_id_token(
                    config,
                    client,
                    old_token.user_id,
                    user,
                    scope,
                    token_response.access_token,
                    keyset,
                )
            except ValueError as exc:
                return oauth_error("server_error", str(exc), status=500)

        response = ORJSONResponse(token_response.model_dump(exclude_none=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        if grant_type not in client.grant_type_list():
            return oauth_error(
                "unauthorized_client", "client is not authorized for this grant type"
            )

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

        claimed = await storage.mark_device_authorization_used(device.device_code)
        if claimed == 0:
            # Lost the race to a concurrent request that already claimed this code.
            return oauth_error("invalid_grant", "device_code has already been redeemed")

        # Device grant never binds cnf, even when the client presented a
        # valid DPoP proof on this request (Rust parity, research-dpop.md
        # gotchas: "device_code grant hardcodes cnf: None") — `cnf` is
        # deliberately not passed through here.
        token_response = await TokenService(storage, config, keyset).issue(
            client,
            device.user_id,
            device.scope,
            with_refresh=True,
            token_family=uuid.uuid4().hex,
        )

        scope_set = set(device.scope.split())
        if "openid" in scope_set and device.user_id:
            user = await storage.get_user_by_id(device.user_id)
            try:
                token_response.id_token = _mint_id_token(
                    config,
                    client,
                    device.user_id,
                    user,
                    device.scope,
                    token_response.access_token,
                    keyset,
                )
            except ValueError as exc:
                return oauth_error("server_error", str(exc), status=500)

        response = ORJSONResponse(token_response.model_dump(exclude_none=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    return oauth_error("unsupported_grant_type", f"grant_type '{grant_type}' is not supported")
