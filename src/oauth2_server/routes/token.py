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
import binascii
import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus

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
from oauth2_server.services.events_bus import emit_event
from oauth2_server.services.rar import RarError, validate_authorization_details
from oauth2_server.services.tokens import TokenService

logger = logging.getLogger(__name__)

router = APIRouter()

_MIN_VERIFIER_LEN = 43
_MAX_VERIFIER_LEN = 128

# RFC 8693 §2.1 grant identifier and the single subject/requested token type
# this server supports exchanging (access tokens only — no id_token/SAML/JWT
# subject types, matching the Rust server's storage-lookup-only model; see
# `.superpowers/sdd/research-rar-token-exchange.md` token-exchange section).
_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
_ACCESS_TOKEN_TYPE_URN = "urn:ietf:params:oauth:token-type:access_token"


def _extract_client_id_for_penalty(form: dict, authorization_header: str | None) -> str | None:
    """Best-effort recovery of the client_id an `invalid_client` outcome
    should be penalized against (RFC 9700 §2.5), mirroring `ClientService.
    authenticate`'s own precedence (`services/clients.py`: Basic header wins
    over the form) WITHOUT re-raising on a malformed header — this only
    needs a bucket key, not a validated credential, so a decode failure
    just means "no key, skip the penalty" rather than another error path.
    """
    if authorization_header and authorization_header.lower().startswith("basic "):
        encoded = authorization_header[len("Basic ") :].strip()
        try:
            decoded = base64.b64decode(encoded).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            decoded = None
        if decoded and ":" in decoded:
            raw_client_id, _, _ = decoded.partition(":")
            return unquote_plus(raw_client_id) or None
    client_id = form.get("client_id")
    return client_id or None


def _invalid_client_response(
    request: Request, client_id: str | None, description: str
) -> ORJSONResponse:
    """Build the `401 invalid_client` response for `client_id`, first
    consuming a token from the invalid_client penalty bucket (RFC 9700
    §2.5, `app.state.invalid_client_limiter` — built in `create_app` only
    when `config.rate_limit_invalid_client_max_requests > 0`, ON by default;
    Rust parity). When the bucket is exhausted, the 401 is replaced by a 429
    whose body is EXACTLY `{"error":"too_many_requests","error_description":
    "Too many failed authentication attempts. Retry after {N}s.",
    "error_uri":null}` — note `error_uri` is present-and-null (unlike
    `oauth_error()`'s normal shape, which omits absent fields entirely) and
    there is deliberately NO `Retry-After` HEADER on this response (the
    retry-seconds value only appears inside `error_description`'s text —
    Rust parity, research doc gotchas). Successes and non-invalid_client
    errors never call this function, so they never consume the bucket.
    Fails OPEN: a limiter backend error, or no recoverable `client_id`
    (e.g. `authenticate()` never got far enough to see one), just returns
    the plain 401.
    """
    limiter = request.app.state.invalid_client_limiter
    if limiter is not None and client_id:
        try:
            result = limiter.check(client_id)
        except Exception:
            logger.warning("invalid_client rate limiter backend error; failing open", exc_info=True)
            result = None
        if result is not None and not result.allowed:
            body = {
                "error": "too_many_requests",
                "error_description": (
                    f"Too many failed authentication attempts. Retry after {result.retry_after}s."
                ),
                "error_uri": None,
            }
            return ORJSONResponse(body, status_code=429, headers={"Cache-Control": "no-store"})
    return oauth_error("invalid_client", description)


def _half_hash(value: str) -> str:
    """OIDC Core §3.3.2.11 / §3.1.3.6: base64url-no-pad(left-half(SHA-256(value)))."""
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _pkce_matches(computed_challenge: str, stored_challenge: str) -> bool:
    """Constant-time compare, safe for a non-ASCII stored code_challenge.

    ``secrets.compare_digest`` raises ``TypeError`` when either ``str``
    operand contains a non-ASCII character instead of returning ``False``.
    `/oauth/authorize` (and PAR) only length-check ``code_challenge`` —
    RFC 7636's base64url charset is never enforced — so a client can store
    a non-ASCII ``code_challenge`` on the authorization code and turn the
    verifier check below into an unhandled 500 instead of the documented
    ``invalid_grant``. Compare on the UTF-8 byte representation instead,
    which has no such restriction; ``computed_challenge`` is always
    base64url/ASCII, so this only changes behavior for the malicious case.
    """
    return secrets.compare_digest(
        computed_challenge.encode("utf-8"), stored_challenge.encode("utf-8")
    )


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
    event_bus = request.app.state.event_bus

    try:
        client = await ClientService(storage, event_bus).authenticate(
            form, request.headers.get("authorization")
        )
    except OAuthError as exc:
        # Rust parity site (oauth.rs bad-client-auth): every client-auth
        # failure at the token endpoint counts as a failed authentication.
        request.app.state.metrics.oauth_failed_authentications.inc()
        if exc.error == "invalid_client":
            # RFC 9700 §2.5 penalty bucket: client_id must be recovered
            # independently here since `authenticate()` raised before ever
            # returning a `Client` — see `_extract_client_id_for_penalty`.
            client_id = _extract_client_id_for_penalty(form, request.headers.get("authorization"))
            return _invalid_client_response(request, client_id, exc.description)
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
            return _invalid_client_response(
                request,
                client.client_id,
                "Public clients cannot use the client_credentials grant",
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

        # RFC 9396: client_credentials has no consent step, so the form
        # value (if any) is validated directly and embedded verbatim — no
        # stored counterpart to reconcile against (unlike authorization_code
        # redemption below).
        authorization_details = None
        raw_details = form.get("authorization_details")
        if raw_details is not None:
            try:
                authorization_details = validate_authorization_details(
                    raw_details, config.rar_types_supported
                )
            except RarError as exc:
                return oauth_error(exc.error, exc.description)

        token_response = await TokenService(storage, config, keyset).issue(
            client,
            None,
            scope,
            with_refresh=False,
            cnf=cnf,
            authorization_details=authorization_details,
        )
        request.app.state.metrics.oauth_token_issued_total.inc()
        emit_event(
            event_bus,
            "token_created",
            client_id=client.client_id,
            metadata={"scope": scope, "has_refresh_token": "false"},
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
            emit_event(
                event_bus,
                "authorization_code_expired",
                severity="warning",
                user_id=auth_code.user_id,
                client_id=auth_code.client_id,
            )
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
            if not _pkce_matches(_pkce_challenge(verifier), auth_code.code_challenge):
                return oauth_error("invalid_grant", "code_verifier does not match code_challenge")
        elif client.is_public():
            return oauth_error("invalid_grant", "public clients must use PKCE")

        # RFC 9396: the details the user consented to at authorize time
        # (stored on the auth code) win. A token-request value is only
        # accepted when there was no stored value (validate + use); when
        # BOTH are present and differ (string comparison — no semantic
        # diffing), this is a validation error, NOT a replay — the code
        # must stay usable and the token family must NOT be revoked, unlike
        # the "already used" branch above/below.
        stored_details = auth_code.authorization_details
        form_details = form.get("authorization_details")
        if (
            stored_details is not None
            and form_details is not None
            and form_details != stored_details
        ):
            return oauth_error(
                "invalid_authorization_details",
                "authorization_details must not be altered at redemption",
            )
        raw_details = stored_details if stored_details is not None else form_details
        authorization_details = None
        if raw_details is not None:
            try:
                authorization_details = validate_authorization_details(
                    raw_details, config.rar_types_supported
                )
            except RarError as exc:
                return oauth_error(exc.error, exc.description)

        claimed = await storage.mark_authorization_code_used(auth_code.code)
        if claimed == 0:
            # Lost the race to a concurrent request that already claimed this code.
            if auth_code.token_family:
                await storage.revoke_token_family(auth_code.token_family)
            return oauth_error("invalid_grant", "authorization code has already been used")

        emit_event(
            event_bus,
            "authorization_code_validated",
            user_id=auth_code.user_id,
            client_id=auth_code.client_id,
        )

        token_response = await TokenService(storage, config, keyset).issue(
            client,
            auth_code.user_id,
            auth_code.scope,
            with_refresh=True,
            token_family=auth_code.token_family,
            cnf=cnf,
            authorization_details=authorization_details,
        )
        request.app.state.metrics.oauth_token_issued_total.inc()
        emit_event(
            event_bus,
            "token_created",
            user_id=auth_code.user_id,
            client_id=client.client_id,
            metadata={"scope": auth_code.scope, "has_refresh_token": "true"},
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
            # Rust parity site (oauth.rs bad-refresh): an unrecognized
            # refresh_token counts as a failed authentication.
            request.app.state.metrics.oauth_failed_authentications.inc()
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

        # RFC 9396 details are DROPPED on refresh (Rust parity,
        # research-rar-token-exchange.md `endpoints`: "authorization_details:
        # None on the rotated token") — unlike `cnf` above, there is no
        # carry-over from the old access token's JWT claim; `authorization_details`
        # is deliberately left unset here.
        token_response = await TokenService(storage, config, keyset).issue(
            client,
            old_token.user_id,
            scope,
            with_refresh=True,
            token_family=family,
            cnf=refresh_cnf,
        )
        request.app.state.metrics.oauth_token_issued_total.inc()
        emit_event(
            event_bus,
            "token_created",
            user_id=old_token.user_id,
            client_id=client.client_id,
            metadata={"scope": scope, "has_refresh_token": "true"},
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
        # deliberately not passed through here. RFC 9396 details are
        # likewise dropped for this grant (Rust parity,
        # research-rar-token-exchange.md `endpoints`: "Same for
        # device_code grant") — DeviceAuthorization has no
        # authorization_details field at all, so there's nothing to embed.
        token_response = await TokenService(storage, config, keyset).issue(
            client,
            device.user_id,
            device.scope,
            with_refresh=True,
            token_family=uuid.uuid4().hex,
        )
        request.app.state.metrics.oauth_token_issued_total.inc()
        emit_event(
            event_bus,
            "token_created",
            user_id=device.user_id,
            client_id=client.client_id,
            metadata={"scope": device.scope, "has_refresh_token": "true"},
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

    if grant_type == _TOKEN_EXCHANGE_GRANT:
        # RFC 8693 token exchange. Check order per
        # `.superpowers/sdd/task-6-brief.md`: grant allow-list -> public-
        # client rejection -> subject_token presence -> subject_token_type
        # validation -> requested_token_type validation -> storage lookup ->
        # validity -> scope subset -> issue. Confidential clients only, and
        # the client must register the full URN (exact match, same
        # `grant_type_list()` check as every other branch above) — there is
        # no short alias, unlike device_code.
        if grant_type not in client.grant_type_list():
            return oauth_error(
                "unauthorized_client", "client is not authorized for this grant type"
            )

        if client.is_public():
            return _invalid_client_response(
                request, client.client_id, "Public clients cannot use token-exchange"
            )

        subject_token = form.get("subject_token")
        if not subject_token:
            return oauth_error("invalid_request", "Missing subject_token")

        # RFC 8693 §2.1 / divergence 18 (research doc): Rust parses
        # subject_token_type/actor_token_type and then ignores them
        # (`#[allow(dead_code)]`) — an id_token or SAML assertion type
        # silently behaves like an access token. This port actually
        # enforces the single type it supports (storage only ever holds
        # access tokens), rejecting anything else including a missing value.
        if form.get("subject_token_type") != _ACCESS_TOKEN_TYPE_URN:
            return oauth_error(
                "invalid_request",
                f"unsupported subject_token_type: only '{_ACCESS_TOKEN_TYPE_URN}' is supported",
            )

        requested_token_type = form.get("requested_token_type")
        if requested_token_type is not None and requested_token_type != _ACCESS_TOKEN_TYPE_URN:
            return oauth_error(
                "invalid_request",
                f"unsupported requested_token_type: only '{_ACCESS_TOKEN_TYPE_URN}' is supported",
            )

        # subject_token is resolved by STORAGE LOOKUP, not JWT signature
        # verification — only a token this server issued and still holds
        # can be exchanged (Rust parity, research doc `key_behaviors`).
        subject_row = await storage.get_token_by_access_token(subject_token)
        if subject_row is None:
            return oauth_error("invalid_grant", "subject_token not found or expired")

        if subject_row.revoked or subject_row.expires_at <= datetime.now(timezone.utc):
            return oauth_error("invalid_grant", "subject_token is expired or revoked")

        requested_scope = form.get("scope")
        if requested_scope:
            if not scope_is_subset(requested_scope, subject_row.scope):
                return oauth_error("invalid_scope", "requested scope exceeds client permissions")
            scope = requested_scope
        else:
            scope = subject_row.scope

        # RFC 8693 §4.1 delegation: `act` is ALWAYS embedded in the issued
        # JWT for an exchanged token — this is impersonation happening
        # regardless of whether the caller declared an `actor_token` — a
        # fixed gap vs Rust, which never puts `act` in the JWT at all (see
        # models.Claims.act's docstring). The response-body `act` member
        # below stays Rust-conditional: present only when `actor_token` was
        # supplied on this request (`actor_token`'s VALUE is never
        # validated, matching Rust — its mere presence triggers the
        # response member).
        act = {"sub": client.client_id}
        actor_token_present = form.get("actor_token") is not None

        # Impersonation model (Rust parity): issued token carries the
        # SUBJECT token's user_id but the EXCHANGING client's client_id.
        # Never a refresh token (`with_refresh=False`, no `token_family`).
        # `cnf` binds THIS request's own DPoP proof (the shared pre-grant
        # block above), not the subject token's binding.
        token_response = await TokenService(storage, config, keyset).issue(
            client,
            subject_row.user_id,
            scope,
            with_refresh=False,
            cnf=cnf,
            act=act,
        )
        request.app.state.metrics.oauth_token_issued_total.inc()
        emit_event(
            event_bus,
            "token_created",
            user_id=subject_row.user_id,
            client_id=client.client_id,
            metadata={"scope": scope, "has_refresh_token": "false"},
        )

        body: dict[str, object] = {
            "access_token": token_response.access_token,
            "issued_token_type": _ACCESS_TOKEN_TYPE_URN,
            "token_type": token_response.token_type,
            "expires_in": token_response.expires_in,
            "scope": token_response.scope,
        }
        if actor_token_present:
            body["act"] = act

        response = ORJSONResponse(body)
        response.headers["Cache-Control"] = "no-store"
        return response

    return oauth_error("unsupported_grant_type", f"grant_type '{grant_type}' is not supported")
