"""GET /oauth/authorize — RFC 6749 §4.1.1 authorization endpoint (PKCE + RFC 9207 iss).

Ported from `crates/oauth2-actix/src/handlers/oauth.rs::authorize`. Supports
`response_type=code` (authorization_code + PKCE, + RFC 9126 PAR and RFC 9101
JAR) and the OIDC hybrid `response_type=code id_token` — no implicit
(`token`/`id_token`).

Validation order matters (RFC 9207 §2 / OAuth 2.0 Security BCP):
0. Any repeated query key (e.g. `?response_type=code&response_type=code`) ->
   400 JSON `invalid_request` *before anything else*, including PAR
   resolution and `client_id` validation (Rust parity). A well-formed
   request never repeats a key.
1. If `request_uri` is present, resolve the pushed authorization request
   (RFC 9126) *before* anything else. Consumption is destructive
   (single-use): unknown/expired -> 400 JSON `invalid_request` (never a
   redirect — no `redirect_uri` can be trusted yet); the entry's `client_id`
   must match the query string's `client_id` -> else 401 JSON `invalid_client`.
   The entry is removed from the store either way, even when the mismatch
   check then fails (Rust parity). PAR-stored values take precedence over
   the query string for exactly: `redirect_uri`, `scope`, `code_challenge`,
   `code_challenge_method`, `nonce`, `resource`, `state`,
   `authorization_details`, `claims`, `acr_values`. `client_id` and
   `response_type` always come from the query string.
2. Unknown/disabled `client_id` -> 400 JSON, never redirect (redirecting would let
   an attacker exfiltrate data to an unregistered endpoint).
2b. RFC 9700 §4.7 `require_state`: a client that opted in must carry `state`
   on the RAW QUERY — checked before the JAR overlay (Rust parity), so a
   `state` that exists only inside the request object does not satisfy it.
2c. If `request` is present (read from the QUERY only — it is not a PAR merge
   key, so a JAR pushed inside a PAR body is ignored), the RFC 9101 request
   object is verified against the client's REGISTERED
   `token_endpoint_auth_method` (`services/jar.py`) and its claims overlaid
   on top of both the query string and any PAR-pushed values. Every JAR
   failure is a 400 JSON body: this runs before `redirect_uri` validation
   (the JAR may itself supply the `redirect_uri`), so no redirect target is
   trusted yet. The EFFECTIVE `response_type` is validated here too, and the
   outer check in step 4 is skipped.
3. `redirect_uri` not an exact match against the client's registered list -> 400
   JSON, never redirect, for the same reason.
3b. `response_mode` (the JAR's if it supplied one, else the QUERY's — never
   the PAR-merged params) is resolved next: `query`, `fragment` or
   `form_post`, defaulting to
   `fragment` for the hybrid flow and `query` otherwise (OIDC Core
   §3.3.2.3). An unsupported value — or, divergence 46, an explicit `query`
   on a hybrid request, which would leak the id_token into the redirect
   URL's query string — is a 400 JSON `invalid_request`: a valid mode is what
   tells us *how* to redirect, so these errors can't use the redirect
   channel (Rust parity). From here on, `_deliver_error` shapes
   every error according to the resolved mode (divergence 37: Rust honors
   `form_post` only for the `login_required` case and `fragment` only inside
   its own error-redirect builder).
4. Everything else is delivered via redirect to `redirect_uri` (`error=...`), since
   the redirect target is now trusted — including divergence 39: the hybrid
   flow REQUIRES `nonce`, and a missing one is an `invalid_request` redirect.
5. Unauthenticated (or `prompt=login`/expired `max_age`) -> save `return_to` in the
   session and 302 to `/auth/login`.
5b. RFC 9470 step-up: an `acr_values` request (query, PAR or JAR) is
   satisfied only when the session's login-stamped `acr` is one of the
   requested values; otherwise `insufficient_user_authentication` through
   the redirect channel. It runs AFTER the login gate so it is never an
   oracle for an unauthenticated caller.
6. Success -> the authorization response (`code`, `state` if given, and `iss`
   — RFC 9207, to prevent authorization-response mix-up attacks) delivered in
   the resolved `response_mode` (see `services/authorize_response.py`), plus
   an `id_token` for the hybrid flow when the granted scope has `openid`
   (minted by `services/id_token.py`, bound to the code via `c_hash`).
"""

from __future__ import annotations

import html
import json
import logging
import re
import secrets
import uuid
from urllib.parse import parse_qsl, urlencode
from oauth2_server import clock

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, ORJSONResponse, RedirectResponse
from starlette.responses import Response

from oauth2_server.errors import OAuthError
from oauth2_server.models import Grant
from oauth2_server.services.consent import PendingConsent, scope_label
from oauth2_server.services.clients import redirect_uri_matches
from oauth2_server.middleware import check_subject_denylisted
from oauth2_server.services.auth import AuthorizeService, scope_is_subset
from oauth2_server.services.authorize_response import (
    error_response,
    resolve_response_mode,
    success_response,
)
from oauth2_server.services.events_bus import emit_event
from oauth2_server.services.id_token import mint_id_token
from oauth2_server.services.jar import process_jar
from oauth2_server.services.limits import LimitError, check_json_param
from oauth2_server.services.rar import RarError, validate_authorization_details
from oauth2_server.services.resource import validate_resource
from oauth2_server.sessions import current_acr, current_amr, current_user_id

logger = logging.getLogger(__name__)

router = APIRouter()

# The only `response_type` values this port supports: plain code, and the
# OIDC hybrid flow that adds a front-channel id_token. `token`/`id_token`
# (implicit) are deliberately unsupported.
_HYBRID_RESPONSE_TYPE = "code id_token"
_SUPPORTED_RESPONSE_TYPES = ("code", _HYBRID_RESPONSE_TYPE)

_MIN_CODE_CHALLENGE_LEN = 43
_MAX_CODE_CHALLENGE_LEN = 128

# RFC 9126 PAR merge whitelist: exactly these keys are overridden by the
# pushed request's stored params, when present. `client_id` and
# `response_type` are deliberately excluded — they always come from the
# query string (Rust parity).
_PAR_MERGE_KEYS = (
    "redirect_uri",
    "scope",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "resource",
    "state",
    "authorization_details",
    "claims",
    "acr_values",
    "dpop_jkt",
)

# A base64url-no-pad SHA-256 thumbprint: 32 bytes -> exactly 43 characters of
# the RFC 4648 §5 alphabet. Padding (`=`), the standard-base64 `+`/`/` and any
# other length are all rejected (divergence 52).
_DPOP_JKT_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def _strip_reauth_params(query: str) -> str:
    """Drop `max_age` and the `login` prompt value from a query string before
    saving it as the post-login `return_to` replay URL — otherwise replaying
    it after re-authentication would immediately force another re-login."""
    kept = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key == "max_age":
            continue
        if key == "prompt":
            remaining = " ".join(p for p in value.split() if p != "login")
            if remaining:
                kept.append((key, remaining))
            continue
        kept.append((key, value))
    return urlencode(kept)


def _error_page(status: int, error: str, description: str) -> ORJSONResponse:
    return ORJSONResponse({"error": error, "error_description": description}, status_code=status)


def _oauth_error_page(exc: OAuthError) -> ORJSONResponse:
    return _error_page(exc.status, exc.error, exc.description or "")


def _deliver_error(
    response_mode: str,
    redirect_uri: str,
    error: str,
    description: str | None,
    state: str | None,
    issuer: str,
) -> Response:
    """Deliver a post-`redirect_uri` error through the redirect channel.

    A registered `redirect_uri` that query mode can't build on (it carries a
    fragment) leaves no safe channel at all, so it falls back to the same JSON
    400 the pre-redirect checks use rather than silently dropping the error.
    """
    try:
        return error_response(
            response_mode,
            redirect_uri,
            error=error,
            error_description=description,
            state=state,
            iss=issuer,
        )
    except OAuthError as exc:
        return _oauth_error_page(exc)


@router.get("/authorize")
async def authorize(request: Request):
    params = request.query_params
    config = request.app.state.config
    storage = request.app.state.storage

    # --- 0. Reject a repeated query key outright (Rust parity) — before any
    # other processing, including PAR resolution and client_id validation. A
    # well-formed request never repeats a key, so this can only reject
    # malformed/ambiguous input (e.g. parameter-pollution attempts). ---
    seen_keys: set[str] = set()
    for key, _ in params.multi_items():
        if key in seen_keys:
            return _error_page(400, "invalid_request", "duplicate query parameter")
        seen_keys.add(key)

    client_id = params.get("client_id")

    # --- 1. Resolve a pushed authorization request, if referenced (RFC 9126) ---
    merged: dict[str, str] = dict(params)
    request_uri = params.get("request_uri")
    if request_uri is not None:
        entry = request.app.state.par_store.take(request_uri)
        if entry is None:
            return _error_page(400, "invalid_request", "Unknown or expired request_uri")
        if entry.client_id != client_id:
            return _error_page(401, "invalid_client", "request_uri client_id mismatch")
        for key in _PAR_MERGE_KEYS:
            if key in entry.params:
                merged[key] = entry.params[key]

    # --- 2. client_id must exist and be enabled ---
    client = await storage.get_client(client_id) if client_id else None
    denylist_reason = (
        await check_subject_denylisted(storage, "client_id", client_id) if client_id else None
    )
    if client_id is None:
        # RFC 6749 §4.1.1: a MISSING client_id is a malformed request (400),
        # informing the resource owner with no redirect.
        return _error_page(400, "invalid_request", "client_id is required")
    if client is None or not client.enabled or denylist_reason is not None:
        # Subject-kind denylist (Phase 3a): a denylisted client_id gets the
        # identical unknown/disabled-client error — no oracle distinguishing
        # "denylisted" from "never registered". The request is unredirectable
        # (no trusted redirect_uri exists for an unknown client), so this is a
        # 401 (the Rust reference's status for invalid_client here), never a
        # redirect to the untrusted request's redirect_uri.
        if denylist_reason is not None:
            logger.warning(
                "authorize blocked: client_id is denylisted (reason=%s)", denylist_reason
            )
        return _error_page(401, "invalid_client", "unknown or disabled client_id")

    # --- 2b. RFC 9700 §4.7: per-client `require_state` ---
    # Evaluated against the RAW QUERY, before the JAR overlay (Rust parity):
    # a client that opts into this must carry `state` on the outer request
    # too, not only inside a request object.
    if client.require_state and params.get("state") is None:
        return _error_page(
            400, "invalid_request", "state parameter is required for this client (RFC 9700 §4.7)"
        )

    # --- 2c. RFC 9101 §4: verify and overlay a JAR `request` object ---
    # Read from the QUERY only — `request` is not a PAR merge key, so a JAR
    # smuggled into a PAR body is never processed. Placed here because the
    # client (and hence the verification key) must already be resolved, and
    # because every JAR failure is a 400 JSON body: it precedes the
    # `redirect_uri` registration check, so no redirect target is trusted yet
    # — and the JAR may itself *supply* the `redirect_uri` being checked.
    request_jwt = params.get("request")
    jar_response_mode: str | None = None
    if request_jwt is not None:
        try:
            jar_claims = await process_jar(
                client,
                request_jwt,
                authorize_url=f"{config.issuer.rstrip('/')}/oauth/authorize",
                jwks_cache=request.app.state.jwks_cache,
            )
        except OAuthError as exc:
            return _oauth_error_page(exc)
        # JAR claims win over BOTH the query string and PAR-pushed values.
        merged.update(jar_claims)
        jar_response_mode = jar_claims.get("response_mode")
        # The EFFECTIVE `response_type` (the JAR's, else the query's) is what
        # gets validated — the outer check below is skipped whenever a JAR is
        # present. Like every other JAR error this is a 400 JSON body.
        if merged.get("response_type") not in _SUPPORTED_RESPONSE_TYPES:
            return _error_page(
                400,
                "invalid_request",
                "Unsupported response_type in JAR; supported values: code, code id_token",
            )

    redirect_uri = merged.get("redirect_uri")
    state = merged.get("state")

    # --- 3. redirect_uri must match the registered list — 400, never redirect ---
    if not redirect_uri or not any(
        redirect_uri_matches(registered, redirect_uri) for registered in client.redirect_uri_list()
    ):
        return _error_page(400, "invalid_request", "redirect_uri is not registered for this client")

    # --- 3b. Resolve response_mode — the last error that can't be redirected ---
    # Read from the raw query only, never the PAR-merged params (Rust parity:
    # `response_mode` is not in the PAR merge whitelist). `response_type` is
    # read from the query too (never PAR-merged) and decides the default:
    # OIDC Core §3.3.2.3 defaults the hybrid `code id_token` flow to
    # `fragment`, everything else to `query`. The response_type is only
    # *validated* below, through the redirect channel — an unsupported value
    # still resolves its mode here so that error can be delivered.
    # With a JAR present every value below is the EFFECTIVE (post-overlay)
    # one, and the JAR's `response_mode` outranks the query's.
    response_type = (
        merged.get("response_type") if request_jwt is not None else params.get("response_type")
    )
    hybrid = response_type == _HYBRID_RESPONSE_TYPE
    try:
        response_mode = resolve_response_mode(
            jar_response_mode or params.get("response_mode"), hybrid=hybrid
        )
    except OAuthError as exc:
        return _oauth_error_page(exc)

    # --- 4. From here on, errors are delivered via redirect ---
    if "authorization_code" not in client.grant_type_list():
        return _deliver_error(
            response_mode,
            redirect_uri,
            "unauthorized_client",
            "client is not authorized for this grant type",
            state,
            config.issuer,
        )

    if request_jwt is None and response_type not in _SUPPORTED_RESPONSE_TYPES:
        return _deliver_error(
            response_mode,
            redirect_uri,
            "unsupported_response_type",
            "only the 'code' and 'code id_token' response_types are supported",
            state,
            config.issuer,
        )

    # Divergence 39: the hybrid flow REQUIRES `nonce`. OIDC Core §3.3.2.11
    # makes it mandatory for any flow that delivers an id_token through the
    # front channel (it is the client's only replay defense there), but Rust
    # mints the hybrid id_token with whatever `nonce` it was given, including
    # none. Missing `nonce` is delivered through the (now trusted) redirect
    # channel like every other post-`redirect_uri` error.
    nonce = merged.get("nonce")
    if hybrid and not nonce:
        return _deliver_error(
            response_mode,
            redirect_uri,
            "invalid_request",
            "nonce is required for response_type=code id_token",
            state,
            config.issuer,
        )

    scope = merged.get("scope") or "read"
    if not scope_is_subset(scope, client.scope):
        return _deliver_error(
            response_mode,
            redirect_uri,
            "invalid_scope",
            "requested scope exceeds the client's allowed scope",
            state,
            config.issuer,
        )

    code_challenge = merged.get("code_challenge")
    code_challenge_method = merged.get("code_challenge_method")

    if not code_challenge:
        return _deliver_error(
            response_mode,
            redirect_uri,
            "invalid_request",
            "a PKCE code_challenge is required (RFC 9700 §2.1.1)",
            state,
            config.issuer,
        )

    if code_challenge is not None:
        if code_challenge_method != "S256":
            return _deliver_error(
                response_mode,
                redirect_uri,
                "invalid_request",
                "only the S256 code_challenge_method is supported",
                state,
                config.issuer,
            )
        if not (_MIN_CODE_CHALLENGE_LEN <= len(code_challenge) <= _MAX_CODE_CHALLENGE_LEN):
            return _deliver_error(
                response_mode,
                redirect_uri,
                "invalid_request",
                "code_challenge must be between 43 and 128 characters",
                state,
                config.issuer,
            )

    # RFC 9396 §5: validate `authorization_details` (query param, or the PAR-
    # merged value) now that redirect_uri is trusted — violations are safe
    # error redirects (`error=invalid_authorization_details`), never a raw
    # 400. The raw string (not the parsed value) is what gets stored on the
    # authorization code below; it's re-parsed at redemption time.
    authorization_details = merged.get("authorization_details")
    if authorization_details is not None:
        try:
            validate_authorization_details(authorization_details, config.rar_types_supported)
        except RarError as exc:
            return _deliver_error(
                response_mode, redirect_uri, exc.error, exc.description, state, config.issuer
            )

    # RFC 8707 §2: validate the resource indicator (query param, or the PAR-
    # merged value). Like `invalid_scope` above, a bad value is delivered
    # through the now-trusted redirect channel (`error=invalid_target`),
    # never a raw 400. The validated value is stored on the authorization
    # code below and becomes the access token's `aud` at redemption.
    try:
        resource = validate_resource(merged.get("resource"))
    except OAuthError as exc:
        return _deliver_error(
            response_mode, redirect_uri, exc.error, exc.description, state, config.issuer
        )

    # OIDC Core §5.5 / divergence 44: `claims` (query param, or the PAR-merged
    # or JAR-overlaid value) must parse as a JSON *object* — an array,
    # string, number or malformed JSON is an `invalid_request` redirect. The
    # raw string (not the parsed dict) is what gets stored on the
    # authorization code below, where `services/claims_request.py` reads it
    # back when the id_token is minted (divergence 59, id_token member only);
    # `claims_parameter_supported` is deliberately not advertised.
    claims_request = merged.get("claims")
    if claims_request is not None:
        try:
            parsed_claims = check_json_param(
                claims_request, name="claims", max_len=8192, max_depth=10
            )
        except LimitError as exc:
            # Divergence 57: over-long / over-nested input is rejected through
            # the same redirect channel, with the limits helper's wording.
            return _deliver_error(
                response_mode,
                redirect_uri,
                "invalid_request",
                exc.description,
                state,
                config.issuer,
            )
        except json.JSONDecodeError:
            parsed_claims = None
        if not isinstance(parsed_claims, dict):
            return _deliver_error(
                response_mode,
                redirect_uri,
                "invalid_request",
                "claims must be a JSON object",
                state,
                config.issuer,
            )

    # RFC 9449 §10 / divergence 52: `dpop_jkt` (query param, PAR-merged or
    # JAR-overlaid) pre-binds the authorization code to a DPoP key, closing
    # the window between the code landing at the client and the proof being
    # presented at the token endpoint. The value is a JWK SHA-256 thumbprint:
    # base64url (RFC 4648 §5, no padding) of 32 bytes, hence exactly 43
    # characters. Like `resource`/`claims` above, a bad value is delivered
    # through the now-trusted redirect channel, never a raw 400. The binding
    # itself is recorded against the issued code below.
    dpop_jkt = merged.get("dpop_jkt")
    if dpop_jkt is not None and not _DPOP_JKT_RE.fullmatch(dpop_jkt):
        return _deliver_error(
            response_mode,
            redirect_uri,
            "invalid_request",
            "dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint",
            state,
            config.issuer,
        )

    # --- 5. Require an authenticated session ---
    # OIDC Core §3.1.2.1: `prompt` is a space-delimited list of values.
    prompt_values = (params.get("prompt") or "").split()
    force_login = "login" in prompt_values or "select_account" in prompt_values

    # prompt=none is mutually exclusive with every other prompt value (OIDC
    # Core §3.1.2.1): "none" MUST NOT be used with any other value.
    if "none" in prompt_values and len(prompt_values) > 1:
        return _deliver_error(
            response_mode,
            redirect_uri,
            "invalid_request",
            "prompt=none cannot be combined with other values",
            state,
            config.issuer,
        )

    user_id = current_user_id(request)

    # max_age: if the session's auth_time is older than max_age seconds (or
    # missing entirely), the user must re-authenticate.
    auth_expired = False
    max_age = params.get("max_age")
    if max_age is not None:
        try:
            max_age_secs = int(max_age)
        except ValueError:
            max_age_secs = None
        if max_age_secs is not None:
            auth_time = request.session.get("auth_time")
            auth_expired = auth_time is None or (clock.time() - auth_time) >= max_age_secs

    # prompt=none: the AS must not display any UI. If the caller isn't
    # authenticated, re-authentication would be forced, or the existing
    # session's max_age has expired, that's an error delivered via the
    # redirect channel (OIDC Core §3.1.2.6) — never the interactive login UI.
    if "none" in prompt_values and (user_id is None or force_login or auth_expired):
        return _deliver_error(
            response_mode,
            redirect_uri,
            "login_required",
            "User is not authenticated and prompt=none was requested",
            state,
            config.issuer,
        )

    if user_id is None or force_login or auth_expired:
        original = request.url.path
        if request.url.query:
            original += "?" + _strip_reauth_params(request.url.query)
        request.session["return_to"] = original
        # Timestamp the pending redirect so POST /auth/login can reject a stale
        # return_to left over from an abandoned (possibly attacker-initiated)
        # authorization request instead of silently replaying it.
        request.session["return_to_ts"] = int(clock.time())
        return RedirectResponse("/auth/login", status_code=302)

    # --- 5b. RFC 9470 step-up: `acr_values` must be satisfied by the session ---
    # Deliberately after the login gate above: an unauthenticated caller is
    # sent to `/auth/login` first, so this error never doubles as a "who is
    # logged in, and how strongly" oracle for an unauthenticated request. The
    # value comes from `merged`, so a query param, a PAR-pushed value and a
    # JAR claim are all enforced identically.
    #
    # Rust parity: satisfied iff the session's stamped `acr` is EXACTLY one of
    # the space-separated requested values — no ordering/"at least as strong
    # as" semantics, and an unknown or unparseable value is simply unsatisfied
    # (an error through the redirect channel, never a 500). A session with no
    # `acr` at all fails closed for the same reason.
    acr_values = merged.get("acr_values")
    if acr_values is not None and current_acr(request) not in acr_values.split():
        return _deliver_error(
            response_mode,
            redirect_uri,
            "insufficient_user_authentication",
            "Authentication Context Class does not satisfy acr_values",
            state,
            config.issuer,
        )

    # --- 5c. User consent (RFC 6749 §3.1, OIDC Core §3.1.2.4) ---
    # A code is only issued for scopes the user has approved for this client:
    # a stored grant covering the request, or an operator/seed policy that
    # makes consent implicit for the client. `prompt=consent` re-asks even when
    # a grant exists; `prompt=none` may never show UI, so it fails instead.
    requested_scopes = set(scope.split())
    grant = await storage.get_grant(user_id, client.client_id)
    granted_scopes = set(grant.scope.split()) if grant is not None else set()
    if not await _consent_is_implicit(request, client.client_id, user_id) and (
        "consent" in prompt_values or not requested_scopes <= granted_scopes
    ):
        if "none" in prompt_values:
            return _deliver_error(
                response_mode,
                redirect_uri,
                "consent_required",
                "User consent is required and prompt=none was requested",
                state,
                config.issuer,
            )
        pending = PendingConsent(
            user_id=user_id,
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            response_mode=response_mode,
            hybrid=hybrid,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            authorization_details=authorization_details,
            resource=resource,
            claims_request=claims_request,
            dpop_jkt=dpop_jkt,
            acr_values=acr_values,
        )
        handle = request.app.state.consent_store.put(pending)
        # Only scopes not already approved need a decision; with a covering
        # grant (prompt=consent) the whole request is shown again.
        shown = requested_scopes - granted_scopes or requested_scopes
        return _consent_page(client.name, sorted(shown), handle, pending.csrf_token)

    # --- 6. Success: mint the authorization code and redirect back to the client ---
    return await _issue_authorization_response(
        request,
        client=client,
        user_id=user_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        response_mode=response_mode,
        hybrid=hybrid,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        authorization_details=authorization_details,
        resource=resource,
        claims_request=claims_request,
        dpop_jkt=dpop_jkt,
    )


async def _consent_is_implicit(request: Request, client_id: str, user_id: str) -> bool:
    """Consent is implied for operator-trusted clients, and — in conformance
    mode only — for the seeded user's `auto_approve_clients`. Neither skips any
    other check: this runs after redirect/PKCE/scope validation."""
    if client_id in request.app.state.config.consent_trusted_client_ids:
        return True
    auto_approve = request.app.state.consent_auto_approve
    if not auto_approve:
        return False
    user = await request.app.state.storage.get_user_by_id(user_id)
    return user is not None and client_id in auto_approve.get(user.username, ())


def _consent_page(client_name: str, scopes: list[str], handle: str, csrf_token: str) -> Response:
    items = "\n".join(
        f"    <li><strong>{html.escape(scope_label(s))}</strong> (<code>{html.escape(s)}</code>)</li>"
        for s in scopes
    )
    body = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Authorize application</title></head>
<body>
<h1>Authorize application</h1>
<p><strong>{html.escape(client_name)}</strong> is requesting access to your account with these permissions:</p>
<ul>
{items}
</ul>
<form method="post" action="/oauth/consent">
  <input type="hidden" name="handle" value="{html.escape(handle, quote=True)}">
  <input type="hidden" name="csrf_token" value="{html.escape(csrf_token, quote=True)}">
  <button type="submit" name="action" value="approve">Allow</button>
  <button type="submit" name="action" value="deny">Deny</button>
</form>
</body>
</html>
"""
    return HTMLResponse(body)


@router.post("/consent")
async def consent(request: Request):
    """Resume the authorization request parked by `GET /authorize`.

    The form carries only an opaque handle, a CSRF token and the decision: the
    request being approved is the one stored server-side, and every parameter
    is re-validated against current client/user state before a code is issued.
    """
    config = request.app.state.config
    storage = request.app.state.storage
    store = request.app.state.consent_store

    user_id = current_user_id(request)
    if user_id is None:
        return _error_page(401, "login_required", "login required")

    form = dict(await request.form())
    handle = form.get("handle")
    action = form.get("action")
    entry = store.peek(handle) if isinstance(handle, str) else None
    csrf = form.get("csrf_token")
    if (
        entry is None
        or entry.user_id != user_id
        or not isinstance(csrf, str)
        or not secrets.compare_digest(csrf, entry.csrf_token)
    ):
        return _error_page(400, "invalid_request", "unknown or expired consent request")
    if action not in ("approve", "deny"):
        return _error_page(400, "invalid_request", "action must be approve or deny")
    store.take(handle)

    # The browser may not change what is being approved.
    for key, expected in (
        ("client_id", entry.client_id),
        ("redirect_uri", entry.redirect_uri),
        ("scope", entry.scope),
        ("state", entry.state or ""),
        ("code_challenge", entry.code_challenge),
    ):
        if key in form and form[key] != expected:
            return _error_page(400, "invalid_request", f"{key} does not match the pending request")

    # Re-validate against current state: the client, its redirect URI and
    # scope allow-list, and the user may all have changed since the page was
    # rendered.
    client = await storage.get_client(entry.client_id)
    denylisted = await check_subject_denylisted(storage, "client_id", entry.client_id)
    if client is None or not client.enabled or denylisted is not None:
        return _error_page(401, "invalid_client", "unknown or disabled client_id")
    if not any(
        redirect_uri_matches(registered, entry.redirect_uri)
        for registered in client.redirect_uri_list()
    ):
        return _error_page(400, "invalid_request", "redirect_uri is not registered for this client")
    user = await storage.get_user_by_id(user_id)
    if user is None or not user.enabled:
        return _deliver_error(
            entry.response_mode,
            entry.redirect_uri,
            "access_denied",
            "user is not permitted to authorize",
            entry.state,
            config.issuer,
        )
    if not scope_is_subset(entry.scope, client.scope):
        return _deliver_error(
            entry.response_mode,
            entry.redirect_uri,
            "invalid_scope",
            "requested scope exceeds the client's allowed scope",
            entry.state,
            config.issuer,
        )
    if entry.acr_values is not None and current_acr(request) not in entry.acr_values.split():
        return _deliver_error(
            entry.response_mode,
            entry.redirect_uri,
            "insufficient_user_authentication",
            "Authentication Context Class does not satisfy acr_values",
            entry.state,
            config.issuer,
        )

    if action == "deny":
        return _deliver_error(
            entry.response_mode,
            entry.redirect_uri,
            "access_denied",
            "the user denied the request",
            entry.state,
            config.issuer,
        )

    # Approve: record the union of what was previously approved and this request.
    now = clock.now()
    existing = await storage.get_grant(user_id, client.client_id)
    merged_scope = set(entry.scope.split())
    if existing is not None:
        merged_scope |= set(existing.scope.split())
    await storage.save_grant(
        Grant(
            id=existing.id if existing is not None else uuid.uuid4().hex,
            user_id=user_id,
            client_id=client.client_id,
            scope=" ".join(sorted(merged_scope)),
            created_at=existing.created_at if existing is not None else now,
            updated_at=now,
        )
    )
    return await _issue_authorization_response(
        request,
        client=client,
        user_id=user_id,
        redirect_uri=entry.redirect_uri,
        scope=entry.scope,
        state=entry.state,
        response_mode=entry.response_mode,
        hybrid=entry.hybrid,
        nonce=entry.nonce,
        code_challenge=entry.code_challenge,
        code_challenge_method=entry.code_challenge_method,
        authorization_details=entry.authorization_details,
        resource=entry.resource,
        claims_request=entry.claims_request,
        dpop_jkt=entry.dpop_jkt,
    )


async def _issue_authorization_response(
    request: Request,
    *,
    client,
    user_id: str,
    redirect_uri: str,
    scope: str,
    state: str | None,
    response_mode: str,
    hybrid: bool,
    nonce: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
    authorization_details: str | None,
    resource: str | None,
    claims_request: str | None,
    dpop_jkt: str | None,
) -> Response:
    """Mint the authorization code and build the authorization response (shared
    by `GET /authorize` and `POST /consent`)."""
    config = request.app.state.config
    storage = request.app.state.storage
    auth_code = await AuthorizeService(storage, config).issue_code(
        client,
        user_id,
        redirect_uri,
        scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        authorization_details=authorization_details,
        resource=resource,
        claims_request=claims_request,
        dpop_jkt=dpop_jkt,
    )
    request.app.state.metrics.oauth_authorization_codes_issued.inc()
    emit_event(
        request.app.state.event_bus,
        "authorization_code_created",
        user_id=user_id,
        client_id=client.client_id,
        metadata={"scope": scope, "redirect_uri": redirect_uri},
    )

    # Hybrid: mint the front-channel id_token alongside the code. Gated on
    # the EFFECTIVE scope (the code's, i.e. what was actually granted) rather
    # than the request's, and bound to the code via `c_hash` — no access
    # token is delivered here, so there is no `at_hash` (Rust parity). The
    # minter and TTL are the token endpoint's (divergence 40), and `acr`/`amr`
    # /`auth_time` are the session's — what this authentication event actually
    # attested to, stamped at login.
    id_token: str | None = None
    if hybrid and "openid" in auth_code.scope.split():
        user = await storage.get_user_by_id(user_id)
        try:
            id_token = mint_id_token(
                config=config,
                keyset=request.app.state.keyset,
                client=client,
                user_id=user_id,
                user=user,
                scope=auth_code.scope,
                nonce=nonce,
                code=auth_code.code,
                acr=current_acr(request),
                amr=current_amr(request),
                auth_time=request.session.get("auth_time"),
            )
        except ValueError as exc:
            # RS256 configured with no usable signing key — a server-side
            # misconfiguration, not the client's fault, and not something to
            # hand to the redirect channel.
            logger.error("hybrid id_token minting failed: %s", exc)
            return _error_page(500, "server_error", str(exc))

    try:
        return success_response(
            response_mode,
            redirect_uri,
            code=auth_code.code,
            state=state,
            iss=config.issuer,
            id_token=id_token,
        )
    except OAuthError as exc:
        return _oauth_error_page(exc)
