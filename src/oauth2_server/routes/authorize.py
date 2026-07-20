"""GET /oauth/authorize — RFC 6749 §4.1.1 authorization endpoint (PKCE + RFC 9207 iss).

Ported from `crates/oauth2-actix/src/handlers/oauth.rs::authorize`. This is a
Phase-1 subset: authorization_code + PKCE only (no PAR/JAR/hybrid/prompt handling).

Validation order matters (RFC 9207 §2 / OAuth 2.0 Security BCP):
1. Unknown/disabled `client_id` -> 400 JSON, never redirect (redirecting would let
   an attacker exfiltrate data to an unregistered endpoint).
2. `redirect_uri` not an exact match against the client's registered list -> 400
   JSON, never redirect, for the same reason.
3. Everything else is delivered via redirect to `redirect_uri` (`error=...`), since
   the redirect target is now trusted.
4. Unauthenticated (or `prompt=login`/expired `max_age`) -> save `return_to` in the
   session and 302 to `/auth/login`.
5. Success -> 302 to `redirect_uri` with `code`, `state` (if given), and `iss`
   (RFC 9207, to prevent authorization-response mix-up attacks).
"""

from __future__ import annotations

import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse, RedirectResponse

from oauth2_server.services.auth import AuthorizeService, scope_is_subset
from oauth2_server.sessions import current_user_id

router = APIRouter()

_MIN_CODE_CHALLENGE_LEN = 43
_MAX_CODE_CHALLENGE_LEN = 128


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


def _build_redirect_url(redirect_uri: str, params: dict[str, str]) -> str:
    """Append `params` to `redirect_uri`, preserving any existing query string."""
    split = urlsplit(redirect_uri)
    query = parse_qsl(split.query, keep_blank_values=True)
    query.extend(params.items())
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))


def _error_page(status: int, error: str, description: str) -> ORJSONResponse:
    return ORJSONResponse({"error": error, "error_description": description}, status_code=status)


def _error_redirect(
    redirect_uri: str, error: str, description: str, state: str | None, issuer: str
) -> RedirectResponse:
    params = {"error": error, "error_description": description, "iss": issuer}
    if state is not None:
        params["state"] = state
    return RedirectResponse(_build_redirect_url(redirect_uri, params), status_code=302)


@router.get("/authorize")
async def authorize(request: Request):
    params = request.query_params
    config = request.app.state.config
    storage = request.app.state.storage

    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    state = params.get("state")

    # --- 1. client_id must exist and be enabled — 400, never redirect ---
    client = await storage.get_client(client_id) if client_id else None
    if client is None or not client.enabled:
        return _error_page(400, "invalid_client", "unknown or disabled client_id")

    # --- 2. redirect_uri must exact-match the registered list — 400, never redirect ---
    if not redirect_uri or redirect_uri not in client.redirect_uri_list():
        return _error_page(400, "invalid_request", "redirect_uri is not registered for this client")

    # --- 3. From here on, errors are delivered via redirect ---
    response_type = params.get("response_type")
    if response_type != "code":
        return _error_redirect(
            redirect_uri,
            "unsupported_response_type",
            "only the 'code' response_type is supported",
            state,
            config.issuer,
        )

    scope = params.get("scope") or "read"
    if not scope_is_subset(scope, client.scope):
        return _error_redirect(
            redirect_uri,
            "invalid_scope",
            "requested scope exceeds the client's allowed scope",
            state,
            config.issuer,
        )

    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method")

    if client.is_public() and not code_challenge:
        return _error_redirect(
            redirect_uri,
            "invalid_request",
            "public clients must send a PKCE code_challenge",
            state,
            config.issuer,
        )

    if code_challenge is not None:
        if code_challenge_method != "S256":
            return _error_redirect(
                redirect_uri,
                "invalid_request",
                "only the S256 code_challenge_method is supported",
                state,
                config.issuer,
            )
        if not (_MIN_CODE_CHALLENGE_LEN <= len(code_challenge) <= _MAX_CODE_CHALLENGE_LEN):
            return _error_redirect(
                redirect_uri,
                "invalid_request",
                "code_challenge must be between 43 and 128 characters",
                state,
                config.issuer,
            )

    # --- 4. Require an authenticated session ---
    # OIDC Core §3.1.2.1: `prompt` is a space-delimited list of values.
    prompt_values = (params.get("prompt") or "").split()
    force_login = "login" in prompt_values or "select_account" in prompt_values

    user_id = current_user_id(request)

    # prompt=none: the AS must not display any UI. Without a session, this is
    # an error delivered via the redirect channel (OIDC Core §3.1.2.6).
    if "none" in prompt_values and user_id is None:
        return _error_redirect(
            redirect_uri,
            "login_required",
            "User is not authenticated and prompt=none was requested",
            state,
            config.issuer,
        )

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
            auth_expired = auth_time is None or (time.time() - auth_time) >= max_age_secs

    if user_id is None or force_login or auth_expired:
        original = request.url.path
        if request.url.query:
            original += "?" + _strip_reauth_params(request.url.query)
        request.session["return_to"] = original
        # Timestamp the pending redirect so POST /auth/login can reject a stale
        # return_to left over from an abandoned (possibly attacker-initiated)
        # authorization request instead of silently replaying it.
        request.session["return_to_ts"] = int(time.time())
        return RedirectResponse("/auth/login", status_code=302)

    # --- 5. Success: mint the authorization code and redirect back to the client ---
    auth_code = await AuthorizeService(storage, config).issue_code(
        client,
        user_id,
        redirect_uri,
        scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=params.get("nonce"),
    )

    success_params = {"code": auth_code.code, "iss": config.issuer}
    if state is not None:
        success_params["state"] = state
    return RedirectResponse(_build_redirect_url(redirect_uri, success_params), status_code=302)
