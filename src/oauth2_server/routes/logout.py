"""GET /oauth/logout — full OIDC RP-Initiated Logout, and GET /oauth/check_session
— OIDC Session Management 1.0 check_session_iframe.

Ported from `crates/oauth2-actix/src/handlers/oidc_logout.rs::logout` and
`crates/oauth2-actix/src/handlers/session.rs::check_session_iframe`.

Divergence from Rust (intentional, documented in the Phase 2 brief): an
`id_token_hint` that fails to decode/verify (bad signature, wrong `iss`,
expired, unsupported `alg`) returns **400** here. The Rust server silently
ignores a cryptographically invalid hint and lets logout proceed. Being
stricter here can't break a compliant RP (a valid hint always decodes) and
surfaces a caller bug immediately instead of pretending the hint didn't exist.
"""

from __future__ import annotations

import html
import json
import time
import uuid
from urllib.parse import quote, urlparse

import httpx
import jwt
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, ORJSONResponse, RedirectResponse

from oauth2_server.models import Client

router = APIRouter()

# OIDC Back-Channel Logout 1.0 §2.2: logout_token lifetime and event claim.
_BACKCHANNEL_LOGOUT_TTL_SECS = 120
_BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class _InvalidHint(Exception):
    """Raised internally when `id_token_hint` fails to decode/verify."""


def _error(description: str, status: int = 400) -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_request", "error_description": description},
        status_code=status,
    )


def _decode_hint(id_token_hint: str, config) -> dict:
    """Decode and verify `id_token_hint`, alg pinned from the JOSE header.

    HS256 is the only supported alg today (verified against `jwt_secret`).
    Raises `_InvalidHint` on any decode/verification failure, including an
    unsupported alg — never returns a claims dict for an untrusted token.
    """
    try:
        header = jwt.get_unverified_header(id_token_hint)
    except jwt.PyJWTError as exc:
        raise _InvalidHint from exc

    alg = header.get("alg")
    if alg != "HS256":
        # TODO(task-13): RS256 hint verification via config PEM public key
        raise _InvalidHint

    try:
        return jwt.decode(
            id_token_hint,
            config.jwt_secret,
            algorithms=["HS256"],
            issuer=config.issuer,
            options={"verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise _InvalidHint from exc


def _extract_audiences(claims: dict) -> list[str]:
    """Normalize the `aud` claim (string, list, missing, or mixed-type list)
    into a list of string audiences, dropping any non-string entries."""
    aud = claims.get("aud")
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list):
        return [a for a in aud if isinstance(a, str)]
    return []


def _append_state(uri: str, state: str | None) -> str:
    if state is None:
        return uri
    separator = "&" if "?" in uri else "?"
    return f"{uri}{separator}state={quote(state, safe='')}"


def _validate_post_logout_redirect_uri(uri: str, clients: list[Client]) -> str | None:
    """Returns an error description on failure, or `None` if `uri` is a
    well-formed http(s) URI, fragment-free, and registered by some client
    (either its `post_logout_redirect_uris` allowlist or, as a backwards-
    compat fallback, its plain `redirect_uris`)."""
    parsed = urlparse(uri)

    if not parsed.scheme or not parsed.netloc:
        return "Invalid post_logout_redirect_uri"
    if parsed.scheme not in ("http", "https"):
        return "post_logout_redirect_uri must use http or https"
    if parsed.fragment:
        return "post_logout_redirect_uri must not contain a fragment"

    for client in clients:
        if uri in client.get_post_logout_redirect_uris() or uri in client.redirect_uri_list():
            return None
    return "Unregistered post_logout_redirect_uri"


async def _dispatch_backchannel_logout(
    http_client: httpx.AsyncClient,
    client: Client,
    config,
    sub: str | None,
    sid: str | None,
) -> None:
    now = int(time.time())
    claims: dict = {
        "iss": config.issuer,
        "aud": client.client_id,
        "iat": now,
        "exp": now + _BACKCHANNEL_LOGOUT_TTL_SECS,
        "jti": uuid.uuid4().hex,
        "events": {_BACKCHANNEL_EVENT: {}},
    }
    if sub is not None:
        claims["sub"] = sub
    if sid is not None:
        claims["sid"] = sid

    # Back-channel logout_token is always HS256(jwt_secret), independent of
    # the id_token signing alg (Rust parity — see research gotchas).
    logout_token = jwt.encode(
        claims, config.jwt_secret, algorithm="HS256", headers={"typ": "logout+JWT"}
    )
    try:
        await http_client.post(
            client.backchannel_logout_uri,
            content=f"logout_token={logout_token}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except Exception:
        # Fire-and-forget: a slow/broken/unreachable RP must never fail (or
        # even delay reporting) the caller's logout.
        pass


def _redirect_script(url: str) -> str:
    """Build the `<script>` tag that JS-redirects to `url` after a short delay.

    `url` is embedded via `json.dumps` (so it's a syntactically valid JS
    string literal, quotes and all escaped) and then has every `<` and `/`
    replaced by their escape sequences. That second pass is what actually
    matters for safety: it guarantees the literal substring `</script>` can
    never appear inside the embedded data, no matter what `url` contains, so
    the data can't break out of our `<script>` element (XSS via
    `</script><script>...`).
    """
    encoded = json.dumps(url).replace("<", "\\u003c").replace("/", "\\/")
    return f"<script>setTimeout(function(){{ window.location.href = {encoded}; }}, 2000);</script>"


def _render_frontchannel_page(
    clients: list[Client], issuer: str, sid: str | None, redirect_url: str | None
) -> str:
    iframes = []
    for client in clients:
        src = f"{client.frontchannel_logout_uri}?iss={quote(issuer, safe='')}"
        if client.frontchannel_logout_session_required and sid:
            src += f"&sid={quote(sid, safe='')}"
        iframes.append(
            f'<iframe src="{html.escape(src, quote=True)}" style="display:none" '
            'sandbox="allow-scripts allow-same-origin"></iframe>'
        )

    script = _redirect_script(redirect_url) if redirect_url else ""

    return (
        "<!doctype html><html><body><p>Logging out...</p>"
        + "".join(iframes)
        + script
        + "</body></html>"
    )


@router.get("/logout")
async def logout(request: Request):
    config = request.app.state.config
    storage = request.app.state.storage
    params = request.query_params

    id_token_hint = params.get("id_token_hint")
    post_logout_redirect_uri = params.get("post_logout_redirect_uri")
    state = params.get("state")
    # No id_token ever carries a `sid` claim yet (Task 13 backlog) and no
    # session cookie stores one either, so `sid` is effectively caller-
    # supplied query input — Rust parity (see research gotchas).
    sid = params.get("sid") or request.session.get("session_id")

    sub: str | None = None

    # --- 1. id_token_hint: decode, aud check, best-effort user-token revoke ---
    if id_token_hint:
        try:
            claims = _decode_hint(id_token_hint, config)
        except _InvalidHint:
            return _error("invalid id_token_hint")

        audiences = _extract_audiences(claims)
        if audiences:
            matched = False
            for aud in audiences:
                if await storage.get_client(aud) is not None:
                    matched = True
                    break
            if not matched:
                return _error("id_token_hint aud does not match a registered client")

        hint_sub = claims.get("sub")
        if isinstance(hint_sub, str) and hint_sub:
            sub = hint_sub
            await storage.revoke_tokens_by_user_id(sub)

    # --- 2. Always purge the session, hint or not ---
    request.session.clear()

    clients = await storage.list_all_clients()

    # --- 3. Back-channel logout: fire-and-forget POST to every subscriber ---
    http_client = request.app.state.http_client
    for client in clients:
        if not client.backchannel_logout_uri:
            continue
        token_sid = sid if client.backchannel_logout_session_required and sid else None
        if sub is None and token_sid is None:
            # OIDC Back-Channel Logout 1.0 §2.5: a logout_token must identify
            # a session via sub and/or sid — skip clients we can't identify.
            continue
        await _dispatch_backchannel_logout(http_client, client, config, sub, token_sid)

    # --- post_logout_redirect_uri validation, shared by both branches below ---
    redirect_url: str | None = None
    if post_logout_redirect_uri:
        error = _validate_post_logout_redirect_uri(post_logout_redirect_uri, clients)
        if error:
            return _error(error)
        redirect_url = _append_state(post_logout_redirect_uri, state)

    # --- 4. Front-channel logout: triggers whenever ANY client subscribes ---
    frontchannel_clients = [c for c in clients if c.frontchannel_logout_uri]
    if frontchannel_clients:
        page = _render_frontchannel_page(frontchannel_clients, config.issuer, sid, redirect_url)
        return HTMLResponse(page)

    # --- 5/6. Standard branch: redirect if requested, else a JSON confirmation ---
    if redirect_url:
        return RedirectResponse(redirect_url, status_code=302)

    return ORJSONResponse({"status": "logged_out"})


_CHECK_SESSION_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>check_session_iframe</title></head>
<body>
<script>
// OIDC Session Management 1.0 check_session_iframe.
//
// Listens for `postMessage("<client_id> <session_state>")` from an RP's own
// hidden iframe and replies "unchanged" / "changed" / "error" per spec:
// session_state is "<hash>.<salt>" where hash = SHA-256(client_id + " " +
// origin + " " + browser_state + " " + salt), browser_state coming from the
// op_browser_state cookie set at authentication time.
function getSalt(sessionState) {
    var idx = sessionState.lastIndexOf(".");
    return idx === -1 ? "" : sessionState.slice(idx + 1);
}

function getCookie(name) {
    var match = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return match ? decodeURIComponent(match[1]) : "";
}

function sha256Hex(input) {
    var bytes = new TextEncoder().encode(input);
    return crypto.subtle.digest("SHA-256", bytes).then(function (digest) {
        var view = new Uint8Array(digest);
        var hex = "";
        for (var i = 0; i < view.length; i++) {
            hex += view[i].toString(16).padStart(2, "0");
        }
        return hex;
    });
}

window.addEventListener("message", function (event) {
    try {
        var parts = String(event.data).split(" ");
        if (parts.length !== 2) {
            event.source.postMessage("error", event.origin);
            return;
        }
        var clientId = parts[0];
        var sessionState = parts[1];
        var expectedHash = sessionState.split(".")[0];
        var salt = getSalt(sessionState);
        var browserState = getCookie("op_browser_state");
        var input = clientId + " " + event.origin + " " + browserState + " " + salt;
        sha256Hex(input).then(function (hash) {
            event.source.postMessage(hash === expectedHash ? "unchanged" : "changed", event.origin);
        });
    } catch (err) {
        event.source.postMessage("error", event.origin);
    }
});
</script>
</body>
</html>
"""


@router.get("/check_session")
async def check_session_iframe() -> HTMLResponse:
    return HTMLResponse(_CHECK_SESSION_HTML)
