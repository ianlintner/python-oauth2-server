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

import asyncio
import html
import json
import logging
import uuid
from urllib.parse import quote, urlparse

import httpx
import jwt
from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, ORJSONResponse, RedirectResponse

from oauth2_server.keys import KeySet, rsa_public_key
from oauth2_server.models import Client
from oauth2_server import clock
from oauth2_server.services.outbound import OutboundTargetError, post_to_public_https_target
from oauth2_server.sessions import current_user_id

logger = logging.getLogger(__name__)
router = APIRouter()

# OIDC Back-Channel Logout 1.0 §2.2: logout_token lifetime and event claim.
_BACKCHANNEL_LOGOUT_TTL_SECS = 120
_BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"

# Caps how many back-channel logout POSTs are in flight at once, so a logout
# fanning out to many subscribing RPs doesn't open unbounded concurrent
# connections.
_BACKCHANNEL_CONCURRENCY = 5


class _InvalidHint(Exception):
    """Raised internally when `id_token_hint` fails to decode/verify."""


def _error(description: str, status: int = 400) -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_request", "error_description": description},
        status_code=status,
    )


def _rs256_hint_verify_materials(config, keyset: KeySet | None, kid: str | None) -> list[bytes]:
    """Ordered list of RS256 private-key PEM materials to try verifying an
    RS256-alg `id_token_hint` against: the `kid`-matched keyset key when one
    resolves, else every active RS256 keyset key (covers a missing/unknown
    `kid`, and a `kid` that's still active but rotated-out during grace),
    else — only when the keyset holds no RS256 key at all — the static
    `config.id_token_private_key_pem` as a last resort (mirrors the JWKS
    fallback in `routes/wellknown.py`)."""
    materials: list[bytes] = []
    if keyset is not None:
        found = keyset.find(kid) if kid else None
        if found is not None and found.algorithm == "RS256":
            materials.append(found.key_material)
        else:
            materials.extend(key.key_material for key in keyset.active_keys_for_alg("RS256"))
    # Invariant: this branch is only reachable when the keyset holds zero
    # active RS256 keys. Once RS256 is in use, `seed_keyset` always adds one
    # and `KeySet.rotate` always adds a fresh `is_current=True` key before
    # any pruning happens -- so a live keyset never has zero active RS256
    # keys. Do not widen this fallback (e.g. to "kid not found"): an expired,
    # pruned key's hint would otherwise verify against the static PEM and be
    # silently resurrected. See test_logout_rejects_hint_signed_by_pruned_key_after_grace.
    if not materials and config.id_token_private_key_pem:
        materials.append(config.id_token_private_key_pem.encode())
    return materials


def _decode_hint(id_token_hint: str, config, keyset: KeySet | None) -> dict:
    """Decode and verify `id_token_hint`, alg pinned from the JOSE header.

    HS256 is verified against `jwt_secret`. RS256 resolves the hint's `kid`
    against the keyset (falling back to every active RS256 keyset key, then
    the static PEM — see `_rs256_hint_verify_materials`) so a hint signed by
    a since-rotated-out key still verifies during its grace period, closing
    the same rotation gap `encode_id_token` fixes for issuance. RS256 with
    no keyset key and no PEM configured is rejected rather than silently
    falling back (kept strict, per the module docstring's documented
    divergence from the Rust server). Raises `_InvalidHint` on any
    decode/verification failure, including an unsupported alg — never
    returns a claims dict for an untrusted token.
    """
    try:
        header = jwt.get_unverified_header(id_token_hint)
    except jwt.PyJWTError as exc:
        raise _InvalidHint from exc

    alg = header.get("alg")
    if alg == "HS256":
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

    if alg != "RS256":
        raise _InvalidHint

    last_error: Exception | None = None
    for material in _rs256_hint_verify_materials(config, keyset, header.get("kid")):
        try:
            # Never feed the private PEM straight into PyJWT's RSA verify
            # path (see research-keys-rs256.md gotchas) — extract the public
            # key explicitly.
            public_key = rsa_public_key(material)
        except ValueError as exc:
            last_error = exc
            continue
        try:
            return jwt.decode(
                id_token_hint,
                public_key,
                algorithms=["RS256"],
                issuer=config.issuer,
                options={"verify_aud": False},
            )
        except jwt.PyJWTError as exc:
            last_error = exc

    raise _InvalidHint from last_error


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
    well-formed http(s) URI, fragment-free, and listed in the
    `post_logout_redirect_uris` of one of `clients` -- the client(s)
    identified by a verified `id_token_hint`. A client's plain
    `redirect_uris` do not qualify, and with no identified client nothing
    matches."""
    parsed = urlparse(uri)

    if not parsed.scheme or not parsed.netloc:
        return "Invalid post_logout_redirect_uri"
    if parsed.scheme not in ("http", "https"):
        return "post_logout_redirect_uri must use http or https"
    if parsed.fragment:
        return "post_logout_redirect_uri must not contain a fragment"

    for client in clients:
        if uri in client.get_post_logout_redirect_uris():
            return None
    return "Unregistered post_logout_redirect_uri"


async def _dispatch_backchannel_logout(
    http_client: httpx.AsyncClient,
    client: Client,
    config,
    keyset: KeySet | None,
    sub: str | None,
    sid: str | None,
) -> None:
    now = int(clock.time())
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

    # The logout_token is signed with the current RS256 keyset key (kid in
    # the header), so the RP verifies it against the published JWKS — the same
    # way it verifies an id_token. `jwt_secret` is never used: it would have to
    # be shared with every RP to be verifiable. Without an RS256 key there is
    # nothing verifiable to send, so the dispatch is skipped.
    signing_key = keyset.current_for_alg("RS256") if keyset is not None else None
    if signing_key is None:
        logger.warning(
            "skipping back-channel logout for client %s: no RS256 signing key",
            client.client_id,
        )
        return
    logout_token = jwt.encode(
        claims,
        signing_key.key_material,
        algorithm="RS256",
        headers={"typ": "logout+JWT", "kid": signing_key.kid},
    )
    try:
        await post_to_public_https_target(
            http_client,
            client.backchannel_logout_uri,
            content=f"logout_token={logout_token}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except OutboundTargetError:
        logger.warning(
            "skipping back-channel logout for client %s: unacceptable target",
            client.client_id,
        )
    except Exception:  # noqa: S110, BLE001 - fire-and-forget by design, see comment below
        # Fire-and-forget: a slow/broken/unreachable RP must never fail (or
        # even delay reporting) the caller's logout.
        pass


async def _dispatch_backchannel_logout_bounded(
    semaphore: asyncio.Semaphore,
    http_client: httpx.AsyncClient,
    client: Client,
    config,
    keyset: KeySet | None,
    sub: str | None,
    sid: str | None,
) -> None:
    async with semaphore:
        await _dispatch_backchannel_logout(http_client, client, config, keyset, sub, sid)


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
async def logout(request: Request, background_tasks: BackgroundTasks):
    config = request.app.state.config
    storage = request.app.state.storage
    keyset = request.app.state.keyset
    params = request.query_params

    id_token_hint = params.get("id_token_hint")
    post_logout_redirect_uri = params.get("post_logout_redirect_uri")
    state = params.get("state")
    # The user bound to this browser's login session (None without one).
    # Only this session-derived identity is used to address back-channel
    # logout, and a hint only triggers revocation when it names this same
    # user; query parameters are never trusted for either. No `sid` is
    # issued yet, so a session id exists only if a session stored one.
    session_user = current_user_id(request)
    sid = request.session.get("session_id")

    hint_sub: str | None = None
    hint_clients: list[Client] = []

    # --- 1. id_token_hint: decode, aud check, identify the requesting client ---
    if id_token_hint:
        try:
            claims = _decode_hint(id_token_hint, config, keyset)
        except _InvalidHint:
            return _error("invalid id_token_hint")

        audiences = _extract_audiences(claims)
        if audiences:
            for aud in audiences:
                hint_client = await storage.get_client(aud)
                if hint_client is not None:
                    hint_clients.append(hint_client)
            if not hint_clients:
                return _error("id_token_hint aud does not match a registered client")

        claim_sub = claims.get("sub")
        if isinstance(claim_sub, str) and claim_sub:
            hint_sub = claim_sub

    # --- post_logout_redirect_uri: must be a post-logout URI of the client
    # identified by the hint (no hint -> nothing to match against) ---
    redirect_url: str | None = None
    if post_logout_redirect_uri:
        error = _validate_post_logout_redirect_uri(post_logout_redirect_uri, hint_clients)
        if error:
            return _error(error)
        redirect_url = _append_state(post_logout_redirect_uri, state)

    # --- 2. Revoke only for a hint that matches the caller's own session ---
    if session_user is not None and hint_sub == session_user:
        await storage.revoke_tokens_by_user_id(session_user)

    # --- 3. Always purge the browser session, hint or not ---
    request.session.clear()

    clients = await storage.list_all_clients()

    # --- 4. Back-channel logout: only for a session that really existed.
    # Dispatch runs after the response is sent (bounded concurrency), so
    # slow RPs never hold up the caller. ---
    if session_user is not None:
        http_client = request.app.state.http_client
        semaphore = asyncio.Semaphore(_BACKCHANNEL_CONCURRENCY)
        for client in clients:
            if not client.backchannel_logout_uri:
                continue
            token_sid = sid if client.backchannel_logout_session_required and sid else None
            background_tasks.add_task(
                _dispatch_backchannel_logout_bounded,
                semaphore,
                http_client,
                client,
                config,
                keyset,
                session_user,
                token_sid,
            )

    # --- 5. Front-channel logout: triggers whenever ANY client subscribes ---
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
