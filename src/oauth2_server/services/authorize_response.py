"""Mode-aware authorization response delivery (OIDC `response_mode`).

Ported from `crates/oauth2-actix/src/handlers/oauth.rs` — `form_post_response`,
`html_escape_attr`, `build_authorize_error_redirect`, and the success-delivery
tail of `authorize`.

Once `redirect_uri` is known-registered, both the success response and every
error response are delivered back to the client through the redirect channel,
shaped by `response_mode`:

- `query` (the default): 302 with the params appended to `redirect_uri`'s
  query string, preserving any query string the registered URI already has.
- `fragment` (the default for hybrid flows, OIDC Core §3.3.2.3): 302 with the
  params percent-encoded into the URL fragment.
- `form_post` (OAuth 2.0 Form Post Response Mode): a 200 auto-submitting HTML
  form POSTing the params to `redirect_uri`.

`response_mode` itself cannot be validated through the redirect channel — a
valid mode is what tells us *how* to redirect — so an unsupported value is a
raw 400 (`resolve_response_mode` raises `OAuthError`).

Three deliberate divergences from Rust:
- Divergence 46: `response_mode=query` is REJECTED for the hybrid
  `response_type=code id_token` (Rust accepts it). OIDC Core §3.3.2.3: the
  query string is not a safe channel for an id_token — it lands in browser
  history, server access logs and the `Referer` of anything the redirect
  target loads. `fragment` (the hybrid default) and `form_post` remain
  allowed.
- Divergence 38: `html_escape_attr` also escapes `'` as `&#x27;`. Rust escapes
  only `& " < >`; single-quoted attributes aren't emitted here either, but
  escaping `'` costs nothing and removes the footgun entirely.
- Divergence 45: fragment params are encoded with `urlencode(...,
  quote_via=quote)` rather than `quote_plus`, so a space becomes `%20` and a
  literal `+` never appears in a fragment (where `+` is not decoded as a
  space, unlike in a query string).
"""

from __future__ import annotations

from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from starlette.responses import HTMLResponse, RedirectResponse, Response

from oauth2_server.errors import OAuthError

VALID_RESPONSE_MODES = ("query", "form_post", "fragment")

# Stamped on every authorize response this module builds, in every mode, for
# both success and error (OAuth 2.0 Security BCP: clickjacking + referrer
# leakage of the authorization response). The app-level `security_headers`
# middleware already applies most of these to `/oauth*`; they are set here too
# so the builder's output is self-contained (and carries the
# `Content-Security-Policy` the middleware set does not include).
_AUTH_RESPONSE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
}


def resolve_response_mode(requested: str | None, *, hybrid: bool) -> str:
    """Return the requested `response_mode`, or the flow's default.

    OIDC Core §3.3.2.3: hybrid flows default to `fragment`, everything else to
    `query`. Raises `OAuthError` (400 `invalid_request`) for an unsupported
    value, and — divergence 46 — for an explicit `query` on a hybrid request,
    which would put the id_token in the redirect URL's query string. Mode
    errors are the one post-`redirect_uri` error that cannot itself be
    delivered through the redirect channel, since a valid mode is what says
    *how* to redirect.
    """
    if requested is None:
        return "fragment" if hybrid else "query"
    if requested not in VALID_RESPONSE_MODES:
        raise OAuthError(
            "invalid_request",
            "Unsupported response_mode; supported values: query, form_post, fragment",
            400,
        )
    if hybrid and requested == "query":
        raise OAuthError(
            "invalid_request",
            "response_mode=query is not allowed for response_type=code id_token",
            400,
        )
    return requested


def success_response(
    mode: str,
    redirect_uri: str,
    *,
    code: str,
    state: str | None,
    iss: str,
    id_token: str | None = None,
) -> Response:
    """Deliver a successful authorization response in `mode`."""
    if mode == "query":
        # `query` is unreachable for a hybrid request (divergence 46), so
        # `id_token` is always None here; listed for symmetry only.
        params = _present([("code", code), ("state", state), ("iss", iss), ("id_token", id_token)])
    else:
        params = _present([("code", code), ("iss", iss), ("state", state), ("id_token", id_token)])
    return _deliver(mode, redirect_uri, params)


def error_response(
    mode: str,
    redirect_uri: str,
    *,
    error: str,
    error_description: str,
    state: str | None,
    iss: str,
) -> Response:
    """Deliver an authorization error response in `mode` (RFC 9207 §2 `iss`)."""
    head = [("error", error), ("error_description", error_description)]
    if mode == "query":
        params = _present([*head, ("state", state), ("iss", iss)])
    else:
        params = _present([*head, ("iss", iss), ("state", state)])
    return _deliver(mode, redirect_uri, params)


def _present(pairs: list[tuple[str, str | None]]) -> list[tuple[str, str]]:
    """Drop the params that weren't supplied, preserving the given order."""
    return [(key, value) for key, value in pairs if value is not None]


def _deliver(mode: str, redirect_uri: str, params: list[tuple[str, str]]) -> Response:
    if mode == "form_post":
        return HTMLResponse(
            _form_post_body(redirect_uri, params),
            status_code=200,
            headers=_AUTH_RESPONSE_HEADERS,
        )
    if mode == "fragment":
        location = f"{redirect_uri}#{urlencode(params, quote_via=quote)}"
    else:
        location = _query_location(redirect_uri, params)
    return RedirectResponse(location, status_code=302, headers=_AUTH_RESPONSE_HEADERS)


def _query_location(redirect_uri: str, params: list[tuple[str, str]]) -> str:
    """Append `params` to `redirect_uri`, preserving any existing query string."""
    split = urlsplit(redirect_uri)
    if split.fragment:
        raise OAuthError("invalid_request", "redirect_uri must not contain a fragment", 400)
    query = parse_qsl(split.query, keep_blank_values=True)
    query.extend(params)
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), ""))


def _html_escape_attr(value: str) -> str:
    """Escape `value` for use inside an HTML attribute. `&` must go first."""
    return (
        value.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("'", "&#x27;")
    )


def _form_post_body(redirect_uri: str, params: list[tuple[str, str]]) -> str:
    inputs = "\n".join(
        f'<input type="hidden" name="{_html_escape_attr(key)}" value="{_html_escape_attr(value)}"/>'
        for key, value in params
    )
    action = _html_escape_attr(redirect_uri)
    return (
        "<!DOCTYPE html>\n"
        '<html><body onload="document.forms[0].submit()">\n'
        f'<form method="post" action="{action}">\n'
        f"{inputs}\n"
        "</form></body></html>"
    )
