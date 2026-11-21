"""Same-origin proof for cookie-authenticated state-changing requests.

Browsers attach an ``Origin`` header to cross-origin POSTs (including form
submissions); a same-origin request either carries our own origin or no
``Origin`` at all (non-browser clients, older browsers).  This helper rejects
any *present* origin that does not match the configured issuer's origin, so a
cross-origin form POST cannot drive an authenticated session.

The issuer is normalised to scheme://host[:port] before comparison: a trailing
slash, an explicit default port, or a differently-cased host must not cause a
legitimate same-origin request to be rejected.  ``Origin: null`` is never
accepted.

``Sec-Fetch-Site`` is treated as an additional signal: a browser that sends
``cross-site`` explicitly is rejected even when its ``Origin`` happens to be
absent (defence in depth for clients that strip headers).
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from fastapi import Request
from fastapi.responses import ORJSONResponse, Response


def _normalize_origin(value: str) -> str | None:
    """Return the scheme://host[:port] origin of an absolute URL, or None."""
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower()
    port = parts.port
    default_port = 443 if parts.scheme == "https" else 80
    netloc = host if port in (None, default_port) else f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, "", "", ""))


def cross_origin_error() -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_request", "error_description": "cross-origin request rejected"},
        status_code=403,
    )


def is_same_origin_request(request: Request) -> bool:
    """True when the request carries no cross-origin signal.

    Call sites apply this only to state-changing, cookie-authenticated
    requests; Bearer-authenticated API calls are not browser-driven and do not
    need it.
    """
    config = request.app.state.config
    expected = _normalize_origin(config.issuer)
    origin = request.headers.get("origin")
    if origin is not None:
        presented = _normalize_origin(origin)
        if presented is None or expected is None or presented != expected:
            return False
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site not in ("same-origin", "same-site", "none"):
        return False
    return True


def require_same_origin(request: Request) -> Response | None:
    """Return a 403 response when the request is cross-origin, else None."""
    return None if is_same_origin_request(request) else cross_origin_error()
