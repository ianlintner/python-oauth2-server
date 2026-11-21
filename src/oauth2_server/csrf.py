"""Shared CSRF helpers for session-authenticated, state-changing form posts.

A per-session token is minted when a page is rendered (`session_csrf_token`)
and must be echoed back on the POST (`csrf_request_ok`). The check also
rejects requests whose `Origin` / `Sec-Fetch-Site` headers say they did not
originate from this server's own origin. Clients that send neither header
(non-browser callers) are judged on the token alone.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from starlette.requests import Request

_SESSION_KEY = "csrf_token"
FORM_FIELD = "csrf_token"


def session_csrf_token(request: Request) -> str:
    """Return the session's CSRF token, creating it on first use."""
    token = request.session.get(_SESSION_KEY)
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        request.session[_SESSION_KEY] = token
    return token


def _origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower()


def csrf_request_ok(request: Request, submitted: object, issuer: str) -> bool:
    """True when the request carries the session's token and no header
    indicates a cross-origin source."""
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site.lower() != "same-origin":
        return False

    origin = request.headers.get("origin")
    if origin is not None and origin.lower() != _origin_of(issuer):
        return False

    expected = request.session.get(_SESSION_KEY)
    if not isinstance(expected, str) or not expected:
        return False
    if not isinstance(submitted, str) or not submitted:
        return False
    return secrets.compare_digest(expected.encode(), submitted.encode())
