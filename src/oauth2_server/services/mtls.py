"""Proxy-supplied mTLS client-certificate headers (RFC 8705 plumbing).

The server terminates TLS behind a reverse proxy, so the client certificate
reaches the app only as headers the proxy sets: `X-Client-Cert-Thumbprint`
(base64url SHA-256 of the DER certificate) and `X-SSL-Client-S-DN` (the
certificate subject DN).

Divergence 47 (deliberate, security-motivated): unlike Rust — which reads
these headers unconditionally — this port returns `(None, None)` unless
`config.trust_proxy_headers` is enabled. Without a trusted proxy in front,
any client could simply send the headers itself and forge a certificate
binding. This matches the conditional gate already applied to
`X-Forwarded-For` in `middleware_ratelimit.py::client_ip`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from oauth2_server.config import Config

THUMBPRINT_HEADER = "x-client-cert-thumbprint"
SUBJECT_DN_HEADER = "x-ssl-client-s-dn"


class _HasHeaders(Protocol):
    """Structural type for what this module needs off a request — a
    case-insensitive `headers` mapping (Starlette's `Request`, or any stand-in)."""

    @property
    def headers(self) -> Mapping[str, str]: ...


def _header(request: _HasHeaders, name: str) -> str | None:
    # Starlette header lookups are case-insensitive; an empty or
    # whitespace-only value is treated as absent so a proxy that always sets
    # the header (blank for non-mTLS connections) doesn't look like a
    # certificate-bearing request.
    value = request.headers.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def mtls_headers(request: _HasHeaders, config: Config) -> tuple[str | None, str | None]:
    """Return `(thumbprint, subject_dn)` from the proxy's mTLS headers.

    Both are `None` unless `config.trust_proxy_headers` is true (divergence
    47), and an empty/whitespace-only header value reads as `None`.
    """
    if not config.trust_proxy_headers:
        return (None, None)
    return (_header(request, THUMBPRINT_HEADER), _header(request, SUBJECT_DN_HEADER))
