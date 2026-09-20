"""`jwks_uri` TTL cache (RFC 7517 / RFC 7523 §3) — fetches and caches a
client's JWKS document so `private_key_jwt` validation does not hit the
client's key endpoint on every token request.

Ported from `crates/oauth2-actix/src/handlers/jwks_cache.rs`; the TTL
constants and clamping rule are reproduced verbatim.

**Divergence from Rust — fetch failures say nothing about the fetch.**
Rust folds the URL, the upstream status code and the transport error text
into the `invalid_client` description it returns to the caller. Since
`jwks_uri` is registrant-controlled and this server dereferences it, that
turns the token endpoint into an SSRF / port-scan oracle: "connection
refused" vs. "HTTP 401" vs. "invalid JSON" distinguishes a closed port from
an open one from a real service, for any host the registrant cares to
point at. Every failure here therefore collapses to one of two fixed
strings (`_FETCH_FAILED_MESSAGE`, `_INVALID_DOCUMENT_MESSAGE`) carrying no
URL, status or exception text, and the detail is `logger.warning`-ed
server-side instead. Registration additionally refuses to store an unsafe
`jwks_uri` at all (`services/clients.py::is_valid_jwks_uri`).

**Single-process only** — a plain `dict` on the instance, one instance per
app (`app.state.jwks_cache`), like the Rust `Arc<Mutex<HashMap>>`
registered once as actix `app_data`.
"""

from __future__ import annotations

import json
import logging
import time

import httpx

from oauth2_server.errors import OAuthError
from oauth2_server.models import Client

# TTL used when the JWKS endpoint advertises no usable `Cache-Control:
# max-age`. Like every other value it is clamped below, so it must stay
# inside [MIN_TTL_SECS, MAX_TTL_SECS].
DEFAULT_TTL_SECS = 300
# Floor, so a JWKS endpoint advertising `max-age=0` cannot be hammered.
MIN_TTL_SECS = 30
# Ceiling, so keys are eventually re-fetched even if the endpoint says to
# cache forever.
MAX_TTL_SECS = 86_400

# Budget for a single JWKS fetch. Passed explicitly on every request rather
# than relying on the shared `app.state.http_client`'s own timeout: that
# client is built for back-channel logout POSTs (app.py) and its timeout is
# not this module's to assume.
JWKS_FETCH_TIMEOUT_SECS = 10

_MAX_AGE_PREFIX = "max-age="

logger = logging.getLogger(__name__)

# The only two fetch-failure descriptions a client is ever shown. See the
# module docstring for why they carry no detail.
_FETCH_FAILED_MESSAGE = "Failed to fetch jwks_uri"
_INVALID_DOCUMENT_MESSAGE = "jwks_uri returned an invalid JWKS document"


def parse_cache_control_max_age(headers: httpx.Headers) -> int:
    """Read `Cache-Control: max-age=N` and clamp it to
    `[MIN_TTL_SECS, MAX_TTL_SECS]`, falling back to `DEFAULT_TTL_SECS` when
    the header is absent, carries no `max-age`, or the value is not a
    non-negative integer (Rust parses into `u64`, so `max-age=-1` and
    `max-age=abc` both fall back rather than clamping)."""
    raw = headers.get("cache-control")
    secs = DEFAULT_TTL_SECS
    if raw:
        directive = next(
            (d for d in (part.strip() for part in raw.split(",")) if d.startswith(_MAX_AGE_PREFIX)),
            None,
        )
        if directive is not None:
            value = directive[len(_MAX_AGE_PREFIX) :]
            secs = int(value) if value.isdigit() else DEFAULT_TTL_SECS
    return min(max(secs, MIN_TTL_SECS), MAX_TTL_SECS)


class JwksCache:
    """Shared `url` -> `(jwks_document, monotonic_expiry)` cache."""

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self._http_client = http_client
        self._entries: dict[str, tuple[dict, float]] = {}

    async def fetch(self, url: str) -> dict:
        """Return the JWKS document at `url`, re-fetching only when the
        cached entry has expired."""
        entry = self._entries.get(url)
        if entry is not None and entry[1] > time.monotonic():
            return entry[0]

        document, ttl = await self._fetch_from_url(url)
        self._entries[url] = (document, time.monotonic() + ttl)
        return document

    async def _fetch_from_url(self, url: str) -> tuple[dict, int]:
        """Fetch and validate the JWKS at `url`.

        Every failure raises `invalid_client` with a fixed, detail-free
        description; the URL, status and exception text go to the log
        instead (module docstring).
        """
        try:
            response = await self._http_client.get(
                url,
                headers={"Accept": "application/json"},
                timeout=JWKS_FETCH_TIMEOUT_SECS,
            )
        except httpx.HTTPError as exc:
            logger.warning("failed to fetch jwks_uri %s: %s", url, exc)
            raise OAuthError("invalid_client", _FETCH_FAILED_MESSAGE) from exc

        if not response.is_success:
            logger.warning("jwks_uri %s returned HTTP %s", url, response.status_code)
            raise OAuthError("invalid_client", _FETCH_FAILED_MESSAGE)

        ttl = parse_cache_control_max_age(response.headers)

        try:
            document = json.loads(response.text)
        except ValueError as exc:
            logger.warning("jwks_uri %s returned invalid JSON: %s", url, exc)
            raise OAuthError("invalid_client", _INVALID_DOCUMENT_MESSAGE) from exc

        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            logger.warning("jwks_uri %s returned a document with no 'keys' array", url)
            raise OAuthError("invalid_client", _INVALID_DOCUMENT_MESSAGE)
        return document, ttl


async def resolve_client_jwks(
    client: Client,
    cache: JwksCache | None,
    *,
    methods: tuple[str, ...] = ("private_key_jwt",),
) -> dict | None:
    """Resolve the JWKS a client's credentials are verified against: `None`
    for every auth method outside `methods` (no fetch needed), the inline
    `jwks` column when set (no network), else the cached `jwks_uri`
    document.

    `methods` defaults to `private_key_jwt` (RFC 7523 §3 assertions) and is
    passed as `("self_signed_tls_client_auth",)` by the RFC 8705 §2.2 path
    in `services/clients.py`, which resolves the same key material to match
    a certificate thumbprint against `x5t#S256`.
    """
    if client.token_endpoint_auth_method not in methods:
        return None

    inline = (client.jwks or "").strip()
    if inline:
        try:
            return json.loads(inline)
        except ValueError as exc:
            raise OAuthError("invalid_client", "Client inline JWKS is not valid JSON") from exc

    uri = (client.jwks_uri or "").strip()
    if uri:
        if cache is None:
            raise OAuthError(
                "invalid_client",
                "jwks_uri is not supported in this context (no JWKS cache available)",
            )
        return await cache.fetch(uri)

    raise OAuthError(
        "invalid_client",
        f"Client must register jwks or jwks_uri for {client.token_endpoint_auth_method}",
    )
