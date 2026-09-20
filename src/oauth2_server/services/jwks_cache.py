"""`jwks_uri` TTL cache (RFC 7517 / RFC 7523 §3) — fetches and caches a
client's JWKS document so `private_key_jwt` validation does not hit the
client's key endpoint on every token request.

Ported from `crates/oauth2-actix/src/handlers/jwks_cache.rs`; the TTL
constants, clamping rule and `invalid_client` descriptions are reproduced
verbatim.

**Single-process only** — a plain `dict` on the instance, one instance per
app (`app.state.jwks_cache`), like the Rust `Arc<Mutex<HashMap>>`
registered once as actix `app_data`.
"""

from __future__ import annotations

import json
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
        try:
            response = await self._http_client.get(
                url,
                headers={"Accept": "application/json"},
                timeout=JWKS_FETCH_TIMEOUT_SECS,
            )
        except httpx.HTTPError as exc:
            raise OAuthError("invalid_client", f"Failed to fetch jwks_uri '{url}': {exc}") from exc

        if not response.is_success:
            raise OAuthError(
                "invalid_client", f"jwks_uri '{url}' returned HTTP {response.status_code}"
            )

        ttl = parse_cache_control_max_age(response.headers)

        try:
            document = json.loads(response.text)
        except ValueError as exc:
            raise OAuthError(
                "invalid_client", f"jwks_uri '{url}' returned invalid JSON: {exc}"
            ) from exc

        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise OAuthError(
                "invalid_client", f"jwks_uri '{url}' JWKS document missing 'keys' array"
            )
        return document, ttl


async def resolve_client_jwks(client: Client, cache: JwksCache | None) -> dict | None:
    """Resolve the JWKS a `private_key_jwt` client's assertions are verified
    against: `None` for every other auth method (no fetch needed), the
    inline `jwks` column when set (no network), else the cached `jwks_uri`
    document."""
    if client.token_endpoint_auth_method != "private_key_jwt":
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

    raise OAuthError("invalid_client", "Client must register jwks or jwks_uri for private_key_jwt")
