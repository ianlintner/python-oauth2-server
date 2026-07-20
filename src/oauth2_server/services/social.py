"""Social-login provider registry, PKCE, token-exchange/userinfo fetch, and
per-provider circuit breakers.

Ported from `crates/oauth2-social-login/src/{service.rs,models.rs,
circuit_breaker.rs}` (see `.superpowers/sdd/research-social-login.md`).
Routing/session/CSRF glue lives in `routes/social.py`; this module only
knows how to talk to the providers and map their responses onto a common
`SocialUserInfo` shape.

Supported OAuth providers: Google (authorization-code + PKCE S256),
Microsoft, GitHub (all three code-flow, no PKCE), and Azure (a pure
config-alias of Microsoft — same `login.microsoftonline.com` endpoints,
its own tenant, falls back to the Microsoft credentials when its own are
unset). Okta and Auth0 are 503 stubs handled entirely in `routes/social.py`
(divergence 25) — they have no entry in `resolve_provider_config` and no
userinfo mapping here.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import httpx

if TYPE_CHECKING:
    from oauth2_server.config import Config

# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

DISPLAY_NAMES = {
    "google": "Google",
    "microsoft": "Microsoft",
    "github": "GitHub",
    "azure": "Azure",
    "okta": "Okta",
    "auth0": "Auth0",
}

# Providers with a real OAuth implementation (routes/social.py's
# GET /auth/login/{provider} + GET /auth/callback/{provider}).
OAUTH_PROVIDERS = ("google", "microsoft", "github", "azure")
# Stub providers — GET /auth/login/{provider} always 503s and never touches
# the session; there is no callback support (divergence 25).
STUB_PROVIDERS = ("okta", "auth0")
ALL_PROVIDERS = OAUTH_PROVIDERS + STUB_PROVIDERS

# Required by GitHub's REST API; Rust used "rust_oauth2_server" (research
# doc gotchas) — this port identifies itself as the Python server instead.
_GITHUB_USER_AGENT = "python_oauth2_server"
_GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


class ProviderError(Exception):
    """Raised on any token-exchange or userinfo-fetch failure: a non-200
    response, a transport error, malformed JSON, or a response missing a
    required field. Callers turn this into the appropriate 400 response."""


@dataclass(frozen=True)
class ProviderRuntimeConfig:
    """Resolved, ready-to-use OAuth config for one provider + this app
    instance's `Config` — URLs, credentials, scope, and whether PKCE
    applies (Google only)."""

    provider: str
    client_id: str
    client_secret: str
    redirect_uri: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scope: str
    pkce: bool


@dataclass(frozen=True)
class SocialUserInfo:
    """Common shape every provider's userinfo mapping normalizes to."""

    provider: str
    provider_user_id: str
    email: str
    name: str | None = None
    picture: str | None = None


def _redirect_uri(config: "Config", provider: str, configured: str | None) -> str:
    """`configured` (the provider's own `*_redirect_uri` field) when set,
    else an issuer-based default — Rust hardcodes `http://localhost:8080/
    auth/callback/{provider}` as its fallback (research doc `config_keys`);
    this port derives it from `config.issuer` instead so it's correct out
    of the box against any deployed origin."""
    return configured or f"{config.issuer}/auth/callback/{provider}"


def resolve_provider_config(config: "Config", provider: str) -> ProviderRuntimeConfig | None:
    """Build the runtime OAuth config for `provider`, or `None` when it
    isn't configured. A provider is configured iff both its `_client_id`
    and `_client_secret` are set (Rust parity — see config.py's module
    comment on why the config-file `enabled` flag has no analogue here).

    Azure prefers its own `OAUTH2_AZURE_CLIENT_ID`/`_SECRET`/`_REDIRECT_URI`
    and falls back whole-hog to the Microsoft credentials when unset (Rust:
    `config.azure.or(config.microsoft)`), but always uses its OWN
    `azure_tenant_id` regardless of which credentials it ends up using.
    """
    if provider == "google":
        if not (config.google_client_id and config.google_client_secret):
            return None
        return ProviderRuntimeConfig(
            provider="google",
            client_id=config.google_client_id,
            client_secret=config.google_client_secret,
            redirect_uri=_redirect_uri(config, "google", config.google_redirect_uri),
            authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://www.googleapis.com/oauth2/v2/userinfo",
            scope="openid email profile",
            pkce=True,
        )

    if provider == "microsoft":
        if not (config.microsoft_client_id and config.microsoft_client_secret):
            return None
        tenant = config.microsoft_tenant_id or "common"
        return ProviderRuntimeConfig(
            provider="microsoft",
            client_id=config.microsoft_client_id,
            client_secret=config.microsoft_client_secret,
            redirect_uri=_redirect_uri(config, "microsoft", config.microsoft_redirect_uri),
            authorize_url=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
            token_url=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            userinfo_url="https://graph.microsoft.com/v1.0/me",
            scope="openid email profile",
            pkce=False,
        )

    if provider == "github":
        if not (config.github_client_id and config.github_client_secret):
            return None
        return ProviderRuntimeConfig(
            provider="github",
            client_id=config.github_client_id,
            client_secret=config.github_client_secret,
            redirect_uri=_redirect_uri(config, "github", config.github_redirect_uri),
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            userinfo_url="https://api.github.com/user",
            scope="user:email",
            pkce=False,
        )

    if provider == "azure":
        if config.azure_client_id and config.azure_client_secret:
            client_id = config.azure_client_id
            client_secret = config.azure_client_secret
            redirect = config.azure_redirect_uri
        elif config.microsoft_client_id and config.microsoft_client_secret:
            client_id = config.microsoft_client_id
            client_secret = config.microsoft_client_secret
            redirect = config.microsoft_redirect_uri
        else:
            return None
        tenant = config.azure_tenant_id or "common"
        return ProviderRuntimeConfig(
            provider="azure",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=_redirect_uri(config, "azure", redirect),
            authorize_url=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
            token_url=f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            userinfo_url="https://graph.microsoft.com/v1.0/me",
            scope="openid email profile",
            pkce=False,
        )

    return None


# ---------------------------------------------------------------------------
# PKCE (Google only)
# ---------------------------------------------------------------------------


def generate_pkce_pair() -> tuple[str, str]:
    """Returns `(code_verifier, code_challenge)` — S256 challenge per RFC
    7636 §4.2 (`BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`, no padding).
    """
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_authorize_url(rc: ProviderRuntimeConfig, state: str, code_challenge: str | None) -> str:
    params = {
        "response_type": "code",
        "client_id": rc.client_id,
        "redirect_uri": rc.redirect_uri,
        "scope": rc.scope,
        "state": state,
    }
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    return f"{rc.authorize_url}?{urlencode(params)}"


# ---------------------------------------------------------------------------
# Token exchange (NOT circuit-breaker-guarded — Rust parity, research doc
# gotchas: only the userinfo fetch is guarded)
# ---------------------------------------------------------------------------


async def exchange_code(
    http_client: httpx.AsyncClient,
    rc: ProviderRuntimeConfig,
    code: str,
    pkce_verifier: str | None,
) -> str:
    """POST the authorization code to `rc.token_url`; returns the bearer
    `access_token`. Raises `ProviderError` on any transport failure,
    non-200 response, malformed JSON, or a response missing `access_token`.
    """
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": rc.redirect_uri,
        "client_id": rc.client_id,
        "client_secret": rc.client_secret,
    }
    if pkce_verifier is not None:
        data["code_verifier"] = pkce_verifier
    headers = {"Accept": "application/json"}
    try:
        response = await http_client.post(rc.token_url, data=data, headers=headers)
    except httpx.HTTPError as exc:
        raise ProviderError(f"token exchange request failed: {exc}") from exc
    if response.status_code != 200:
        raise ProviderError(f"token endpoint returned {response.status_code}: {response.text}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise ProviderError("token endpoint returned malformed JSON") from exc
    access_token = payload.get("access_token") if isinstance(payload, dict) else None
    if not access_token:
        raise ProviderError("token endpoint response missing access_token")
    return access_token


# ---------------------------------------------------------------------------
# Userinfo fetch + per-provider mapping (circuit-breaker-guarded by the
# caller — see SocialCircuitBreaker below)
# ---------------------------------------------------------------------------


async def _get_json(http_client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> Any:
    try:
        response = await http_client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        raise ProviderError(f"userinfo request failed: {exc}") from exc
    if response.status_code != 200:
        raise ProviderError(f"userinfo endpoint returned {response.status_code}: {response.text}")
    try:
        return response.json()
    except ValueError as exc:
        raise ProviderError("userinfo endpoint returned malformed JSON") from exc


async def _fetch_google_userinfo(
    http_client: httpx.AsyncClient, rc: ProviderRuntimeConfig, access_token: str
) -> SocialUserInfo:
    data = await _get_json(
        http_client, rc.userinfo_url, {"Authorization": f"Bearer {access_token}"}
    )
    user_id = data.get("id") if isinstance(data, dict) else None
    email = data.get("email") if isinstance(data, dict) else None
    if not user_id or not email:
        raise ProviderError("Google userinfo response missing id or email")
    return SocialUserInfo(
        provider="google",
        provider_user_id=str(user_id),
        email=email,
        name=data.get("name"),
        picture=data.get("picture"),
    )


async def _fetch_microsoft_userinfo(
    http_client: httpx.AsyncClient, rc: ProviderRuntimeConfig, access_token: str
) -> SocialUserInfo:
    data = await _get_json(
        http_client, rc.userinfo_url, {"Authorization": f"Bearer {access_token}"}
    )
    user_id = data.get("id") if isinstance(data, dict) else None
    # Microsoft Graph's `/me` has no `email` field guaranteed populated —
    # `userPrincipalName` is what the Rust server (and this port) treats as
    # the account's email (research doc key_behaviors: "may be a UPN, not a
    # real mailbox address").
    email = data.get("userPrincipalName") if isinstance(data, dict) else None
    if not user_id or not email:
        raise ProviderError(
            f"{DISPLAY_NAMES[rc.provider]} userinfo response missing id or userPrincipalName"
        )
    return SocialUserInfo(
        provider=rc.provider,
        provider_user_id=str(user_id),
        email=email,
        name=data.get("displayName"),
        picture=None,
    )


async def _fetch_github_userinfo(
    http_client: httpx.AsyncClient, rc: ProviderRuntimeConfig, access_token: str
) -> SocialUserInfo:
    headers = {"Authorization": f"Bearer {access_token}", "User-Agent": _GITHUB_USER_AGENT}
    data = await _get_json(http_client, rc.userinfo_url, headers)
    user_id = data.get("id") if isinstance(data, dict) else None
    if user_id is None:
        raise ProviderError("GitHub userinfo response missing id")

    email = data.get("email") if isinstance(data, dict) else None
    if not email:
        # GitHub omits `email` from /user when the user hasn't made one
        # public; fall back to the authenticated /user/emails list and pick
        # the entry flagged primary (research doc key_behaviors).
        emails = await _get_json(http_client, _GITHUB_EMAILS_URL, headers)
        primary = None
        if isinstance(emails, list):
            primary = next(
                (e.get("email") for e in emails if isinstance(e, dict) and e.get("primary")),
                None,
            )
        if not primary:
            raise ProviderError("No email found")
        email = primary

    return SocialUserInfo(
        provider="github",
        provider_user_id=str(user_id),
        email=email,
        name=data.get("name"),
        picture=data.get("avatar_url"),
    )


async def fetch_userinfo(
    http_client: httpx.AsyncClient, rc: ProviderRuntimeConfig, access_token: str
) -> SocialUserInfo:
    if rc.provider == "google":
        return await _fetch_google_userinfo(http_client, rc, access_token)
    if rc.provider in ("microsoft", "azure"):
        return await _fetch_microsoft_userinfo(http_client, rc, access_token)
    if rc.provider == "github":
        return await _fetch_github_userinfo(http_client, rc, access_token)
    raise ProviderError(f"no userinfo mapping for provider {rc.provider!r}")


# ---------------------------------------------------------------------------
# Per-provider circuit breaker — userinfo fetch ONLY
# ---------------------------------------------------------------------------
#
# NOTE on the name: this is intentionally a separate, smaller class from
# `services/resilience.py::CircuitBreaker` (which guards the whole app via
# `ResilienceMiddleware` and has configurable failure/success thresholds and
# multi-probe half-open capacity). Social login's breaker is hardcoded to
# the Rust-parity constants below (5 consecutive failures, 30s cooldown,
# exactly one half-open probe) and guards only the userinfo HTTP call, never
# the token exchange (research doc key_behaviors) — reimplementing it here
# keeps the two independent rather than overloading resilience.py's knobs.


class SocialCircuitBreaker:
    """Closed -> Open (after 5 consecutive `record_failure()` calls) ->
    HalfOpen (after a 30s cooldown, admits exactly one probe) ->
    Closed (probe succeeds) / Open (probe fails, cooldown restarts)."""

    _FAILURE_THRESHOLD = 5
    _COOLDOWN_SECS = 30

    def __init__(self) -> None:
        self._open = False
        self._failures = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._lock = asyncio.Lock()

    def _cooldown_elapsed(self) -> bool:
        return self._opened_at is not None and (
            time.monotonic() - self._opened_at >= self._COOLDOWN_SECS
        )

    async def allow(self) -> bool:
        """`True` when the caller may proceed with the userinfo fetch (and
        must then call exactly one of `record_success`/`record_failure`).
        `False` means the circuit is open (or the single half-open probe
        slot is already taken) — the caller must not attempt the fetch."""
        async with self._lock:
            if not self._open:
                return True
            if not self._cooldown_elapsed():
                return False
            if self._probe_in_flight:
                return False
            self._probe_in_flight = True
            return True

    async def record_success(self) -> None:
        async with self._lock:
            self._open = False
            self._opened_at = None
            self._failures = 0
            self._probe_in_flight = False

    async def record_failure(self) -> None:
        async with self._lock:
            if self._open:
                # The half-open probe itself failed — reopen immediately,
                # no failure-threshold grace period while probing.
                self._opened_at = time.monotonic()
                self._probe_in_flight = False
                return
            self._failures += 1
            if self._failures >= self._FAILURE_THRESHOLD:
                self._open = True
                self._opened_at = time.monotonic()
                self._failures = 0
