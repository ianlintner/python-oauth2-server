"""Runtime configuration, sourced from `OAUTH2_*` environment variables.

Mirrors `crates/oauth2-config/src/lib.rs::ServerConfig`.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_INSECURE_JWT_SECRETS = {"secret", "changeme", "your-256-bit-secret", "jwt_secret"}


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OAUTH2_", populate_by_name=True)

    database_url: str = "sqlite+aiosqlite://"
    jwt_secret: str
    issuer: str = Field(default="http://localhost:8080", validation_alias="OAUTH2_PUBLIC_URL")
    allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    access_tokens_opaque: bool = False
    dynamic_registration_enabled: bool = False
    access_token_ttl_secs: int = 3600
    refresh_token_ttl_secs: int = 86400
    authorization_code_ttl_secs: int = 600
    allow_insecure_defaults: bool = False
    host: str = "0.0.0.0"
    port: int = 8080
    max_connections: Annotated[int, Field(validation_alias="OAUTH2_DATABASE_MAX_CONNECTIONS")] = 10
    seed_username: str = "admin"
    seed_password: str | None = None
    seed_email: str = "admin@example.com"
    admin_client_ids: Annotated[list[str], NoDecode] = Field(default_factory=list)
    admin_emails: Annotated[list[str], NoDecode] = Field(default_factory=list)
    id_token_private_key_pem: str | None = None
    id_token_kid: str | None = None
    # Resolved by `_default_id_token_alg` below when left unset: "RS256"
    # when `id_token_private_key_pem` is configured, else "HS256". Setting
    # `OAUTH2_ID_TOKEN_ALG` explicitly always wins over that default.
    id_token_alg: str | None = None
    key_rotation_grace_hours: int = 24
    # Login rate limiting (services/ratelimit.py::FixedWindowLimiter), keyed
    # per-IP and per-username. Mirrors the Rust `LoginRateLimiter` default of
    # 10 attempts / 15 minutes (900s).
    login_rate_limit_attempts: int = 10
    login_rate_limit_window_secs: int = 900
    # Stateless DPoP nonce issuer (services/dpop_nonce.py::DpopNonceIssuer).
    # Secret decoding order (base64url-no-pad -> std base64 -> hex-when-64-
    # chars, else a random per-process fallback) lives in
    # `decode_dpop_nonce_secret`, not here — this field just carries the raw
    # env string through.
    dpop_nonce_secret: str | None = None
    dpop_nonce_lifetime_secs: int = 300
    # RFC 9396 §18.2 `authorization_details_types_supported` discovery value,
    # and the allowlist `services/rar.py::validate_authorization_details`
    # enforces. The Rust server advertises a hardcoded `["openid"]` but never
    # actually enforces it (research-rar-token-exchange.md gotchas, backlog
    # gap #20) — the Python port makes this config-driven and enforced.
    rar_types_supported: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["openid"])
    # Rate limiting (services/limiter.py::TokenBucketLimiter) +
    # resilience (services/resilience.py, middleware_ratelimit.py) — ported
    # from `oauth2-ratelimit`/`oauth2-resilience` (research doc
    # research-ratelimit-resilience.md `config_keys`). Both master switches
    # default to False (Rust parity: `rate_limit.enabled`/`resilience.
    # enabled` are both off out of the box); `rate_limit_invalid_client_max_
    # requests` is independent of `rate_limit_enabled` and defaults ON (5),
    # matching Rust's always-active invalid_client penalty bucket.
    rate_limit_enabled: bool = False
    rate_limit_max_requests: int = 100
    rate_limit_window_secs: int = 60
    rate_limit_invalid_client_max_requests: int = 5
    # Shared by the global rate-limit middleware's IP-extraction (honor
    # `X-Forwarded-For` only when set) — env name matches Rust's
    # `server.trust_proxy_headers` (`OAUTH2_SERVER_TRUST_PROXY_HEADERS`),
    # not the `OAUTH2_RATE_LIMIT_*`-prefixed sibling fields above, since
    # Rust scopes this under `[server]`, not `[rate_limit]`.
    trust_proxy_headers: Annotated[
        bool, Field(validation_alias="OAUTH2_SERVER_TRUST_PROXY_HEADERS")
    ] = False
    resilience_enabled: bool = False
    resilience_max_concurrent: int = 1000
    resilience_cb_failure_threshold: int = 5
    resilience_cb_success_threshold: int = 2
    resilience_cb_open_secs: int = 30
    resilience_cb_half_open_max_probes: int = 3

    @field_validator("dpop_nonce_lifetime_secs")
    @classmethod
    def _clamp_dpop_nonce_lifetime(cls, v: int) -> int:
        # Rust parity (dpop_nonce.rs): a non-positive lifetime would make
        # every nonce bucket-id computation divide-by-zero or produce a
        # degenerate always-current window, so it's clamped to >= 1 rather
        # than rejected outright.
        return max(1, v)

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("rar_types_supported", mode="before")
    @classmethod
    def _split_rar_types(cls, v: object) -> object:
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v

    @field_validator("admin_client_ids", mode="before")
    @classmethod
    def _split_admin_client_ids(cls, v: object) -> object:
        if isinstance(v, str):
            return [client_id.strip() for client_id in v.split(",") if client_id.strip()]
        return v

    @field_validator("admin_emails", mode="before")
    @classmethod
    def _split_admin_emails(cls, v: object) -> object:
        # Case-insensitive allowlist: lowercase both str (env, comma-split)
        # and list (e.g. test config_overrides) inputs alike.
        if isinstance(v, str):
            v = v.split(",")
        if isinstance(v, list):
            return [str(email).strip().lower() for email in v if str(email).strip()]
        return v

    @field_validator("id_token_private_key_pem", mode="before")
    @classmethod
    def _unescape_pem_newlines(cls, v: object) -> object:
        # A PEM passed as a single-line env var typically carries literal
        # "\n" two-character sequences instead of real newlines — replace
        # them so `cryptography`/PyJWT see a well-formed multi-line PEM.
        if isinstance(v, str):
            return v.replace("\\n", "\n")
        return v

    @field_validator("id_token_alg", mode="before")
    @classmethod
    def _normalize_id_token_alg(cls, v: object) -> object:
        # Rust compares OidcConfig.id_token_alg case-insensitively; normalize
        # to upper-case here so every `== "RS256"` check downstream doesn't
        # have to re-derive that (an operator-set `OAUTH2_ID_TOKEN_ALG=rs256`
        # must behave identically to `RS256`).
        if isinstance(v, str):
            return v.upper()
        return v

    @model_validator(mode="after")
    def _default_id_token_alg(self) -> "Config":
        if self.id_token_alg is None:
            self.id_token_alg = "RS256" if self.id_token_private_key_pem else "HS256"
        return self

    def validate_for_production(self) -> None:
        if len(self.jwt_secret) < 32 or self.jwt_secret in _INSECURE_JWT_SECRETS:
            raise ValueError("jwt_secret is insecure: too short or a known default value")
