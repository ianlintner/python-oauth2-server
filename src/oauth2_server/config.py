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

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
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
