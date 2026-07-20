"""Runtime configuration, sourced from `OAUTH2_*` environment variables.

Mirrors `crates/oauth2-config/src/lib.rs::ServerConfig`.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_INSECURE_JWT_SECRETS = {"secret", "changeme", "your-256-bit-secret", "jwt_secret"}


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OAUTH2_", populate_by_name=True)

    database_url: str = "sqlite+aiosqlite://"
    jwt_secret: str
    issuer: str = Field(default="http://localhost:8080", validation_alias="OAUTH2_PUBLIC_URL")
    allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)
    access_tokens_opaque: bool = False
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

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    def validate_for_production(self) -> None:
        if len(self.jwt_secret) < 32 or self.jwt_secret in _INSECURE_JWT_SECRETS:
            raise ValueError("jwt_secret is insecure: too short or a known default value")
