"""Domain models — field-for-field port of crates/oauth2-core/src/models/."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Client(BaseModel):
    id: str
    client_id: str
    client_secret: str
    redirect_uris: str  # JSON array stored as string (TEXT column)
    grant_types: str  # JSON array stored as string
    scope: str
    name: str
    created_at: datetime
    updated_at: datetime
    token_endpoint_auth_method: str = "client_secret_basic"
    registration_access_token: str = ""
    response_types: str = '["code"]'
    contacts: str = ""
    logo_uri: str = ""
    client_uri: str = ""
    policy_uri: str = ""
    tos_uri: str = ""
    jwks: str = ""
    jwks_uri: str = ""
    backchannel_logout_uri: str = ""
    backchannel_logout_session_required: bool = False
    frontchannel_logout_uri: str = ""
    frontchannel_logout_session_required: bool = False
    post_logout_redirect_uris: str = ""
    enabled: bool = True
    require_state: bool = False
    tls_client_certificate_subject_dn: str = ""
    dpop_nonce_required: bool = False

    def is_public(self) -> bool:
        return self.token_endpoint_auth_method == "none"

    def redirect_uri_list(self) -> list[str]:
        return json.loads(self.redirect_uris) if self.redirect_uris else []

    def grant_type_list(self) -> list[str]:
        return json.loads(self.grant_types) if self.grant_types else []


class User(BaseModel):
    id: str
    username: str
    password_hash: str
    email: str
    enabled: bool = True
    role: str = "user"
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)

    def is_admin(self) -> bool:
        return self.role == "admin"


class Token(BaseModel):
    id: str
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int = 3600
    scope: str = ""
    client_id: str
    user_id: str | None = None
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime
    revoked: bool = False
    token_family: str | None = None


class AuthorizationCode(BaseModel):
    id: str
    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scope: str
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime
    used: bool = False
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    nonce: str | None = None
    resource: str | None = None
    authorization_details: str | None = None
    claims_request: str | None = None
    token_family: str | None = None


class DeviceAuthorization(BaseModel):
    id: str
    device_code: str
    user_code: str
    client_id: str
    scope: str
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime
    interval_seconds: int = 5
    approved: bool = False
    denied: bool = False
    used: bool = False
    user_id: str | None = None


class Claims(BaseModel):
    """RFC 9068 access-token claims."""

    sub: str
    iss: str
    aud: list[str]
    exp: int
    iat: int
    scope: str
    jti: str
    client_id: str | None = None

    @classmethod
    def new(
        cls, subject: str, client_id: str, scope: str, duration_seconds: int, issuer: str
    ) -> "Claims":
        iat = int(_now().timestamp())
        return cls(
            sub=subject,
            iss=issuer,
            aud=[client_id],
            exp=iat + duration_seconds,
            iat=iat,
            scope=scope,
            jti=uuid.uuid4().hex,
            client_id=client_id,
        )

    def to_payload(self) -> dict[str, Any]:
        data = self.model_dump(exclude_none=True)
        if len(self.aud) == 1:
            data["aud"] = self.aud[0]  # Rust serde: single aud -> bare string
        return data


class IdTokenClaims(BaseModel):
    iss: str
    sub: str
    aud: str
    exp: int
    iat: int
    nonce: str | None = None
    at_hash: str | None = None
    c_hash: str | None = None
    email: str | None = None
    preferred_username: str | None = None
    acr: str | None = None
    auth_time: int | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int
    scope: str | None = None
    id_token: str | None = None


class IntrospectionResponse(BaseModel):
    active: bool
    scope: str | None = None
    client_id: str | None = None
    username: str | None = None
    token_type: str | None = None
    exp: int | None = None
    iat: int | None = None
    nbf: int | None = None
    sub: str | None = None
    aud: list[str] | str | None = None
    jti: str | None = None
    iss: str | None = None


class ClientRegistration(BaseModel):
    redirect_uris: list[str]
    client_name: str = ""
    grant_types: list[str] = ["authorization_code"]
    response_types: list[str] = ["code"]
    scope: str = ""
    token_endpoint_auth_method: str = "client_secret_basic"
    contacts: list[str] = []
    logo_uri: str | None = None
    client_uri: str | None = None
    policy_uri: str | None = None
    tos_uri: str | None = None
    jwks: dict | None = None
    jwks_uri: str | None = None


class ClientRegistrationResponse(BaseModel):
    client_id: str
    client_secret: str | None = None
    client_id_issued_at: int
    client_secret_expires_at: int | None = None
    registration_access_token: str
    registration_client_uri: str
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    token_endpoint_auth_method: str
    client_name: str = ""
    scope: str = ""
