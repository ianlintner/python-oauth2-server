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

    def get_post_logout_redirect_uris(self) -> list[str]:
        """Parse the `post_logout_redirect_uris` JSON-array TEXT column.

        Mirrors `Client::get_post_logout_redirect_uris` (crates/oauth2-core):
        an empty/missing column or malformed JSON yields `[]` rather than
        raising, since this is used for an allowlist membership check.
        """
        if not self.post_logout_redirect_uris:
            return []
        try:
            return json.loads(self.post_logout_redirect_uris)
        except json.JSONDecodeError:
            return []


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
    # RFC 9449 §6.1 confirmation claim: {"jkt": "<b64url thumbprint>"} when
    # the access token is DPoP-bound, otherwise omitted entirely (never a
    # literal `null`) via `to_payload`'s `exclude_none=True`. Set by
    # `TokenService.issue`'s `cnf` keyword — see `services/tokens.py` and
    # `routes/token.py` for the grant-by-grant binding rules.
    cnf: dict | None = None

    @classmethod
    def new(
        cls,
        subject: str,
        client_id: str,
        scope: str,
        duration_seconds: int,
        issuer: str,
        *,
        cnf: dict | None = None,
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
            cnf=cnf,
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
    cnf: dict | None = None


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
    backchannel_logout_uri: str | None = None
    backchannel_logout_session_required: bool = False
    frontchannel_logout_uri: str | None = None
    frontchannel_logout_session_required: bool = False
    post_logout_redirect_uris: list[str] = []


class DenylistEntry(BaseModel):
    """Subject denylist row — keyed on (kind, value), kind is one of
    'ip' | 'user_id' | 'username' | 'email' | 'client_id'."""

    id: str
    kind: str
    value: str
    reason: str = ""
    created_by: str = ""
    created_at: datetime
    expires_at: datetime | None = None

    def is_active(self) -> bool:
        return self.expires_at is None or self.expires_at > _now()


class AuditLogEntry(BaseModel):
    """Admin mutation audit trail row."""

    id: str
    actor_id: str = ""
    actor_email: str = ""
    action: str
    target_kind: str = ""
    target_id: str = ""
    ip: str = ""
    user_agent: str = ""
    metadata: str = ""
    created_at: datetime


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
    backchannel_logout_uri: str | None = None
    backchannel_logout_session_required: bool = False
    frontchannel_logout_uri: str | None = None
    frontchannel_logout_session_required: bool = False
    post_logout_redirect_uris: list[str] = []
