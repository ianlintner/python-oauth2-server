"""Domain models — field-for-field port of crates/oauth2-core/src/models/."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_datetime(value: Any) -> Any:
    """Tolerant datetime coercion — port of `oauth2-core::chrono_serde`.

    Every datetime field on the storage models runs through this before
    Pydantic's normal validation, so it must accept everything a document
    round-tripped through Mongo (or the existing SQL path) can hand back:

    - a native `datetime` — the SQL path already passes these straight
      through (asyncpg on Postgres) or via ISO strings (SQLite TEXT
      columns); a naive value is assumed UTC, an aware value passes
      through unchanged.
    - an RFC 3339 / ISO 8601 string, including one with a trailing "Z"
      (`datetime.fromisoformat` alone doesn't accept "Z" prior to
      Python 3.11's relaxed parser, so it's normalized to "+00:00" first).
    - the MongoDB extended-JSON forms `{"$date": <millis>}` (v1, a bare
      int) and `{"$date": {"$numberLong": "<millis>"}}` (v2, wrapped —
      what `mongoexport`/some drivers emit for 64-bit ints), both encoding
      milliseconds since the Unix epoch.

    Anything else is passed through unchanged so Pydantic's own error
    reporting applies.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    if isinstance(value, dict) and "$date" in value:
        raw = value["$date"]
        if isinstance(raw, dict):
            raw = raw["$numberLong"]
        millis = int(raw)
        return datetime.fromtimestamp(millis / 1000, tz=timezone.utc)
    return value


MongoDateTime = Annotated[datetime, BeforeValidator(_coerce_datetime)]


class Client(BaseModel):
    id: str
    client_id: str
    client_secret: str
    redirect_uris: str  # JSON array stored as string (TEXT column)
    grant_types: str  # JSON array stored as string
    scope: str
    name: str
    created_at: MongoDateTime
    updated_at: MongoDateTime
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
    created_at: MongoDateTime = Field(default_factory=_now)
    updated_at: MongoDateTime = Field(default_factory=_now)

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
    created_at: MongoDateTime = Field(default_factory=_now)
    expires_at: MongoDateTime
    revoked: bool = False
    token_family: str | None = None


class AuthorizationCode(BaseModel):
    id: str
    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scope: str
    created_at: MongoDateTime = Field(default_factory=_now)
    expires_at: MongoDateTime
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
    created_at: MongoDateTime = Field(default_factory=_now)
    expires_at: MongoDateTime
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
    # RFC 9396 §7.1 / §9.2: the validated authorization_details array carried
    # by this access token, when RAR was used — omitted entirely (never a
    # literal `null`) when absent, same as `cnf`. See
    # `services/rar.py::validate_authorization_details` for how this is
    # produced, and `routes/token.py` for which grants embed it.
    authorization_details: list[dict] | None = None
    # RFC 8693 §4.1 delegation/impersonation claim: `{"sub": <exchanging
    # client_id>}` on every token minted by the token-exchange grant —
    # omitted entirely (never a literal `null`) otherwise, same pattern as
    # `cnf`/`authorization_details`. Rust never sets this on the JWT (only
    # ever on the HTTP response body, and only when `actor_token` was
    # present — see research-rar-token-exchange.md gotchas); this port fixes
    # the JWT gap while keeping the response-body member Rust-conditional
    # (routes/token.py's token-exchange branch).
    #
    # Nested chains (divergence 55): when the token being exchanged was
    # itself produced by a prior exchange (its own `act` claim is a dict),
    # that prior `act` nests one level deeper: `{"sub": <this exchanging
    # client_id>, "act": <prior act>}` — a re-exchange chain reads as a
    # delegation history, most recent actor outermost. A client
    # re-exchanging a token it already stamped (`prior["sub"]` equal to its
    # own `client_id`) does NOT nest — the chain stays flat. Chains deeper
    # than 10 levels are rejected (`invalid_request`) rather than embedded;
    # see `services/limits.py::check_depth` and `routes/token.py`'s
    # token-exchange branch for both rules.
    act: dict | None = None

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
        authorization_details: list[dict] | None = None,
        act: dict | None = None,
        resource: str | None = None,
        audience: list[str] | None = None,
    ) -> "Claims":
        """Build access-token claims.

        `resource` is the RFC 8707 resource indicator: when present it
        REPLACES `client_id` as the audience, so the token is only accepted
        by the resource server it was requested for. Absent, `aud` stays
        `[client_id]` (Rust parity — see `services/resource.py`).

        `audience` is an explicit audience LIST and wins over `resource`: it
        is how the refresh grant carries an already-granted audience set
        forward (divergence 60) rather than re-deriving it from a single
        resource indicator.
        """
        iat = int(_now().timestamp())
        return cls(
            sub=subject,
            iss=issuer,
            aud=audience or ([resource] if resource else [client_id]),
            exp=iat + duration_seconds,
            iat=iat,
            scope=scope,
            jti=uuid.uuid4().hex,
            client_id=client_id,
            cnf=cnf,
            authorization_details=authorization_details,
            act=act,
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
    amr: list[str] | None = None
    auth_time: int | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int
    scope: str | None = None
    id_token: str | None = None
    # RFC 9396 §7.1: the AS MUST echo the validated authorization_details in
    # the token response when RAR was used — a gap the Rust server has (see
    # research-rar-token-exchange.md gotchas); this port fixes it.
    authorization_details: list[dict] | None = None


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
    # RFC 9396 §9.2 — included for active tokens that carry it; absent
    # otherwise (opaque-mode tokens have none, Rust parity — see
    # routes/introspect.py).
    authorization_details: list[dict] | None = None


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
    # RFC 8705 §2.1.2: the expected certificate Subject DN for a
    # `tls_client_auth` client. Persisted to the existing
    # `Client.tls_client_certificate_subject_dn` column.
    tls_client_certificate_subject_dn: str | None = None
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
    created_at: MongoDateTime
    expires_at: MongoDateTime | None = None

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
    created_at: MongoDateTime


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
    # RFC 7591 §3.2.1: echoed back only when the client registered them
    # (`model_dump(exclude_none=True)` drops them otherwise).
    jwks: dict | None = None
    jwks_uri: str | None = None
    tls_client_certificate_subject_dn: str | None = None
    backchannel_logout_uri: str | None = None
    backchannel_logout_session_required: bool = False
    frontchannel_logout_uri: str | None = None
    frontchannel_logout_session_required: bool = False
    post_logout_redirect_uris: list[str] = []
