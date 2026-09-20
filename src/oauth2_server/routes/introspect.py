"""POST /oauth/introspect (RFC 7662) and POST /oauth/revoke (RFC 7009)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Request, Response
from fastapi.responses import ORJSONResponse

from oauth2_server.config import Config
from oauth2_server.errors import OAuthError, oauth_error
from oauth2_server.models import Client, IntrospectionResponse, Token
from oauth2_server.security import (
    INTROSPECTION_JWT_TYP,
    decode_access_token,
    decode_unverified_claims,
    encode_introspection_jwt,
)
from oauth2_server.services.clients import ClientService
from oauth2_server.services.dpop import DpopError, read_dpop_header, validate_dpop_proof
from oauth2_server.services.events_bus import emit_event
from oauth2_server.services.mtls import mtls_headers

router = APIRouter()


async def _lookup_token(storage, token_value: str) -> tuple[Token | None, bool]:
    """Look up a token by access or refresh value.

    Returns `(row, matched_via_refresh)` so callers can tell which column
    matched — a refresh-token match has its own expiry (`created_at +
    refresh_token_ttl_secs`) rather than the access token's `expires_at`.
    """
    row = await storage.get_token_by_access_token(token_value)
    if row is not None:
        return row, False
    row = await storage.get_token_by_refresh_token(token_value)
    return row, row is not None


def _expiry_deadline(row: Token, matched_via_refresh: bool, config: Config) -> datetime:
    if matched_via_refresh:
        return row.created_at + timedelta(seconds=config.refresh_token_ttl_secs)
    return row.expires_at


def _is_active(row: Token | None, deadline: datetime | None) -> bool:
    if row is None or row.revoked or deadline is None:
        return False
    return deadline > datetime.now(timezone.utc)


# RFC 9701 §3: the media type a caller puts in `Accept` to ask for a
# JWT-secured introspection response, and the Content-Type it gets back.
INTROSPECTION_JWT_MEDIA_TYPE = f"application/{INTROSPECTION_JWT_TYP}"


def _introspection_response(request: Request, body: dict, client: Client) -> Response:
    """Render an introspection RESULT as JSON or, when the caller asked for
    it via `Accept: application/token-introspection+jwt`, as an RFC 9701
    JWT-secured introspection response.

    Every path that returns an introspection result goes through here —
    including the inactive ones. That is divergence 34 (deliberate): Rust
    only wraps the active result, leaving a JWT-negotiating caller to parse
    a bare JSON `{"active": false}` for the inactive answer. Wrapping both
    keeps one media type per request, and an unwrapped inactive response
    would also be unauthenticated — a network attacker could downgrade any
    active answer to a forgeable `{"active": false}`.

    Client-authentication failures (`invalid_client`) are NOT results and
    stay JSON: at that point there is no authenticated `aud` to sign for.

    A public client asking for the JWT format when the server has no RS256
    key gets a 400 rather than a JSON body: `encode_introspection_jwt` has
    no key such a client could verify, and quietly answering in the other
    media type would be an unauthenticated downgrade.
    """
    if INTROSPECTION_JWT_MEDIA_TYPE in request.headers.get("accept", ""):
        config = request.app.state.config
        payload = {
            "iss": config.issuer,
            "aud": client.client_id,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "token_introspection": body,
        }
        try:
            signed = encode_introspection_jwt(
                payload, keyset=request.app.state.keyset, client=client
            )
        except OAuthError as exc:
            return oauth_error(exc.error, exc.description, exc.status)
        response: Response = Response(
            content=signed,
            media_type=INTROSPECTION_JWT_MEDIA_TYPE,
        )
    else:
        response = ORJSONResponse(body)
    response.headers["Cache-Control"] = "no-store"
    return response


def _inactive_response(request: Request, client: Client) -> Response:
    return _introspection_response(
        request, IntrospectionResponse(active=False).model_dump(exclude_none=True), client
    )


@router.post("/introspect")
async def introspect(request: Request) -> Response:
    form = dict(await request.form())
    storage = request.app.state.storage
    config = request.app.state.config
    event_bus = request.app.state.event_bus

    try:
        client = await ClientService.from_app(request.app.state).authenticate(
            form, request.headers.get("authorization"), mtls=mtls_headers(request, config)
        )
    except OAuthError as exc:
        return oauth_error(exc.error, exc.description, exc.status)

    token_value = form.get("token")
    row, matched_via_refresh = (
        await _lookup_token(storage, token_value) if token_value else (None, False)
    )
    deadline = _expiry_deadline(row, matched_via_refresh, config) if row is not None else None

    inactive = not _is_active(row, deadline)
    if inactive and row is not None:
        # `token_expired` (research doc EVENT TYPES: "severity=Warning, on
        # ValidateToken hitting expired/revoked token") — only when a row
        # actually exists (an unrecognized token value is simply not this
        # event; there's nothing to report as expired).
        emit_event(
            event_bus,
            "token_expired",
            severity="warning",
            user_id=row.user_id,
            client_id=row.client_id,
        )
    if inactive or row.client_id != client.client_id:
        return _inactive_response(request, client)

    # RFC 9449 §7.1: an access token bound to a DPoP key (a `cnf.jkt` claim)
    # requires the introspection request itself to carry a valid, matching
    # DPoP proof. Per research-dpop.md's POST /oauth/introspect entry, a
    # missing header, an invalid proof, and a jkt mismatch all collapse to
    # the same `{"active": false}` — introspection never leaks *why* a
    # DPoP-bound token failed binding. Claims are decoded unverified (the
    # storage row above is the validity gate, same established pattern as
    # `_salvage_old_cnf` in routes/token.py); opaque access tokens — or any
    # token that isn't a JWT — simply decode to no claims, so `cnf` is never
    # found and this whole block is a no-op, leaving unbound tokens
    # unaffected. `token_type` still reports the stored "Bearer" below even
    # on a successful DPoP-bound introspection (documented Rust quirk, kept
    # for parity) — only `cnf` is echoed back.
    # Deliberately decodes the PRESENTED value (like the jti extraction
    # below), not row.access_token: a DPoP-bound token introspected via its
    # opaque refresh-token value skips the binding check. Accepted parity —
    # a refresh-token holder can already mint a fresh bound access token via
    # the refresh grant without a proof (research-dpop.md, documented gap).
    unverified_claims = decode_unverified_claims(token_value)
    claim_cnf = unverified_claims.get("cnf")
    jkt = claim_cnf.get("jkt") if isinstance(claim_cnf, dict) else None
    # RFC 9396 §9.2: echo authorization_details for active tokens, read from
    # the same unverified-claims decode as `cnf` above. Opaque access tokens
    # (or any non-JWT token value) decode to no claims, so this is naturally
    # `None` for them — the documented opaque-mode drop (parity with
    # services/tokens.py's `bound_details`).
    claim_authorization_details = unverified_claims.get("authorization_details")

    cnf: dict | None = None
    if jkt:
        try:
            dpop_header = read_dpop_header(request)
        except DpopError as exc:
            return oauth_error(exc.error, exc.description)

        if dpop_header is None:
            return _inactive_response(request, client)

        try:
            validated = validate_dpop_proof(
                dpop_header,
                "POST",
                config.issuer.rstrip("/") + "/oauth/introspect",
                request.app.state.dpop_replay,
            )
        except DpopError:
            return _inactive_response(request, client)

        if validated.jkt != jkt:
            return _inactive_response(request, client)

        cnf = claim_cnf

    username = None
    if row.user_id:
        user = await storage.get_user_by_id(row.user_id)
        username = user.username if user else None

    jti = row.id
    # RFC 8707: when the access token carries a resource-bound `aud`, report
    # THAT audience rather than the client_id — the same verified decode that
    # supplies `jti`. Anything that doesn't verify (an opaque token, a
    # refresh-token value, a foreign JWT) falls back to `row.client_id`, the
    # pre-resource-indicator behavior. A single audience is emitted as a bare
    # string, matching the JWT's own serde rule (`Claims.to_payload`).
    aud: list[str] | str = row.client_id
    try:
        claims = decode_access_token(
            token_value, config.jwt_secret, config.issuer, keyset=request.app.state.keyset
        )
        jti = claims.jti
        aud = claims.aud[0] if len(claims.aud) == 1 else claims.aud
    except jwt.PyJWTError:
        pass

    emit_event(event_bus, "token_validated", user_id=row.user_id, client_id=row.client_id)

    iat = int(row.created_at.timestamp())
    body = IntrospectionResponse(
        active=True,
        scope=row.scope,
        client_id=row.client_id,
        username=username,
        token_type="Bearer",
        exp=int(deadline.timestamp()),
        iat=iat,
        nbf=iat,
        sub=row.user_id or row.client_id,
        aud=aud,
        jti=jti,
        iss=config.issuer,
        cnf=cnf,
        authorization_details=claim_authorization_details,
    )
    return _introspection_response(request, body.model_dump(exclude_none=True), client)


@router.post("/revoke")
async def revoke(request: Request) -> ORJSONResponse:
    form = dict(await request.form())
    storage = request.app.state.storage
    config = request.app.state.config
    event_bus = request.app.state.event_bus

    try:
        client = await ClientService.from_app(request.app.state).authenticate(
            form, request.headers.get("authorization"), mtls=mtls_headers(request, config)
        )
    except OAuthError as exc:
        return oauth_error(exc.error, exc.description, exc.status)

    token_value = form.get("token")
    row, _ = await _lookup_token(storage, token_value) if token_value else (None, False)

    if row is not None and row.client_id == client.client_id:
        if row.token_family:
            await storage.revoke_token_family(row.token_family)
        else:
            await storage.revoke_token(token_value)
        request.app.state.metrics.oauth_token_revoked_total.inc()
        emit_event(event_bus, "token_revoked", user_id=row.user_id, client_id=row.client_id)

    response = ORJSONResponse({})
    response.headers["Cache-Control"] = "no-store"
    return response
