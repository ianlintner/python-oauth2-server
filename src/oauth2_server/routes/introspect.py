"""POST /oauth/introspect (RFC 7662) and POST /oauth/revoke (RFC 7009)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.config import Config
from oauth2_server.errors import OAuthError, oauth_error
from oauth2_server.models import IntrospectionResponse, Token
from oauth2_server.security import decode_access_token
from oauth2_server.services.clients import ClientService
from oauth2_server.services.dpop import DpopError, read_dpop_header, validate_dpop_proof

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


def _inactive_response() -> ORJSONResponse:
    response = ORJSONResponse(IntrospectionResponse(active=False).model_dump(exclude_none=True))
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/introspect")
async def introspect(request: Request) -> ORJSONResponse:
    form = dict(await request.form())
    storage = request.app.state.storage
    config = request.app.state.config

    try:
        client = await ClientService(storage).authenticate(
            form, request.headers.get("authorization")
        )
    except OAuthError as exc:
        return oauth_error(exc.error, exc.description, exc.status)

    token_value = form.get("token")
    row, matched_via_refresh = (
        await _lookup_token(storage, token_value) if token_value else (None, False)
    )
    deadline = _expiry_deadline(row, matched_via_refresh, config) if row is not None else None

    if not _is_active(row, deadline) or row.client_id != client.client_id:
        return _inactive_response()

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
    try:
        unverified_claims = jwt.decode(token_value, options={"verify_signature": False})
    except jwt.PyJWTError:
        unverified_claims = {}
    claim_cnf = unverified_claims.get("cnf")
    jkt = claim_cnf.get("jkt") if isinstance(claim_cnf, dict) else None

    cnf: dict | None = None
    if jkt:
        try:
            dpop_header = read_dpop_header(request)
        except DpopError as exc:
            return oauth_error(exc.error, exc.description)

        if dpop_header is None:
            return _inactive_response()

        try:
            validated = validate_dpop_proof(
                dpop_header,
                "POST",
                config.issuer.rstrip("/") + "/oauth/introspect",
                request.app.state.dpop_replay,
            )
        except DpopError:
            return _inactive_response()

        if validated.jkt != jkt:
            return _inactive_response()

        cnf = claim_cnf

    username = None
    if row.user_id:
        user = await storage.get_user_by_id(row.user_id)
        username = user.username if user else None

    jti = row.id
    try:
        claims = decode_access_token(
            token_value, config.jwt_secret, config.issuer, keyset=request.app.state.keyset
        )
        jti = claims.jti
    except jwt.PyJWTError:
        pass

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
        aud=row.client_id,
        jti=jti,
        iss=config.issuer,
        cnf=cnf,
    )
    response = ORJSONResponse(body.model_dump(exclude_none=True))
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/revoke")
async def revoke(request: Request) -> ORJSONResponse:
    form = dict(await request.form())
    storage = request.app.state.storage

    try:
        client = await ClientService(storage).authenticate(
            form, request.headers.get("authorization")
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

    response = ORJSONResponse({})
    response.headers["Cache-Control"] = "no-store"
    return response
