"""POST /connect/register — RFC 7591 dynamic client registration."""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse
from pydantic import ValidationError

from oauth2_server.models import Client, ClientRegistration, ClientRegistrationResponse
from oauth2_server.services.clients import (
    JWKS_URI_ERROR,
    VALID_AUTH_METHODS,
    is_valid_jwks_uri,
    is_valid_redirect_uri,
)
from oauth2_server.services.events_bus import emit_event

router = APIRouter()


def _registration_error(description: str) -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_client_metadata", "error_description": description},
        status_code=400,
        headers={"Cache-Control": "no-store"},
    )


# Moved to `services/clients.py` so the admin client API can share it; the
# module-local name stays as the call sites (and tests) already spell it.
_is_valid_redirect_uri = is_valid_redirect_uri


@router.post("/register")
async def register_client(request: Request) -> ORJSONResponse:
    config = request.app.state.config
    if not config.dynamic_registration_enabled:
        return ORJSONResponse(
            {
                "error": "access_denied",
                "error_description": "dynamic client registration is disabled",
            },
            status_code=403,
            headers={"Cache-Control": "no-store"},
        )

    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        return _registration_error("invalid registration request")

    try:
        reg = ClientRegistration.model_validate(body)
    except ValidationError:
        return _registration_error("invalid registration request")

    storage = request.app.state.storage

    if not reg.redirect_uris or not all(_is_valid_redirect_uri(u) for u in reg.redirect_uris):
        return _registration_error("redirect_uris must be a non-empty list of absolute URLs")

    if reg.backchannel_logout_uri and not _is_valid_redirect_uri(reg.backchannel_logout_uri):
        return _registration_error(
            "backchannel_logout_uri must be an absolute http(s) URL without fragment"
        )

    if reg.frontchannel_logout_uri and not _is_valid_redirect_uri(reg.frontchannel_logout_uri):
        return _registration_error(
            "frontchannel_logout_uri must be an absolute http(s) URL without fragment"
        )

    if reg.post_logout_redirect_uris and not all(
        _is_valid_redirect_uri(u) for u in reg.post_logout_redirect_uris
    ):
        return _registration_error(
            "post_logout_redirect_uris must be a list of absolute http(s) URLs without fragment"
        )

    if reg.token_endpoint_auth_method not in VALID_AUTH_METHODS:
        return _registration_error(
            f"token_endpoint_auth_method must be one of {sorted(VALID_AUTH_METHODS)}"
        )

    # RFC 7523 §3 / RFC 7591 §2: a private_key_jwt client's assertions can
    # only ever be verified against a registered key set.
    if (
        reg.token_endpoint_auth_method == "private_key_jwt"
        and reg.jwks is None
        and not reg.jwks_uri
    ):
        return _registration_error("private_key_jwt requires jwks or jwks_uri")

    if reg.jwks is not None and reg.jwks_uri:
        return _registration_error("jwks and jwks_uri are mutually exclusive")

    # `jwks_uri` is the one registrant-supplied URL this server dereferences
    # itself, so it gets a stricter rule than the redirect URIs above — see
    # `services/clients.py::is_valid_jwks_uri`.
    if reg.jwks_uri and not is_valid_jwks_uri(reg.jwks_uri):
        return _registration_error(JWKS_URI_ERROR)

    is_public = reg.token_endpoint_auth_method == "none"
    if is_public and "client_credentials" in reg.grant_types:
        return _registration_error(
            "public clients (token_endpoint_auth_method=none) cannot use the "
            "client_credentials grant"
        )

    now = datetime.now(timezone.utc)
    client_id = secrets.token_urlsafe(16)
    client_secret = "" if is_public else secrets.token_urlsafe(32)
    registration_access_token = secrets.token_urlsafe(32)

    client = Client(
        id=uuid.uuid4().hex,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uris=json.dumps(reg.redirect_uris),
        grant_types=json.dumps(reg.grant_types),
        response_types=json.dumps(reg.response_types),
        scope=reg.scope,
        name=reg.client_name,
        created_at=now,
        updated_at=now,
        token_endpoint_auth_method=reg.token_endpoint_auth_method,
        registration_access_token=registration_access_token,
        contacts=json.dumps(reg.contacts),
        backchannel_logout_uri=reg.backchannel_logout_uri or "",
        backchannel_logout_session_required=reg.backchannel_logout_session_required,
        frontchannel_logout_uri=reg.frontchannel_logout_uri or "",
        frontchannel_logout_session_required=reg.frontchannel_logout_session_required,
        post_logout_redirect_uris=json.dumps(reg.post_logout_redirect_uris),
        jwks=json.dumps(reg.jwks) if reg.jwks else "",
        jwks_uri=reg.jwks_uri or "",
        enabled=True,
    )
    await storage.save_client(client)
    emit_event(
        request.app.state.event_bus,
        "client_registered",
        client_id=client_id,
        metadata={"client_name": reg.client_name, "scope": reg.scope},
    )

    response_body = ClientRegistrationResponse(
        client_id=client_id,
        client_secret=None if is_public else client_secret,
        client_id_issued_at=int(now.timestamp()),
        client_secret_expires_at=None if is_public else 0,
        registration_access_token=registration_access_token,
        registration_client_uri=f"{config.issuer}/connect/register/{client_id}",
        redirect_uris=reg.redirect_uris,
        grant_types=reg.grant_types,
        response_types=reg.response_types,
        token_endpoint_auth_method=reg.token_endpoint_auth_method,
        client_name=reg.client_name,
        scope=reg.scope,
        jwks=reg.jwks,
        jwks_uri=reg.jwks_uri,
        backchannel_logout_uri=reg.backchannel_logout_uri,
        backchannel_logout_session_required=reg.backchannel_logout_session_required,
        frontchannel_logout_uri=reg.frontchannel_logout_uri,
        frontchannel_logout_session_required=reg.frontchannel_logout_session_required,
        post_logout_redirect_uris=reg.post_logout_redirect_uris,
    )
    return ORJSONResponse(
        response_body.model_dump(exclude_none=True),
        status_code=201,
        headers={"Cache-Control": "no-store"},
    )
