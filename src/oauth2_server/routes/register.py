"""POST /connect/register — RFC 7591 dynamic client registration."""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.models import Client, ClientRegistration, ClientRegistrationResponse

router = APIRouter()

_VALID_AUTH_METHODS = {"client_secret_basic", "client_secret_post", "none"}


def _registration_error(description: str) -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_client_metadata", "error_description": description},
        status_code=400,
        headers={"Cache-Control": "no-store"},
    )


def _is_valid_redirect_uri(uri: str) -> bool:
    parsed = urlparse(uri)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


@router.post("/register")
async def register_client(request: Request) -> ORJSONResponse:
    body = await request.json()
    reg = ClientRegistration.model_validate(body)
    storage = request.app.state.storage
    config = request.app.state.config

    if not reg.redirect_uris or not all(_is_valid_redirect_uri(u) for u in reg.redirect_uris):
        return _registration_error("redirect_uris must be a non-empty list of absolute URLs")

    if reg.token_endpoint_auth_method not in _VALID_AUTH_METHODS:
        return _registration_error(
            f"token_endpoint_auth_method must be one of {sorted(_VALID_AUTH_METHODS)}"
        )

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
        enabled=True,
    )
    await storage.save_client(client)

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
    )
    return ORJSONResponse(
        response_body.model_dump(exclude_none=True),
        status_code=201,
        headers={"Cache-Control": "no-store"},
    )
