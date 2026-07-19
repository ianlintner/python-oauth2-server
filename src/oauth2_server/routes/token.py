"""POST /oauth/token — RFC 6749 §3.2 token endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.errors import OAuthError, oauth_error
from oauth2_server.services.clients import ClientService
from oauth2_server.services.tokens import TokenService

router = APIRouter()


@router.post("/token")
async def token(request: Request) -> ORJSONResponse:
    form = dict(await request.form())
    storage = request.app.state.storage
    config = request.app.state.config

    try:
        client = await ClientService(storage).authenticate(
            form, request.headers.get("authorization")
        )
    except OAuthError as exc:
        return oauth_error(exc.error, exc.description, exc.status)

    grant_type = form.get("grant_type")

    if grant_type == "client_credentials":
        if "client_credentials" not in client.grant_type_list():
            return oauth_error(
                "unauthorized_client", "client is not authorized for this grant type"
            )

        requested_scope = form.get("scope") or ""
        if requested_scope:
            client_scopes = set(client.scope.split())
            scope = " ".join(s for s in requested_scope.split() if s in client_scopes)
        else:
            scope = client.scope

        token_response = await TokenService(storage, config).issue(
            client, None, scope, with_refresh=False
        )
        response = ORJSONResponse(token_response.model_dump(exclude_none=True))
        response.headers["Cache-Control"] = "no-store"
        return response

    return oauth_error("unsupported_grant_type", f"grant_type '{grant_type}' is not supported")
