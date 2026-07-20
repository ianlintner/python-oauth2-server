"""GET /oauth/logout — minimal OIDC RP-Initiated Logout.

Ported (partially) from `crates/oauth2-actix/src/handlers/oidc_logout.rs::logout`.
Only `id_token_hint` `aud` validation is implemented for Phase 1; full logout UX
(post_logout_redirect_uri, confirmation page, `id_token_hint` signature checks
beyond HS256, etc.) stays out of scope for this port.
"""

from __future__ import annotations

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

router = APIRouter()


@router.get("/logout")
async def logout(request: Request) -> ORJSONResponse:
    id_token_hint = request.query_params.get("id_token_hint")

    if id_token_hint:
        config = request.app.state.config
        storage = request.app.state.storage

        try:
            claims = jwt.decode(
                id_token_hint,
                config.jwt_secret,
                algorithms=["HS256"],
                options={"verify_aud": False, "verify_exp": False},
            )
        except jwt.PyJWTError:
            return ORJSONResponse(
                {"error": "invalid_request", "error_description": "invalid id_token_hint"},
                status_code=400,
            )

        aud = claims.get("aud")
        client_id = aud[0] if isinstance(aud, list) else aud
        client = await storage.get_client(client_id) if client_id else None
        if client is None:
            return ORJSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "id_token_hint aud does not match a registered client",
                },
                status_code=400,
            )

    request.session.clear()
    return ORJSONResponse({"status": "logged_out"})
