"""POST /oauth/par — RFC 9126 pushed authorization requests.

Ported from `handlers::oauth::par` (`crates/oauth2-actix/src/handlers/oauth.rs`).
The request body is parsed manually from raw bytes (not via FastAPI's form
parsing) so duplicate parameters can be rejected per RFC 6749 §3.1, mirroring
the Rust handler's use of `form_urlencoded::parse` over the raw body instead
of serde.

Validation order (all before client lookup/auth): non-UTF-8 body -> 400;
duplicate parameter -> 400; missing client_id -> 400; missing response_type
-> 400. Client authentication then reuses `ClientService.authenticate` — the
same RFC 6749 §2.3 logic as the token endpoint (Basic auth wins over body
credentials; public clients pass with a bare client_id).
"""

from __future__ import annotations

from urllib.parse import parse_qsl

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.errors import OAuthError, oauth_error
from oauth2_server.services.clients import ClientService

router = APIRouter()

# Divergence 5: strip credentials out of the stored param map before they sit
# in memory for up to PAR_TTL_SECS. The Rust implementation stores the raw
# map verbatim (nothing leaks in practice since only the 10 whitelisted keys
# are ever read back at /oauth/authorize), but stripping is strictly safer.
_STRIPPED_KEYS = frozenset({"client_secret", "client_assertion", "client_assertion_type"})


def _par_error(status: int, error: str, description: str) -> ORJSONResponse:
    return ORJSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


@router.post("/par")
async def par(request: Request) -> ORJSONResponse:
    raw_body = await request.body()
    try:
        body_str = raw_body.decode("utf-8")
    except UnicodeDecodeError:
        return _par_error(400, "invalid_request", "Invalid PAR request body encoding")

    params: dict[str, str] = {}
    seen: set[str] = set()
    for key, value in parse_qsl(body_str, keep_blank_values=True):
        if key in seen:
            return _par_error(400, "invalid_request", "Duplicate parameter in PAR request")
        seen.add(key)
        params[key] = value

    client_id = params.get("client_id")
    if not client_id:
        return _par_error(400, "invalid_request", "Missing client_id in PAR request")

    response_type = params.get("response_type")
    if not response_type:
        return _par_error(400, "invalid_request", "Missing response_type in PAR request")

    storage = request.app.state.storage
    try:
        await ClientService(storage, request.app.state.event_bus).authenticate(
            params, request.headers.get("authorization")
        )
    except OAuthError as exc:
        return oauth_error(exc.error, exc.description, exc.status)

    stored_params = {k: v for k, v in params.items() if k not in _STRIPPED_KEYS}
    request_uri = request.app.state.par_store.store(client_id, stored_params)

    response = ORJSONResponse({"request_uri": request_uri, "expires_in": 60}, status_code=201)
    response.headers["Cache-Control"] = "no-store"
    return response
