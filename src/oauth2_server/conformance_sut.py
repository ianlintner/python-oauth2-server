"""SUT interface v2 routes (`contract/sut-interface.md` section 7).

The router is included by `app.build()` **only** when conformance mode is on
(`OAUTH2_CONFORMANCE_MODE=1` plus a valid seed). With the mode off the paths
are never registered, so they answer `404` like any unknown path and the test
clock can never move; `create_app` alone never mounts them.

Implemented capabilities (advertised verbatim at `GET /conformance/capabilities`):

* `test-clock`        — `POST /conformance/clock`      (`oauth2_server.clock`)
* `dpop-nonce-mode`   — `POST /conformance/dpop-nonce` (`DpopNonceIssuer.require_all`)

Not implemented, therefore not advertised: `restart`, `multi-instance`, `mtls`.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server import clock

INTERFACE_VERSION = 2
CAPABILITIES = ["test-clock", "dpop-nonce-mode"]

router = APIRouter(prefix="/conformance", tags=["conformance"])


def _bad_request(description: str) -> ORJSONResponse:
    return ORJSONResponse({"error": "invalid_request", "error_description": description}, 400)


async def _json_object(request: Request) -> dict | None:
    try:
        body = json.loads(await request.body())
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


@router.get("/capabilities")
async def capabilities() -> ORJSONResponse:
    return ORJSONResponse(
        {"interface_version": INTERFACE_VERSION, "capabilities": list(CAPABILITIES)}
    )


@router.post("/clock")
async def advance_clock(request: Request) -> ORJSONResponse:
    body = await _json_object(request)
    if body is None:
        return _bad_request("body must be a JSON object")
    seconds = body.get("advance_seconds")
    # bool is an int subclass; a fractional or numeric-string value is not an integer.
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        return _bad_request("advance_seconds must be an integer")
    try:
        clock.advance(seconds)
    except ValueError as exc:
        return _bad_request(str(exc))
    return ORJSONResponse({"now": int(clock.time())})


@router.post("/dpop-nonce")
async def set_dpop_nonce_mode(request: Request) -> ORJSONResponse:
    body = await _json_object(request)
    if body is None or not isinstance(body.get("required"), bool):
        return _bad_request("required must be a boolean")
    request.app.state.dpop_nonce_issuer.require_all = body["required"]
    return ORJSONResponse({"required": body["required"]})
