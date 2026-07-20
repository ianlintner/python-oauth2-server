"""Small shared helpers for the admin JSON API handlers.

Split out from `clients.py`/`users.py` (rather than living in
`routes/admin/__init__.py`) because `__init__.py` imports both of those
modules at import time to build `admin_router`; having them import back
from `__init__.py` would create a circular import.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel, ValidationError


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _validation_error_response(exc: ValidationError) -> ORJSONResponse:
    """Turns the first Pydantic error into a 400 `invalid_request` — used so
    a hand-validated PUT body model never lets FastAPI's automatic 422
    escape (these models aren't wired as route parameters, so FastAPI never
    sees them; `_parse_body` below validates by hand instead)."""
    first = exc.errors()[0]
    field = ".".join(str(part) for part in first["loc"]) or "body"
    return ORJSONResponse(
        {"error": "invalid_request", "error_description": f"{field}: {first['msg']}"},
        status_code=400,
    )


async def _parse_body(
    request: Request, model_cls: type[BaseModel]
) -> tuple[BaseModel, None] | tuple[None, ORJSONResponse]:
    """Validates the JSON request body against `model_cls` — an all-optional,
    `extra="ignore"` Pydantic model. Returns `(model, None)` on success or
    `(None, error_response)` on a type/shape mismatch; callers should
    `return` the error response verbatim. Use `model.model_fields_set` to
    tell "field provided" from "field defaulted", preserving partial-update
    semantics (only explicitly-provided fields should be applied)."""
    raw = await _json_body(request)
    try:
        model = model_cls.model_validate(raw)
    except ValidationError as exc:
        return None, _validation_error_response(exc)
    return model, None
