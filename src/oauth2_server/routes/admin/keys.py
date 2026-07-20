"""Admin JSON API — in-memory signing-key rotation and listing.

Ported from `crates/oauth2-actix/src/handlers/admin_keys.rs`. Routes attach
to `admin_router` (see `routes/admin/__init__.py`), which already carries
`Depends(require_admin)` as a router-level dependency, so both handlers below
are guarded without redeclaring it.

Unlike the other Task 8-10 admin mutation endpoints, rotation is not written
to the audit log — the Rust handler this was ported from doesn't write one
either (see `.superpowers/sdd/research-keys-rs256.md`); the response's own
`warning` field is the only record that a rotation happened.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.keys import generate_signing_key
from oauth2_server.routes.admin._util import _json_body

router = APIRouter()

_VALID_ALGORITHMS = ("HS256", "RS256")
# Rust parity: guards `grace_period_hours * 3600` from overflowing when
# building the rotated key's expiry (`timedelta(seconds=...)` raises
# `OverflowError` well before this — datetime's max range is ~2.7e5 years —
# so this bound is chosen generously above any legitimate grace period while
# still being nowhere near datetime's actual ceiling).
_MAX_GRACE_PERIOD_HOURS = 1_000_000

_WARNING = (
    "Key rotation is in-memory only. Rotated keys will be lost on restart. "
    "DB persistence is not yet implemented."
)


def _invalid_request(message: str) -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_request", "error_description": message}, status_code=400
    )


@router.post("/keys/rotate")
async def rotate_key(request: Request) -> ORJSONResponse:
    body = await _json_body(request)
    config = request.app.state.config
    keyset = request.app.state.keyset

    raw_algorithm = body.get("algorithm")
    # Rust parity: omitting `algorithm` defaults to RS256 regardless of the
    # server's current key mix, not "the current key's algorithm".
    algorithm = str(raw_algorithm).strip().upper() if raw_algorithm else "RS256"
    if algorithm not in _VALID_ALGORITHMS:
        return _invalid_request(f"Unknown algorithm: {raw_algorithm}")

    raw_grace = body.get("grace_period_hours")
    grace_period_hours = config.key_rotation_grace_hours if raw_grace is None else raw_grace
    try:
        grace_period_hours = int(grace_period_hours)
    except (TypeError, ValueError):
        return _invalid_request("grace_period_hours must be an integer")

    if grace_period_hours < 0:
        return _invalid_request("grace_period_hours must be non-negative")
    if grace_period_hours > _MAX_GRACE_PERIOD_HOURS:
        return _invalid_request("grace_period_hours is too large")

    kid = f"{algorithm.lower()}-{int(time.time())}"
    new_key = generate_signing_key(algorithm, kid)
    keyset.rotate(new_key, grace_period_hours * 3600)
    keyset.prune_expired()

    return ORJSONResponse(
        {
            "kid": new_key.kid,
            "algorithm": new_key.algorithm,
            "created_at": new_key.created_at.isoformat(),
            "grace_period_hours": grace_period_hours,
            "warning": _WARNING,
        }
    )


@router.get("/keys")
async def list_keys(request: Request) -> ORJSONResponse:
    keyset = request.app.state.keyset
    return ORJSONResponse(
        {
            "keys": [
                {
                    "kid": key.kid,
                    "algorithm": key.algorithm,
                    "is_current": key.is_current,
                    "created_at": key.created_at.isoformat(),
                    "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                }
                for key in keyset.active_keys()
            ]
        }
    )
