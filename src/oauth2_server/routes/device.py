"""RFC 8628 Device Authorization Grant.

- `POST /oauth/device_authorization` — client requests a device_code/user_code pair.
- `POST /oauth/device/verify` — logged-in user approves/denies by user_code.

Token-endpoint polling for the `urn:ietf:params:oauth:grant-type:device_code`
grant is handled in `routes/token.py`.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse

from oauth2_server.errors import OAuthError, oauth_error
from oauth2_server.models import DeviceAuthorization
from oauth2_server.services.clients import ClientService
from oauth2_server.sessions import current_user_id

router = APIRouter()

_USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"
_EXPIRES_IN = 600
_INTERVAL = 5


def _random_part() -> str:
    return "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(4))


def _generate_user_code() -> str:
    return f"{_random_part()}-{_random_part()}"


def _normalize_user_code(raw: str) -> str:
    value = raw.strip().upper()
    if "-" not in value and len(value) == 8:
        value = f"{value[:4]}-{value[4:]}"
    return value


@router.post("/device_authorization")
async def device_authorization(request: Request) -> ORJSONResponse:
    form = dict(await request.form())
    storage = request.app.state.storage
    config = request.app.state.config

    try:
        client = await ClientService(storage).authenticate(
            form, request.headers.get("authorization")
        )
    except OAuthError as exc:
        return oauth_error(exc.error, exc.description, exc.status)

    requested_scope = form.get("scope") or ""
    if requested_scope:
        client_scopes = set(client.scope.split())
        if not set(requested_scope.split()).issubset(client_scopes):
            return oauth_error("invalid_scope", "requested scope exceeds client scope")
        scope = requested_scope
    else:
        scope = client.scope

    now = datetime.now(timezone.utc)
    device = DeviceAuthorization(
        id=uuid.uuid4().hex,
        device_code=secrets.token_urlsafe(32),
        user_code=_generate_user_code(),
        client_id=client.client_id,
        scope=scope,
        expires_at=now + timedelta(seconds=_EXPIRES_IN),
        interval_seconds=_INTERVAL,
    )
    await storage.save_device_authorization(device)

    base = config.issuer.rstrip("/")
    verification_uri = f"{base}/oauth/device/verify"
    response = ORJSONResponse(
        {
            "device_code": device.device_code,
            "user_code": device.user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": f"{verification_uri}?user_code={device.user_code}",
            "expires_in": _EXPIRES_IN,
            "interval": _INTERVAL,
        }
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/device/verify")
async def device_verify(request: Request) -> ORJSONResponse:
    user_id = current_user_id(request)
    if user_id is None:
        return ORJSONResponse({"error": "login_required"}, status_code=401)

    form = dict(await request.form())
    raw_user_code = form.get("user_code")
    action = form.get("action")
    if not raw_user_code:
        return ORJSONResponse({"error": "invalid_user_code"}, status_code=400)

    user_code = _normalize_user_code(raw_user_code)
    storage = request.app.state.storage
    device = await storage.get_device_authorization_by_user_code(user_code)

    if (
        device is None
        or device.used
        or device.approved
        or device.denied
        or device.expires_at <= datetime.now(timezone.utc)
    ):
        return ORJSONResponse({"error": "invalid_user_code"}, status_code=400)

    if action == "approve":
        await storage.approve_device_authorization(user_code, user_id)
        return ORJSONResponse({"status": "approved"})
    if action == "deny":
        await storage.deny_device_authorization(user_code)
        return ORJSONResponse({"status": "denied"})

    return ORJSONResponse({"error": "invalid_request"}, status_code=400)
