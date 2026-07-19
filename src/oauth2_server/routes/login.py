"""POST /auth/login — username/password session login.

Ported from `crates/oauth2-actix/src/handlers/login.rs::login_submit` (credential
verification, disabled-account rejection, safe `return_to` redirect). Rate limiting
and the HTML login page are out of scope for this port.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse, RedirectResponse

from oauth2_server.security import verify_password
from oauth2_server.services.auth import is_safe_redirect
from oauth2_server.sessions import set_login

router = APIRouter()


@router.post("/login")
async def login(request: Request):
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")
    return_to = form.get("return_to")

    storage = request.app.state.storage
    user = await storage.get_user_by_username(username)

    # Generic error for unknown username, disabled account, and bad password
    # alike, to avoid leaking account existence/state.
    if user is None or not user.enabled or not verify_password(password, user.password_hash):
        return ORJSONResponse({"error": "invalid_credentials"}, status_code=401)

    set_login(request, user.id)

    target = return_to if is_safe_redirect(return_to) else "/"
    return RedirectResponse(target, status_code=302)
