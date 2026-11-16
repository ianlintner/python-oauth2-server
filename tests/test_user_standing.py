"""Session and grant paths re-read the stored user (enabled, role, epoch, denylist)."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from oauth2_server.models import DenylistEntry
from tests.conftest import build_client_app
from tests.helpers import PKCE_CHALLENGE, login_admin, login_session, post_token, seed_admin
from tests.test_social_login import _mock_transport, _state_from_location
from tests.test_token_endpoint import issue_code, run_code_flow

_AUTHORIZE = {
    "response_type": "code",
    "client_id": "client1",
    "code_challenge": PKCE_CHALLENGE,
    "code_challenge_method": "S256",
    "redirect_uri": "https://a.example/cb",
    "scope": "read",
}


# --- Admin session ---


async def test_demoted_admin_session_loses_admin():
    async with build_client_app() as client:
        await seed_admin(client.storage)
        await login_admin(client)
        assert (await client.get("/admin/api/users")).status_code == 200

        resp = await client.put("/admin/api/users/admin1", json={"role": "user"})
        assert resp.status_code == 200

        resp = await client.get("/admin/api/users")
        assert resp.status_code == 403
        assert resp.json()["error"] == "insufficient_permissions"


async def test_disabled_admin_session_rejected():
    async with build_client_app() as client:
        await seed_admin(client.storage)
        await login_admin(client)

        resp = await client.post("/admin/api/users/admin1/enabled", json={"enabled": False})
        assert resp.status_code == 200

        assert (await client.get("/admin/api/users")).status_code == 403


async def test_deleted_admin_session_rejected():
    async with build_client_app() as client:
        await seed_admin(client.storage)
        await login_admin(client)
        await client.storage.delete_user("admin1")

        assert (await client.get("/admin/api/users")).status_code == 403


async def test_password_reset_ends_existing_admin_session():
    async with build_client_app() as client:
        await seed_admin(client.storage)
        await login_admin(client)

        resp = await client.post(
            "/admin/api/users/admin1/password", json={"password": "another-pass-1"}
        )
        assert resp.status_code == 200

        assert (await client.get("/admin/api/users")).status_code == 403


async def test_session_with_stale_epoch_is_rejected():
    async with build_client_app() as client:
        await seed_admin(client.storage)
        await login_admin(client)
        user = await client.storage.get_user_by_id("admin1")
        await client.storage.update_user(user.model_copy(update={"session_epoch": 5}))

        assert (await client.get("/admin/api/users")).status_code == 403


async def test_denylisted_admin_session_rejected():
    async with build_client_app() as client:
        await seed_admin(client.storage)
        await login_admin(client)
        await client.storage.add_denylist_entry(
            DenylistEntry(
                id="d1",
                kind="username",
                value="admin_rfc",
                reason="test",
                created_at=datetime.now(UTC),
            )
        )

        assert (await client.get("/admin/api/users")).status_code == 403


# --- Authorize / token ---


async def test_disabled_user_session_cannot_obtain_code(client_app):
    await login_session(client_app)
    await client_app.storage.set_user_enabled("u1", False)

    resp = await client_app.get("/oauth/authorize", params=_AUTHORIZE)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"


async def test_active_user_session_still_obtains_code(client_app):
    await login_session(client_app)

    resp = await client_app.get("/oauth/authorize", params=_AUTHORIZE)
    assert resp.status_code == 302
    assert "code=" in resp.headers["location"]


async def test_code_from_disabled_user_is_rejected(client_app):
    code, verifier = await issue_code(client_app)
    await client_app.storage.set_user_enabled("u1", False)

    resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
            "code_verifier": verifier,
        },
        basic_auth=("client1", "s3cret"),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


async def test_refresh_for_disabled_user_is_rejected(client_app):
    resp, _ = await run_code_flow(client_app)
    assert resp.status_code == 200
    refresh = resp.json()["refresh_token"]
    await client_app.storage.set_user_enabled("u1", False)

    resp = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": refresh},
        basic_auth=("client1", "s3cret"),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


# --- Social login ---


async def test_social_callback_rejects_disabled_linked_user():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "oauth2.googleapis.com":
                return httpx.Response(200, json={"access_token": "tok"})
            if request.url.host == "www.googleapis.com":
                return httpx.Response(
                    200,
                    json={"id": "999", "email": "bob@example.com", "verified_email": True},
                )
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        async def callback():
            login_resp = await client.get("/auth/login/google", follow_redirects=False)
            state = _state_from_location(login_resp.headers["location"])
            return await client.get(
                "/auth/callback/google",
                params={"state": state, "code": "c"},
                follow_redirects=False,
            )

        first = await callback()
        assert first.status_code == 302

        user = await client.storage.get_user_by_username("google:999")
        await client.storage.set_user_enabled(user.id, False)
        client.cookies.clear()

        second = await callback()
        assert second.status_code == 403
        assert second.json()["error"] == "access_denied"
        assert "oauth2_session" not in second.headers.get("set-cookie", "")
