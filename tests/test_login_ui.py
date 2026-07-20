"""GET /auth/login (login page) and GET /oauth/device/verify (device-verify
page) — UI parity with the Rust server.

Ported from `crates/oauth2-actix/src/handlers/login.rs::login_page` (error
banner mapping) and `crates/oauth2-actix/src/handlers/device.rs` unit tests
`user_code_is_html_escaped` / `normal_user_code_is_preserved` (XSS hardening
of the pre-filled `user_code` input).
"""

from __future__ import annotations

from tests.helpers import login_session


async def start_device_flow(client_app, *, client_id="client1", client_secret="s3cret"):
    import base64

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return await client_app.post(
        "/oauth/device_authorization",
        headers={"Authorization": f"Basic {basic}"},
    )


# ---------------------------------------------------------------------------
# GET /auth/login
# ---------------------------------------------------------------------------


async def test_login_page_renders_form(client_app):
    resp = await client_app.get("/auth/login")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    assert '<form method="post" action="/auth/login">' in body
    assert 'name="username"' in body
    assert 'name="password"' in body
    # No error banner when ?error= is absent.
    assert "<!--SERVER_ERROR-->" not in body


async def test_login_page_shows_error_banner(client_app):
    cases = {
        "invalid_credentials": "Invalid username or password. Please try again.",
        "login_required": "Please log in to continue.",
        "too_many_attempts": "Too many login attempts. Please wait a few minutes and try again.",
        "some_unknown_key": "An error occurred. Please try again.",
    }
    for error_key, expected_message in cases.items():
        resp = await client_app.get("/auth/login", params={"error": error_key})
        assert resp.status_code == 200
        assert expected_message in resp.text, error_key


async def test_login_error_key_is_escaped(client_app):
    resp = await client_app.get("/auth/login", params={"error": "<script>alert(1)</script>"})
    assert resp.status_code == 200
    body = resp.text
    assert "<script>alert(1)</script>" not in body
    # Unknown key -> generic message, never the raw key reflected.
    assert "An error occurred. Please try again." in body


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


async def test_failed_login_redirects_with_error(client_app):
    resp = await client_app.post(
        "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/auth/login?error=invalid_credentials"


async def test_failed_login_unknown_user_redirects_with_error(client_app):
    resp = await client_app.post(
        "/auth/login", data={"username": "no-such-user", "password": "whatever"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/auth/login?error=invalid_credentials"


async def test_successful_login_redirects_with_303(client_app):
    resp = await login_session(client_app)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


async def test_failed_login_preserves_pending_return_to(client_app):
    """A failed login must not clear a pending `return_to` (only a
    successful `set_login()` clears the session) — otherwise a user who
    mistypes their password on the first attempt loses the authorize replay
    on their next (successful) attempt."""
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
        },
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"

    bad = await client_app.post(
        "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
    )
    assert bad.status_code == 303
    assert bad.headers["location"] == "/auth/login?error=invalid_credentials"

    good = await login_session(client_app)
    assert good.status_code == 303
    assert good.headers["location"].startswith("/oauth/authorize?")


# ---------------------------------------------------------------------------
# GET /oauth/device/verify
# ---------------------------------------------------------------------------


async def test_device_verify_page_requires_session(client_app):
    resp = await start_device_flow(client_app)
    assert resp.status_code == 200, resp.text
    user_code = resp.json()["user_code"]

    verify_resp = await client_app.get("/oauth/device/verify", params={"user_code": user_code})
    assert verify_resp.status_code == 302
    assert verify_resp.headers["location"] == "/auth/login"


async def test_device_verify_page_round_trips_through_login(client_app):
    resp = await start_device_flow(client_app)
    user_code = resp.json()["user_code"]

    verify_resp = await client_app.get("/oauth/device/verify", params={"user_code": user_code})
    assert verify_resp.status_code == 302
    assert verify_resp.headers["location"] == "/auth/login"

    login_resp = await login_session(client_app)
    assert login_resp.status_code == 303
    assert login_resp.headers["location"] == f"/oauth/device/verify?user_code={user_code}"


async def test_device_verify_page_renders_form_when_logged_in(client_app):
    resp = await start_device_flow(client_app)
    user_code = resp.json()["user_code"]

    await login_session(client_app)
    verify_resp = await client_app.get("/oauth/device/verify", params={"user_code": user_code})
    assert verify_resp.status_code == 200
    assert "text/html" in verify_resp.headers["content-type"]
    body = verify_resp.text
    assert f'value="{user_code}"' in body
    assert 'name="user_code"' in body
    assert 'value="approve"' in body
    assert 'value="deny"' in body


async def test_device_verify_page_escapes_user_code(client_app):
    await login_session(client_app)
    payload = '"><script>alert(1)</script>'
    resp = await client_app.get("/oauth/device/verify", params={"user_code": payload})
    assert resp.status_code == 200
    body = resp.text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


async def test_device_verify_page_preserves_normal_user_code(client_app):
    await login_session(client_app)
    resp = await client_app.get("/oauth/device/verify", params={"user_code": "WDJB-MJHT"})
    assert resp.status_code == 200
    assert 'value="WDJB-MJHT"' in resp.text
