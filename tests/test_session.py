from __future__ import annotations

from tests.conftest import build_client_app


async def test_session_max_age_is_configured_not_starlette_default():
    async with build_client_app({"session_max_age_secs": 3600}) as client:
        resp = await client.post(
            "/auth/login", data={"username": "user_rfc", "password": "password123"}
        )
        cookie = resp.headers["set-cookie"]
        assert "oauth2_session=" in cookie
        assert "Max-Age=3600;" in cookie
        assert "Max-Age=1209600;" not in cookie
