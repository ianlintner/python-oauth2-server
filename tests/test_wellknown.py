import base64

from tests.test_token_endpoint import run_code_flow


async def test_rfc8414_oauth_authorization_server_well_known_returns_metadata(client_app):
    resp = await client_app.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issuer"] == "https://auth.example.com"
    assert body["authorization_endpoint"] == "https://auth.example.com/oauth/authorize"
    assert body["token_endpoint"] == "https://auth.example.com/oauth/token"
    assert body["authorization_response_iss_parameter_supported"] is True


async def test_rfc8414_both_well_known_paths_return_same_response(client_app):
    resp1 = await client_app.get("/.well-known/oauth-authorization-server")
    resp2 = await client_app.get("/.well-known/openid-configuration")
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.content == resp2.content


async def test_discovery_includes_iss_parameter_supported(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["authorization_response_iss_parameter_supported"] is True


async def test_discovery_advertises_none_auth_method(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert "none" in resp.json()["token_endpoint_auth_methods_supported"]


async def test_discovery_advertises_par(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["pushed_authorization_request_endpoint"] == "https://auth.example.com/oauth/par"
    assert body["require_pushed_authorization_requests"] is False
    assert body["request_uri_parameter_supported"] is True
    assert body["request_parameter_supported"] is False


async def test_jwks_returns_empty_keys(client_app):
    resp = await client_app.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert resp.json() == {"keys": []}


async def test_discovery_includes_session_management_fields(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["end_session_endpoint"] == "https://auth.example.com/oauth/logout"
    assert body["check_session_iframe"] == "https://auth.example.com/oauth/check_session"
    assert body["backchannel_logout_supported"] is True
    assert body["backchannel_logout_session_supported"] is True
    assert body["frontchannel_logout_supported"] is True
    assert body["frontchannel_logout_session_supported"] is True


async def _get_userinfo(client_app, access_token: str | None, *, in_query: bool = False):
    if in_query:
        return await client_app.get("/oauth/userinfo", params={"access_token": access_token})
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    return await client_app.get("/oauth/userinfo", headers=headers)


async def test_userinfo_returns_real_claims_for_auth_code_flow(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email profile")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    info_resp = await _get_userinfo(client_app, access_token)
    assert info_resp.status_code == 200, info_resp.text
    body = info_resp.json()
    assert body["sub"] == "u1"
    assert body["email"] == "user_rfc@example.test"
    assert body["preferred_username"] == "user_rfc"


async def test_userinfo_returns_real_email_when_email_scope_requested(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    info_resp = await _get_userinfo(client_app, access_token)
    assert info_resp.status_code == 200, info_resp.text
    body = info_resp.json()
    assert body["email"] == "user_rfc@example.test"
    assert "preferred_username" not in body


async def test_userinfo_rejects_token_in_query(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    info_resp = await _get_userinfo(client_app, access_token, in_query=True)
    assert info_resp.status_code == 401
    assert info_resp.headers["www-authenticate"] == "Bearer"


async def test_userinfo_rejects_revoked_token(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    basic = base64.b64encode(b"client1:s3cret").decode()
    revoke = await client_app.post(
        "/oauth/revoke",
        data={"token": access_token},
        headers={"Authorization": f"Basic {basic}"},
    )
    assert revoke.status_code == 200, revoke.text

    info_resp = await _get_userinfo(client_app, access_token)
    assert info_resp.status_code == 401
    assert info_resp.json()["error"] == "invalid_token"


async def test_userinfo_foreign_jwt_rejected_not_500(client_app):
    """Verify that a validly-signed but foreign-shaped JWT returns 401, not 500.

    A JWT signed with the correct secret but with a payload that doesn't match
    the Claims model (e.g., minted by another system sharing the secret) should
    raise pydantic.ValidationError, which must be caught and treated as an
    invalid token (storage lookup path) rather than allowed to bubble up as a 500.
    """
    import jwt as pyjwt

    jwt_secret = "unit-test-secret-not-for-production-0123456789abcdef"
    foreign = pyjwt.encode(
        {"sub": "u1", "iss": "https://auth.example.com", "exp": 9999999999, "iat": 1},
        jwt_secret,
        algorithm="HS256",
    )
    resp = await _get_userinfo(client_app, foreign)
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"
