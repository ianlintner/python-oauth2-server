"""Opaque access-token mode (`Config(access_tokens_opaque=True)`)."""

import base64

import jwt
import pytest

from tests.conftest import build_client_app
from tests.helpers import post_token
from tests.test_token_endpoint import run_code_flow


@pytest.fixture
async def opaque_client_app():
    async with build_client_app({"access_tokens_opaque": True}) as c:
        yield c


async def post_introspect(client_app, token: str, basic_auth: tuple[str, str] | None):
    headers = {}
    if basic_auth is not None:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    return await client_app.post("/oauth/introspect", data={"token": token}, headers=headers)


async def post_revoke(client_app, token: str, basic_auth: tuple[str, str] | None):
    headers = {}
    if basic_auth is not None:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    return await client_app.post("/oauth/revoke", data={"token": token}, headers=headers)


async def test_opaque_access_tokens_issue_and_introspect_successfully(opaque_client_app):
    resp = await post_token(
        opaque_client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    assert "." not in access_token
    with pytest.raises(jwt.PyJWTError):
        jwt.get_unverified_header(access_token)

    introspect_resp = await post_introspect(
        opaque_client_app, access_token, basic_auth=("client1", "s3cret")
    )
    assert introspect_resp.status_code == 200, introspect_resp.text
    body = introspect_resp.json()
    assert body["active"] is True
    assert body["client_id"] == "client1"
    assert body["scope"]
    assert body["iss"] == "https://auth.example.com"
    assert body["jti"]
    assert body["nbf"] is not None
    assert body["nbf"] <= body["iat"]


async def test_opaque_token_userinfo_works(opaque_client_app):
    resp, _code = await run_code_flow(opaque_client_app, scope="openid email profile")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]
    assert "." not in access_token

    userinfo_resp = await opaque_client_app.get(
        "/oauth/userinfo", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert userinfo_resp.status_code == 200, userinfo_resp.text
    body = userinfo_resp.json()
    assert body["sub"] == "u1"
    assert body["email"]


async def test_opaque_token_revocation(opaque_client_app):
    resp = await post_token(
        opaque_client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    revoke_resp = await post_revoke(
        opaque_client_app, access_token, basic_auth=("client1", "s3cret")
    )
    assert revoke_resp.status_code == 200

    introspect_resp = await post_introspect(
        opaque_client_app, access_token, basic_auth=("client1", "s3cret")
    )
    assert introspect_resp.json() == {"active": False}
