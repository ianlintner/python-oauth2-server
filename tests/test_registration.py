import pytest
from httpx import ASGITransport, AsyncClient

from oauth2_server.app import create_app
from oauth2_server.config import Config
from tests.helpers import make_storage, post_token


@pytest.fixture
async def client(client_app):
    """Alias for `client_app`, matching the fixture name used by the RFC brief."""
    return client_app


async def test_registration_disabled_by_default_returns_403():
    """Production default: OAUTH2_DYNAMIC_REGISTRATION_ENABLED is unset/False,
    so /connect/register must refuse before any body parsing occurs.

    Built with an explicit Config/app instead of the `client`/`client_app`
    fixtures — `tests/conftest.py` enables the flag by default so the many
    other registration tests below don't each need to opt in.
    """
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
    )
    assert config.dynamic_registration_enabled is False
    app = create_app(config, await make_storage())
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://auth.example.com"
    ) as c:
        resp = await c.post("/connect/register", json={"redirect_uris": ["https://app.example/cb"]})
    assert resp.status_code == 403
    assert resp.json() == {
        "error": "access_denied",
        "error_description": "dynamic client registration is disabled",
    }


async def test_public_client_registration_with_none_auth_method_succeeds(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
        },
    )
    assert resp.status_code == 201
    assert resp.json().get("client_secret") in (None, "")


async def test_public_client_registration_with_client_credentials_is_rejected(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["client_credentials"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


async def test_confidential_registration_returns_secret(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["client_secret"]
    assert body["client_secret_expires_at"] == 0
    assert body["registration_access_token"]
    assert body["registration_client_uri"].startswith("https://auth.example.com")


async def test_registered_client_can_get_token(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "grant_types": ["client_credentials"],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()

    token_resp = await post_token(
        client,
        {"grant_type": "client_credentials"},
        basic_auth=(body["client_id"], body["client_secret"]),
    )
    assert token_resp.status_code == 200, token_resp.text


async def test_missing_redirect_uris_rejected(client):
    resp = await client.post("/connect/register", json={"redirect_uris": []})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


async def test_invalid_auth_method_rejected(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


async def test_missing_body_fields_return_400_not_500(client):
    resp = await client.post("/connect/register", json={})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


async def test_fragment_redirect_uri_rejected(client):
    resp = await client.post(
        "/connect/register",
        json={"redirect_uris": ["https://app.example/cb#frag"]},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


async def test_client_registration_includes_logout_fields(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "backchannel_logout_uri": "https://app.example/bc-logout",
            "backchannel_logout_session_required": True,
            "frontchannel_logout_uri": "https://app.example/fc-logout",
            "frontchannel_logout_session_required": True,
            "post_logout_redirect_uris": ["https://app.example/logged-out"],
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["backchannel_logout_uri"] == "https://app.example/bc-logout"
    assert body["backchannel_logout_session_required"] is True
    assert body["frontchannel_logout_uri"] == "https://app.example/fc-logout"
    assert body["frontchannel_logout_session_required"] is True
    assert body["post_logout_redirect_uris"] == ["https://app.example/logged-out"]
