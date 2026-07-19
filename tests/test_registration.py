import pytest

from tests.helpers import post_token


@pytest.fixture
async def client(client_app):
    """Alias for `client_app`, matching the fixture name used by the RFC brief."""
    return client_app


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
