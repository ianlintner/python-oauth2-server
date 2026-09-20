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
            "token_endpoint_auth_method": "bogus_method",
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


async def test_invalid_scheme_backchannel_logout_uri_rejected(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "backchannel_logout_uri": "gopher://app.example/bc-logout",
        },
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_client_metadata"
    assert body["error_description"] == (
        "backchannel_logout_uri must be an absolute http(s) URL without fragment"
    )


async def test_fragment_frontchannel_logout_uri_rejected(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "frontchannel_logout_uri": "https://app.example/fc-logout#frag",
        },
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_client_metadata"
    assert body["error_description"] == (
        "frontchannel_logout_uri must be an absolute http(s) URL without fragment"
    )


async def test_invalid_scheme_post_logout_redirect_uri_rejected(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "post_logout_redirect_uris": ["gopher://app.example/logged-out"],
        },
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_client_metadata"
    assert body["error_description"] == (
        "post_logout_redirect_uris must be a list of absolute http(s) URLs without fragment"
    )


async def test_fragment_post_logout_redirect_uri_rejected(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "post_logout_redirect_uris": ["https://app.example/logged-out#frag"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


async def test_valid_logout_uris_still_accepted(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "backchannel_logout_uri": "https://app.example/bc-logout",
            "frontchannel_logout_uri": "https://app.example/fc-logout",
            "post_logout_redirect_uris": ["https://app.example/logged-out"],
        },
    )
    assert resp.status_code == 201, resp.text


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


# --- RFC 8705 mTLS client authentication ---


async def test_registration_accepts_tls_client_auth_with_subject_dn(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_certificate_subject_dn": "CN=svc,O=Example",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["token_endpoint_auth_method"] == "tls_client_auth"
    assert body["tls_client_certificate_subject_dn"] == "CN=svc,O=Example"

    stored = await client.storage.get_client(body["client_id"])
    assert stored.tls_client_certificate_subject_dn == "CN=svc,O=Example"


@pytest.mark.parametrize("blank", ["   ", "\t", "\n "])
async def test_registration_rejects_blank_subject_dn(client, blank):
    """An exactly-empty registered DN is the documented "any certificate"
    wildcard; a whitespace-only one is almost certainly a mistake, and would
    read as that wildcard if anything ever trimmed it. Refuse it at the door."""
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_certificate_subject_dn": blank,
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json() == {
        "error": "invalid_client_metadata",
        "error_description": "tls_client_certificate_subject_dn must not be blank",
    }


async def test_registration_allows_empty_subject_dn(client):
    """The empty string stays legal — it is the RFC 8705 "any certificate the
    proxy vouched for" registration."""
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "tls_client_auth",
            "tls_client_certificate_subject_dn": "",
        },
    )
    assert resp.status_code == 201, resp.text


async def test_registration_self_signed_requires_jwks(client):
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "self_signed_tls_client_auth",
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json() == {
        "error": "invalid_client_metadata",
        "error_description": "self_signed_tls_client_auth requires jwks or jwks_uri",
    }


async def test_registration_self_signed_with_jwks_succeeds(client):
    jwks = {"keys": [{"kty": "RSA", "n": "abc", "e": "AQAB", "x5t#S256": "thumb"}]}
    resp = await client.post(
        "/connect/register",
        json={
            "redirect_uris": ["https://app.example/cb"],
            "token_endpoint_auth_method": "self_signed_tls_client_auth",
            "jwks": jwks,
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["jwks"] == jwks
    # Not registered, so not echoed (RFC 7591 §3.2.1).
    assert "tls_client_certificate_subject_dn" not in resp.json()
