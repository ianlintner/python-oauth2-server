import secrets
from urllib.parse import parse_qs, urlparse

from tests.helpers import login_session, seed_client


async def test_rfc9207_iss_included_in_authorization_response(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "state": "xyz",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["iss"] == ["https://auth.example.com"]
    assert q["state"] == ["xyz"]
    assert "code" in q


async def test_unregistered_redirect_uri_never_redirects(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://evil.example/cb",
        },
    )
    assert resp.status_code == 400


async def test_public_client_requires_s256_pkce(app_with_session):
    await seed_client(
        app_with_session.storage,
        client_id="public-client",
        client_secret="",
        redirect_uris='["https://pub.example/cb"]',
        token_endpoint_auth_method="none",
    )
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "public-client",
            "redirect_uri": "https://pub.example/cb",
            "scope": "read",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["invalid_request"]


async def test_plain_pkce_method_rejected(app_with_session):
    await login_session(app_with_session)
    challenge = secrets.token_urlsafe(32)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "plain",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["invalid_request"]


async def test_implicit_response_type_rejected(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "token",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["unsupported_response_type"]
