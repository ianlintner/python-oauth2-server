import secrets
from urllib.parse import parse_qs, urlparse

from tests.helpers import login_session, reseed_client, seed_client


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


# --- return_to staleness hardening (login-CSRF) -------------------------------
#
# GET /oauth/authorize stores `return_to` (+ `return_to_ts`) in the session
# before redirecting to /auth/login. A stale return_to from an abandoned
# (possibly attacker-initiated) authorization request must NOT be replayed on
# a later unrelated login — only a fresh, timestamped return_to is honored.

_AUTHORIZE_PARAMS = {
    "response_type": "code",
    "client_id": "client1",
    "redirect_uri": "https://a.example/cb",
    "scope": "read",
}


async def test_fresh_return_to_is_replayed_after_login(app_with_session):
    # Unauthenticated authorize request -> redirected to login, return_to saved.
    resp = await app_with_session.get("/oauth/authorize", params=_AUTHORIZE_PARAMS)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"

    # Logging in promptly replays the pending authorize URL.
    resp = await login_session(app_with_session)
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/oauth/authorize?")


async def test_stale_return_to_is_not_replayed_after_login(app_with_session, monkeypatch):
    import oauth2_server.routes.login as login_routes

    resp = await app_with_session.get("/oauth/authorize", params=_AUTHORIZE_PARAMS)
    assert resp.status_code == 302

    # Advance the clock past the freshness window, as seen by the login route.
    real_time = login_routes.time.time
    monkeypatch.setattr(
        login_routes.time,
        "time",
        lambda: real_time() + login_routes.RETURN_TO_MAX_AGE_SECS + 1,
    )

    resp = await login_session(app_with_session)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/", "stale return_to must not be replayed"


async def test_login_without_pending_authorize_does_not_replay(app_with_session):
    # A login not initiated by an authorize redirect has no return_to to honor.
    resp = await login_session(app_with_session)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"


async def test_authorize_requires_authorization_code_grant(app_with_session):
    await reseed_client(app_with_session, grant_types=["client_credentials"])
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
    assert q["error"] == ["unauthorized_client"]
    assert q["state"] == ["xyz"]
    assert "iss" in q
