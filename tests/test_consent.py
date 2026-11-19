"""User consent in the authorization flow (RFC 6749 §3.1, OIDC Core §3.1.2.4).

`GET /oauth/authorize` parks the validated request and renders a consent page
unless the user already approved the requested scopes for the client;
`POST /oauth/consent` resumes only the parked request.
"""

from urllib.parse import parse_qs, urlparse

import pytest

from oauth2_server.models import Grant
from tests.conftest import build_client_app
from tests.helpers import (
    PKCE_CHALLENGE,
    approve_consent,
    login_session,
    make_storage,
    seed_client,
    seed_user,
)

REDIRECT = "https://a.example/cb"


def _params(**overrides):
    params = {
        "response_type": "code",
        "client_id": "client1",
        "redirect_uri": REDIRECT,
        "scope": "openid email",
        "state": "s",
        "code_challenge": PKCE_CHALLENGE,
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return {k: v for k, v in params.items() if v is not None}


@pytest.fixture
async def consent_app():
    """The standard app, but with NO operator-trusted clients."""
    async with build_client_app({"consent_trusted_client_ids": []}) as c:
        yield c


async def _authorize(client, **overrides):
    return await client.get("/oauth/authorize", params=_params(**overrides))


def _redirect_query(resp):
    assert resp.status_code == 302, resp.text
    location = urlparse(resp.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    return parse_qs(location.query)


async def test_authorize_without_prior_consent_renders_consent_page(consent_app):
    await login_session(consent_app)
    resp = await _authorize(consent_app)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "location" not in resp.headers
    assert "test-client" in resp.text
    assert "openid" in resp.text and "email" in resp.text
    assert "profile" not in resp.text
    # The page never carries the request itself, only an opaque handle.
    assert REDIRECT not in resp.text
    assert PKCE_CHALLENGE not in resp.text


async def test_authorize_consent_post_issues_code(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app)
    resp = await approve_consent(consent_app, page)
    query = _redirect_query(resp)
    assert query["state"] == ["s"]
    assert "code" in query
    assert query["iss"] == ["https://auth.example.com"]
    grant = await consent_app.storage.get_grant("u1", "client1")
    assert grant is not None
    assert set(grant.scope.split()) == {"openid", "email"}


async def test_second_request_with_covering_grant_skips_consent(consent_app):
    await login_session(consent_app)
    await approve_consent(consent_app, await _authorize(consent_app))
    resp = await _authorize(consent_app, scope="email")
    assert "code" in _redirect_query(resp)


async def test_scope_widening_asks_again_for_only_the_additional_scope(consent_app):
    await login_session(consent_app)
    await approve_consent(consent_app, await _authorize(consent_app))
    page = await _authorize(consent_app, scope="openid email profile")
    assert page.status_code == 200
    assert "profile" in page.text
    assert "email" not in page.text
    resp = await approve_consent(consent_app, page)
    assert "code" in _redirect_query(resp)
    grant = await consent_app.storage.get_grant("u1", "client1")
    assert set(grant.scope.split()) == {"openid", "email", "profile"}


async def test_authorize_prompt_none_without_grant_returns_consent_required(consent_app):
    await login_session(consent_app)
    resp = await _authorize(consent_app, prompt="none")
    query = _redirect_query(resp)
    assert query["error"] == ["consent_required"]
    assert query["state"] == ["s"]
    assert "code" not in query
    assert await consent_app.storage.get_grant("u1", "client1") is None


async def test_authorize_prompt_none_with_grant_issues_code(consent_app):
    await login_session(consent_app)
    await approve_consent(consent_app, await _authorize(consent_app))
    resp = await _authorize(consent_app, prompt="none")
    assert "code" in _redirect_query(resp)


async def test_authorize_prompt_consent_with_existing_grant_shows_page(consent_app):
    await login_session(consent_app)
    await approve_consent(consent_app, await _authorize(consent_app))
    resp = await _authorize(consent_app, prompt="consent")
    assert resp.status_code == 200
    assert "location" not in resp.headers
    assert "openid" in resp.text and "email" in resp.text


async def test_consent_post_rejects_changed_redirect_uri(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app)
    resp = await approve_consent(consent_app, page, redirect_uri="https://evil.example/cb")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert "location" not in resp.headers
    assert await consent_app.storage.get_grant("u1", "client1") is None


async def test_consent_post_rejects_changed_scope(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app)
    resp = await approve_consent(consent_app, page, scope="openid email profile")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert "location" not in resp.headers


async def test_consent_post_with_matching_echoed_fields_is_accepted(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app)
    resp = await approve_consent(consent_app, page, redirect_uri=REDIRECT, scope="openid email")
    assert "code" in _redirect_query(resp)


async def test_consent_deny_redirects_access_denied_and_stores_nothing(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app)
    resp = await approve_consent(consent_app, page, action="deny")
    query = _redirect_query(resp)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["s"]
    assert "code" not in query
    assert await consent_app.storage.get_grant("u1", "client1") is None


async def test_consent_post_requires_matching_csrf_token(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app)
    resp = await approve_consent(consent_app, page, csrf_token="wrong")
    assert resp.status_code == 400
    # A bad token does not burn the pending request.
    assert "code" in _redirect_query(await approve_consent(consent_app, page))


async def test_consent_handle_is_single_use(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app)
    assert "code" in _redirect_query(await approve_consent(consent_app, page))
    replay = await approve_consent(consent_app, page)
    assert replay.status_code == 400


async def test_consent_post_without_session_is_rejected(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app)
    consent_app.cookies.clear()
    resp = await approve_consent(consent_app, page)
    assert resp.status_code == 401


async def test_consent_handle_is_bound_to_the_user(consent_app):
    await seed_user_two(consent_app)
    await login_session(consent_app)
    page = await _authorize(consent_app)
    await login_session(consent_app, username="other", password="password123")
    resp = await approve_consent(consent_app, page)
    assert resp.status_code == 400
    assert await consent_app.storage.get_grant("other-id", "client1") is None


async def seed_user_two(client_app):
    from oauth2_server import security
    from oauth2_server.models import User

    await client_app.storage.save_user(
        User(
            id="other-id",
            username="other",
            email="other@example.test",
            password_hash=security.hash_password("password123"),
        )
    )


async def test_unknown_consent_handle_is_rejected(consent_app):
    await login_session(consent_app)
    resp = await consent_app.post(
        "/oauth/consent", data={"handle": "nope", "csrf_token": "x", "action": "approve"}
    )
    assert resp.status_code == 400


async def test_consent_revalidates_client_state_on_post(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app)
    await consent_app.storage.set_client_enabled("client1", False)
    resp = await approve_consent(consent_app, page)
    assert resp.status_code == 401
    assert await consent_app.storage.get_grant("u1", "client1") is None


async def test_consent_page_escapes_client_name(consent_app):
    await seed_client(
        consent_app.storage,
        client_id="evil-name",
        name='<script>alert("x")</script>',
        redirect_uris='["https://a.example/cb"]',
    )
    await login_session(consent_app)
    page = await _authorize(consent_app, client_id="evil-name")
    assert page.status_code == 200
    assert "<script>" not in page.text
    assert "&lt;script&gt;" in page.text


async def test_unauthenticated_authorize_still_goes_to_login(consent_app):
    resp = await _authorize(consent_app)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"


async def test_trusted_client_skips_consent():
    async with build_client_app({"consent_trusted_client_ids": ["client1"]}) as c:
        await login_session(c)
        resp = await _authorize(c)
        assert "code" in _redirect_query(resp)
        assert await c.storage.get_grant("u1", "client1") is None


async def test_trusted_client_still_gets_other_validation():
    async with build_client_app({"consent_trusted_client_ids": ["client1"]}) as c:
        await login_session(c)
        resp = await _authorize(c, scope="admin")
        assert _redirect_query(resp)["error"] == ["invalid_scope"]


async def test_hybrid_flow_resumes_through_consent(consent_app):
    await login_session(consent_app)
    page = await _authorize(consent_app, response_type="code id_token", nonce="n1")
    assert page.status_code == 200
    resp = await approve_consent(consent_app, page)
    assert resp.status_code == 302
    fragment = parse_qs(urlparse(resp.headers["location"]).fragment)
    assert "code" in fragment and "id_token" in fragment


async def test_trusted_client_ids_parse_from_comma_separated_string():
    from oauth2_server.config import Config

    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        consent_trusted_client_ids="a, b ,,c",
    )
    assert config.consent_trusted_client_ids == ["a", "b", "c"]
    assert (
        Config(
            jwt_secret="unit-test-secret-not-for-production-0123456789abcdef"
        ).consent_trusted_client_ids
        == []
    )


# -- grant storage ----------------------------------------------------------


async def test_grant_storage_roundtrip_upsert_and_delete():
    storage = await make_storage()
    await seed_user(storage)
    await seed_client(storage)
    assert await storage.get_grant("u1", "client1") is None

    await storage.save_grant(Grant(id="g1", user_id="u1", client_id="client1", scope="openid"))
    got = await storage.get_grant("u1", "client1")
    assert got is not None and got.scope == "openid" and got.id == "g1"

    # Upsert on (user_id, client_id): scope changes, identity and created_at stay.
    await storage.save_grant(
        Grant(id="g2", user_id="u1", client_id="client1", scope="openid email")
    )
    updated = await storage.get_grant("u1", "client1")
    assert updated is not None and updated.scope == "openid email"
    assert updated.id == "g1"
    assert updated.created_at == got.created_at

    assert await storage.get_grant("u1", "other-client") is None
    await storage.delete_grant("u1", "client1")
    assert await storage.get_grant("u1", "client1") is None
