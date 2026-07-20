"""GET /auth/login/{provider} + GET /auth/callback/{provider} — social login.

Ported from `crates/oauth2-social-login` (see
`.superpowers/sdd/research-social-login.md`); the Rust crate itself has
ZERO tests of any social flow (research doc `tests_to_port`), so every
provider-HTTP-mocked test here is new, using `httpx.MockTransport` on
`app.state.http_client` (the same client `routes/logout.py`'s back-channel
POSTs use — see `tests/test_logout.py` for the established pattern) to
route by URL to canned token/userinfo responses.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

import httpx
import pytest
from fastapi import Request
from fastapi.responses import ORJSONResponse

from oauth2_server.services.auth import is_safe_redirect
from tests.conftest import build_client_app


def _mock_transport(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=10)


def _state_from_location(location: str) -> str:
    return dict(parse_qsl(urlparse(location).query))["state"]


# ---------------------------------------------------------------------------
# is_safe_redirect — direct unit coverage (governs the callback's
# `return_to` fallback; ported from the Rust `redirect.rs` unit tests,
# research doc `tests_to_port`).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["/", "/profile", "/oauth/authorize?response_type=code&client_id=x"],
)
def test_is_safe_redirect_accepts_relative_paths(url):
    assert is_safe_redirect(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com",
        "http://evil.example.com/path",
        "//evil.example.com",
        "/\\evil.example.com",
        "",
        "relative/path",
        None,
    ],
)
def test_is_safe_redirect_rejects_unsafe_targets(url):
    assert is_safe_redirect(url) is False


# ---------------------------------------------------------------------------
# GET /auth/login/{provider}
# ---------------------------------------------------------------------------


async def test_login_redirects_to_provider_with_state():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:
        resp = await client.get("/auth/login/google", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth?")

        query = dict(parse_qsl(urlparse(location).query))
        assert query["state"]
        assert query["code_challenge_method"] == "S256"
        assert query["code_challenge"]
        assert query["client_id"] == "g-id"


async def test_login_unconfigured_provider_400(client_app):
    resp = await client_app.get("/auth/login/google", follow_redirects=False)
    assert resp.status_code == 400
    assert resp.json() == {
        "error": "provider_not_configured",
        "error_description": "Google login not configured",
    }


async def test_okta_auth0_stub_503(client_app):
    resp = await client_app.get("/auth/login/okta", follow_redirects=False)
    assert resp.status_code == 503
    assert resp.text == "Okta login not yet implemented"

    resp2 = await client_app.get("/auth/login/auth0", follow_redirects=False)
    assert resp2.status_code == 503
    assert resp2.text == "Auth0 login not yet implemented"


# ---------------------------------------------------------------------------
# GET /auth/callback/{provider} — CSRF/session validation
# ---------------------------------------------------------------------------


async def test_callback_missing_state_403(client_app):
    resp = await client_app.get("/auth/callback/google", follow_redirects=False)
    assert resp.status_code == 403
    assert resp.json() == {
        "error": "access_denied",
        "error_description": "CSRF state parameter is required",
    }


async def test_callback_state_mismatch_403():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:
        await client.get("/auth/login/google", follow_redirects=False)
        resp = await client.get(
            "/auth/callback/google",
            params={"state": "wrong-state", "code": "abc"},
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert resp.json() == {
            "error": "access_denied",
            "error_description": "CSRF token mismatch",
        }


async def test_callback_non_ascii_state_mismatch_403_not_500():
    """`_state_matches` compares byte-encoded operands (constant-time,
    Task 3c-4 fix) instead of `state != session_csrf` directly — a
    non-ASCII, attacker-controlled `state` value must still fall through to
    the normal 403 CSRF-mismatch path rather than an unhandled 500."""
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:
        await client.get("/auth/login/google", follow_redirects=False)
        resp = await client.get(
            "/auth/callback/google",
            params={"state": "wrong-stäte-é中", "code": "abc"},
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert resp.json() == {
            "error": "access_denied",
            "error_description": "CSRF token mismatch",
        }


async def test_callback_provider_mismatch_400():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:
        login_resp = await client.get("/auth/login/google", follow_redirects=False)
        state = _state_from_location(login_resp.headers["location"])

        resp = await client.get(
            "/auth/callback/microsoft",
            params={"state": state, "code": "abc"},
            follow_redirects=False,
        )
        assert resp.status_code == 400
        assert resp.json() == {
            "error": "invalid_request",
            "error_description": "Provider mismatch",
        }


# ---------------------------------------------------------------------------
# GET /auth/callback/{provider} — full flows
# ---------------------------------------------------------------------------


async def test_google_full_flow_provisions_user():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "oauth2.googleapis.com":
                assert request.method == "POST"
                return httpx.Response(200, json={"access_token": "google-access-token"})
            if request.url.host == "www.googleapis.com":
                assert request.headers.get("authorization") == "Bearer google-access-token"
                return httpx.Response(
                    200,
                    json={
                        "id": "1234567890",
                        "email": "alice@example.com",
                        "verified_email": True,
                        "name": "Alice",
                        "picture": "https://example.com/pic.png",
                    },
                )
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        login_resp = await client.get("/auth/login/google", follow_redirects=False)
        state = _state_from_location(login_resp.headers["location"])

        resp = await client.get(
            "/auth/callback/google",
            params={"state": state, "code": "abc123"},
            follow_redirects=False,
        )
        assert resp.status_code == 302, resp.text
        assert resp.headers["location"] == "/profile"

        user = await client.storage.get_user_by_username("google:1234567890")
        assert user is not None
        assert user.email == "alice@example.com"
        assert user.role == "user"


async def test_github_email_fallback():
    async with build_client_app(
        {"github_client_id": "gh-id", "github_client_secret": "gh-secret"}
    ) as client:
        seen_paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_paths.append(request.url.path)
            if request.url.host == "github.com" and request.url.path == "/login/oauth/access_token":
                return httpx.Response(200, json={"access_token": "gh-access-token"})
            if request.url.host == "api.github.com" and request.url.path == "/user":
                assert request.headers.get("user-agent") == "python_oauth2_server"
                return httpx.Response(
                    200,
                    json={
                        "id": 555,
                        "email": None,
                        "name": "Bob",
                        "avatar_url": "https://example.com/bob.png",
                    },
                )
            if request.url.host == "api.github.com" and request.url.path == "/user/emails":
                assert request.headers.get("user-agent") == "python_oauth2_server"
                return httpx.Response(
                    200,
                    json=[
                        {"email": "secondary@example.com", "primary": False, "verified": True},
                        {"email": "bob@example.com", "primary": True, "verified": True},
                    ],
                )
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        login_resp = await client.get("/auth/login/github", follow_redirects=False)
        state = _state_from_location(login_resp.headers["location"])

        resp = await client.get(
            "/auth/callback/github",
            params={"state": state, "code": "xyz"},
            follow_redirects=False,
        )
        assert resp.status_code == 302, resp.text
        assert "/user/emails" in seen_paths

        user = await client.storage.get_user_by_username("github:555")
        assert user is not None
        assert user.email == "bob@example.com"


async def test_github_no_primary_email_provider_error():
    async with build_client_app(
        {"github_client_id": "gh-id", "github_client_secret": "gh-secret"}
    ) as client:

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "github.com":
                return httpx.Response(200, json={"access_token": "gh-access-token"})
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 777, "email": None})
            if request.url.path == "/user/emails":
                return httpx.Response(200, json=[{"email": "x@example.com", "primary": False}])
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        login_resp = await client.get("/auth/login/github", follow_redirects=False)
        state = _state_from_location(login_resp.headers["location"])

        resp = await client.get(
            "/auth/callback/github",
            params={"state": state, "code": "xyz"},
            follow_redirects=False,
        )
        assert resp.status_code == 400
        assert resp.json() == {"error": "provider_error", "error_description": "No email found"}


async def test_github_unverified_primary_email_provider_error():
    """A `primary: true` entry that GitHub has not verified must NOT be
    provisioned — `session["email"]` can grant admin via
    `OAUTH2_ADMIN_EMAILS` (routes/admin/guard.py), so an unverified email
    is treated the same as no email at all (falls through to the existing
    "No email found" 400), rather than trusting the provider's `primary`
    flag alone."""
    async with build_client_app(
        {"github_client_id": "gh-id", "github_client_secret": "gh-secret"}
    ) as client:

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "github.com":
                return httpx.Response(200, json={"access_token": "gh-access-token"})
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 888, "email": None})
            if request.url.path == "/user/emails":
                return httpx.Response(
                    200,
                    json=[
                        {"email": "unverified@example.com", "primary": True, "verified": False},
                        {"email": "other@example.com", "primary": False, "verified": True},
                    ],
                )
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        login_resp = await client.get("/auth/login/github", follow_redirects=False)
        state = _state_from_location(login_resp.headers["location"])

        resp = await client.get(
            "/auth/callback/github",
            params={"state": state, "code": "xyz"},
            follow_redirects=False,
        )
        assert resp.status_code == 400
        assert resp.json() == {"error": "provider_error", "error_description": "No email found"}

        user = await client.storage.get_user_by_username("github:888")
        assert user is None


async def test_github_direct_user_email_ignored_still_resolves_via_emails_endpoint():
    """Even when GitHub's `/user` response includes a top-level `email`
    field directly (a public email, not guaranteed verified by the API
    contract), the port must still resolve the provisioned address via the
    authenticated `/user/emails` verified-primary lookup rather than
    trusting `/user`'s `email` field as-is."""
    async with build_client_app(
        {"github_client_id": "gh-id", "github_client_secret": "gh-secret"}
    ) as client:
        seen_paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_paths.append(request.url.path)
            if request.url.host == "github.com":
                return httpx.Response(200, json={"access_token": "gh-access-token"})
            if request.url.path == "/user":
                return httpx.Response(
                    200, json={"id": 999, "email": "public@example.com", "name": "Erin"}
                )
            if request.url.path == "/user/emails":
                return httpx.Response(
                    200,
                    json=[{"email": "erin@example.com", "primary": True, "verified": True}],
                )
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        login_resp = await client.get("/auth/login/github", follow_redirects=False)
        state = _state_from_location(login_resp.headers["location"])

        resp = await client.get(
            "/auth/callback/github",
            params={"state": state, "code": "xyz"},
            follow_redirects=False,
        )
        assert resp.status_code == 302, resp.text
        assert "/user/emails" in seen_paths

        user = await client.storage.get_user_by_username("github:999")
        assert user is not None
        assert user.email == "erin@example.com"


async def test_google_unverified_email_provider_error():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "oauth2.googleapis.com":
                return httpx.Response(200, json={"access_token": "tok"})
            if request.url.host == "www.googleapis.com":
                return httpx.Response(
                    200,
                    json={
                        "id": "666",
                        "email": "unverified@example.com",
                        "verified_email": False,
                    },
                )
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        login_resp = await client.get("/auth/login/google", follow_redirects=False)
        state = _state_from_location(login_resp.headers["location"])

        resp = await client.get(
            "/auth/callback/google",
            params={"state": state, "code": "c"},
            follow_redirects=False,
        )
        assert resp.status_code == 400
        assert resp.json() == {
            "error": "provider_error",
            "error_description": "Google email not verified",
        }

        user = await client.storage.get_user_by_username("google:666")
        assert user is None


async def test_existing_social_user_not_duplicated():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "oauth2.googleapis.com":
                return httpx.Response(200, json={"access_token": "tok"})
            if request.url.host == "www.googleapis.com":
                return httpx.Response(
                    200,
                    json={"id": "999", "email": "carol@example.com", "verified_email": True},
                )
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        for _ in range(2):
            login_resp = await client.get("/auth/login/google", follow_redirects=False)
            state = _state_from_location(login_resp.headers["location"])
            resp = await client.get(
                "/auth/callback/google",
                params={"state": state, "code": "c"},
                follow_redirects=False,
            )
            assert resp.status_code == 302, resp.text

        users = await client.storage.list_all_users()
        matching = [u for u in users if u.username == "google:999"]
        assert len(matching) == 1


async def test_callback_circuit_breaker_opens_after_failures():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "oauth2.googleapis.com":
                return httpx.Response(200, json={"access_token": "tok"})
            if request.url.host == "www.googleapis.com":
                return httpx.Response(500, text="boom")
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        responses = []
        for _ in range(6):
            login_resp = await client.get("/auth/login/google", follow_redirects=False)
            state = _state_from_location(login_resp.headers["location"])
            resp = await client.get(
                "/auth/callback/google",
                params={"state": state, "code": "c"},
                follow_redirects=False,
            )
            responses.append(resp)

        # First 5 failures are ordinary userinfo-fetch errors ...
        for resp in responses[:5]:
            assert resp.status_code == 400
            assert resp.json()["error"] == "provider_error"

        # ... the 6th sees the breaker already open, before even trying.
        assert responses[5].status_code == 400
        assert responses[5].json() == {
            "error": "provider_unavailable",
            "error_description": "Google circuit breaker open",
        }


async def test_callback_safe_return_to_redirect():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:

        @client.app.get("/__test_set_unsafe_return_to")
        async def _set_return_to(request: Request) -> ORJSONResponse:
            request.session["return_to"] = "https://evil.example.com/steal"
            return ORJSONResponse({"ok": True})

        await client.get("/__test_set_unsafe_return_to")

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "oauth2.googleapis.com":
                return httpx.Response(200, json={"access_token": "tok"})
            if request.url.host == "www.googleapis.com":
                return httpx.Response(
                    200,
                    json={"id": "42", "email": "dave@example.com", "verified_email": True},
                )
            return httpx.Response(404)

        client.app.state.http_client = _mock_transport(handler)

        login_resp = await client.get("/auth/login/google", follow_redirects=False)
        state = _state_from_location(login_resp.headers["location"])

        resp = await client.get(
            "/auth/callback/google",
            params={"state": state, "code": "c"},
            follow_redirects=False,
        )
        assert resp.status_code == 302, resp.text
        assert resp.headers["location"] == "/profile"


# ---------------------------------------------------------------------------
# Microsoft / Azure — no PKCE, tenant-scoped URLs, Azure's config alias
# ---------------------------------------------------------------------------


async def test_microsoft_login_redirects_without_pkce():
    async with build_client_app(
        {
            "microsoft_client_id": "ms-id",
            "microsoft_client_secret": "ms-secret",
            "microsoft_tenant_id": "contoso",
        }
    ) as client:
        resp = await client.get("/auth/login/microsoft", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith(
            "https://login.microsoftonline.com/contoso/oauth2/v2.0/authorize?"
        )
        query = dict(parse_qsl(urlparse(location).query))
        assert "code_challenge" not in query
        assert query["state"]


async def test_azure_falls_back_to_microsoft_credentials():
    async with build_client_app(
        {
            "microsoft_client_id": "ms-id",
            "microsoft_client_secret": "ms-secret",
            "azure_tenant_id": "contoso-azure",
        }
    ) as client:
        resp = await client.get("/auth/login/azure", follow_redirects=False)
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith(
            "https://login.microsoftonline.com/contoso-azure/oauth2/v2.0/authorize?"
        )
        query = dict(parse_qsl(urlparse(location).query))
        assert query["client_id"] == "ms-id"


async def test_azure_unconfigured_without_microsoft_fallback_400(client_app):
    resp = await client_app.get("/auth/login/azure", follow_redirects=False)
    assert resp.status_code == 400
    assert resp.json() == {
        "error": "provider_not_configured",
        "error_description": "Azure login not configured",
    }
