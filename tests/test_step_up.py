"""RFC 9470 `acr_values` step-up + the session `acr`/`amr` it is checked against.

Rust parity (`crates/oauth2-actix/src/handlers/oauth.rs::authorize`): a request
carrying `acr_values` is satisfied iff the session's stamped `acr` is EXACTLY
one of the space-separated requested values; otherwise the authorization fails
with `insufficient_user_authentication`. The check runs after the login gate
(an unauthenticated user is sent to `/auth/login` first, so the error can never
be used as an "is anyone logged in / at what acr" oracle before authentication)
and after scope validation.

Divergence 42: the `acr` stamped at login is config-driven
(`config.acr_values_supported[0]`, env `OAUTH2_ACR_VALUES_SUPPORTED`) rather
than a hardcoded constant, and `amr` distinguishes the authentication method
(`["pwd"]` for password login, `["fed"]` for social/federated login).

Divergence 37: the step-up error goes through the mode-aware builder, so
`response_mode=fragment`/`form_post` are honored (Rust builds this particular
error as a plain query redirect).

Divergence 40: the hybrid front-channel id_token carries the session's
`acr`/`amr`/`auth_time`.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse, urlsplit

import httpx
import jwt
import pytest

from oauth2_server.config import Config
from tests.conftest import build_client_app
from tests.helpers import PKCE_CHALLENGE, login_session

BRONZE = "urn:mace:incommon:iap:bronze"
SILVER = "urn:mace:incommon:iap:silver"
ISSUER = "https://auth.example.com"
REDIRECT_URI = "https://a.example/cb"

STEP_UP_ERROR = "insufficient_user_authentication"
STEP_UP_DESCRIPTION = "Authentication Context Class does not satisfy acr_values"


@pytest.fixture
async def client_app_silver():
    async with build_client_app({"acr_values_supported": [SILVER, BRONZE]}) as c:
        yield c


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.rstrip(b"=").decode()


def _basic_header(client_id: str, client_secret: str) -> dict:
    raw = f"{client_id}:{client_secret}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


def _authorize_params(**overrides) -> dict:
    params = {
        "response_type": "code",
        "client_id": "client1",
        "code_challenge": PKCE_CHALLENGE,
        "code_challenge_method": "S256",
        "redirect_uri": REDIRECT_URI,
        "scope": "read",
    }
    params.update(overrides)
    return {k: v for k, v in params.items() if v is not None}


def _query(resp) -> dict[str, list[str]]:
    return parse_qs(urlparse(resp.headers["location"]).query)


def _fragment(resp) -> dict[str, list[str]]:
    split = urlsplit(resp.headers["location"])
    assert split.query == "", "fragment mode must not use the query channel"
    return parse_qs(split.fragment)


def _unverified(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


# --- config -------------------------------------------------------------------


def test_acr_values_supported_config_default():
    config = Config(jwt_secret="unit-test-secret-not-for-production-0123456789abcdef")
    assert config.acr_values_supported == [BRONZE]


def test_acr_values_supported_config_splits_comma_string():
    # Env (`OAUTH2_ACR_VALUES_SUPPORTED`) arrives as a comma-separated string,
    # like `rar_types_supported`; `NoDecode` + a before-validator keeps it out
    # of pydantic-settings' JSON list decoding.
    config = Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        acr_values_supported=f"{SILVER}, {BRONZE}",
    )
    assert config.acr_values_supported == [SILVER, BRONZE]


# --- login stamps acr/amr -----------------------------------------------------


async def test_login_stamps_acr_and_amr(client_app):
    await login_session(client_app)
    # The session is a signed cookie, so the stamped values are observable
    # through behavior: the default `acr` satisfies an `acr_values` asking for
    # it, and `amr` shows up in the hybrid id_token.
    _, challenge = _pkce_pair()
    resp = await client_app.get(
        "/oauth/authorize",
        params=_authorize_params(
            response_type="code id_token",
            scope="openid read",
            nonce="n-0S6_WzA2Mj",
            acr_values=BRONZE,
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
    )
    assert resp.status_code == 302, resp.text
    claims = _unverified(_fragment(resp)["id_token"][0])
    assert claims["acr"] == BRONZE
    assert claims["amr"] == ["pwd"]


# --- step-up enforcement ------------------------------------------------------


async def test_acr_satisfied_proceeds_to_code(client_app):
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize", params=_authorize_params(acr_values=BRONZE, state="xyz")
    )
    assert resp.status_code == 302, resp.text
    q = _query(resp)
    assert q["code"], q
    assert q["state"] == ["xyz"]
    assert "error" not in q


async def test_acr_satisfied_when_one_of_several_requested(client_app):
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize", params=_authorize_params(acr_values=f"{SILVER} {BRONZE}")
    )
    assert resp.status_code == 302, resp.text
    assert _query(resp)["code"]


async def test_acr_unsatisfied_redirects_insufficient_user_authentication(client_app):
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize", params=_authorize_params(acr_values=SILVER, state="xyz")
    )
    assert resp.status_code == 302, resp.text
    q = _query(resp)
    assert q["error"] == [STEP_UP_ERROR]
    assert q["error_description"] == [STEP_UP_DESCRIPTION]
    assert q["state"] == ["xyz"]
    assert q["iss"] == [ISSUER]
    assert "code" not in q


async def test_acr_unknown_value_is_the_step_up_error_not_a_500(client_app):
    # An `acr_values` naming something the server has never heard of is simply
    # unsatisfied — never a crash, and never a 500.
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize", params=_authorize_params(acr_values="not-an-acr  \t 0")
    )
    assert resp.status_code == 302, resp.text
    assert _query(resp)["error"] == [STEP_UP_ERROR]


async def test_acr_check_runs_after_the_login_gate(client_app):
    # Unauthenticated + an unsatisfiable `acr_values` -> the login redirect,
    # not the step-up error: the error must not be reachable (nor act as an
    # oracle) before the user has authenticated at all.
    resp = await client_app.get("/oauth/authorize", params=_authorize_params(acr_values=SILVER))
    assert resp.status_code == 302, resp.text
    assert resp.headers["location"] == "/auth/login"


async def test_acr_check_runs_after_scope_validation(client_app):
    # Both a bad scope and an unsatisfiable acr: the scope error wins.
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize", params=_authorize_params(scope="admin", acr_values=SILVER)
    )
    assert resp.status_code == 302, resp.text
    assert _query(resp)["error"] == ["invalid_scope"]


async def test_acr_error_honors_fragment_mode(client_app):
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params=_authorize_params(acr_values=SILVER, state="xyz", response_mode="fragment"),
    )
    assert resp.status_code == 302, resp.text
    frag = _fragment(resp)
    assert frag["error"] == [STEP_UP_ERROR]
    assert frag["error_description"] == [STEP_UP_DESCRIPTION]
    assert frag["state"] == ["xyz"]


async def test_acr_error_honors_form_post_mode(client_app):
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params=_authorize_params(acr_values=SILVER, state="xyz", response_mode="form_post"),
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/html; charset=utf-8"
    assert f'<input type="hidden" name="error" value="{STEP_UP_ERROR}"/>' in resp.text
    assert '<input type="hidden" name="state" value="xyz"/>' in resp.text


async def test_acr_values_from_par_are_enforced(client_app):
    push = await client_app.post(
        "/oauth/par",
        data={
            "client_id": "client1",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "read",
            "state": "xyz",
            "acr_values": SILVER,
        },
        headers=_basic_header("client1", "s3cret"),
    )
    assert push.status_code == 201, push.text
    request_uri = push.json()["request_uri"]

    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client1", "response_type": "code"},
    )
    assert resp.status_code == 302, resp.text
    q = _query(resp)
    assert q["error"] == [STEP_UP_ERROR]
    assert q["state"] == ["xyz"]


async def test_acr_step_up_uses_configured_first_value(client_app_silver):
    # The stamped `acr` follows `acr_values_supported[0]`, so with a silver-
    # first config the bronze request is the one that fails.
    await login_session(client_app_silver)
    ok = await client_app_silver.get(
        "/oauth/authorize", params=_authorize_params(acr_values=SILVER)
    )
    assert ok.status_code == 302, ok.text
    assert _query(ok)["code"]

    bad = await client_app_silver.get(
        "/oauth/authorize", params=_authorize_params(acr_values=BRONZE)
    )
    assert bad.status_code == 302, bad.text
    assert _query(bad)["error"] == [STEP_UP_ERROR]


# --- hybrid id_token ----------------------------------------------------------


async def test_hybrid_id_token_carries_acr_amr_auth_time(client_app):
    await login_session(client_app)
    _, challenge = _pkce_pair()
    resp = await client_app.get(
        "/oauth/authorize",
        params=_authorize_params(
            response_type="code id_token",
            scope="openid read",
            nonce="n-0S6_WzA2Mj",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
    )
    assert resp.status_code == 302, resp.text
    claims = _unverified(_fragment(resp)["id_token"][0])
    assert claims["acr"] == BRONZE
    assert claims["amr"] == ["pwd"]
    assert claims["auth_time"] <= claims["iat"]


# --- social login stamps amr=["fed"] ------------------------------------------


async def test_social_login_stamps_amr_fed():
    async with build_client_app(
        {"google_client_id": "g-id", "google_client_secret": "g-secret"}
    ) as client:

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "oauth2.googleapis.com":
                return httpx.Response(200, json={"access_token": "google-access-token"})
            return httpx.Response(
                200,
                json={
                    "id": "1234567890",
                    "email": "alice@example.com",
                    "verified_email": True,
                    "name": "Alice",
                },
            )

        client.app.state.http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), timeout=10
        )
        login = await client.get("/auth/login/google", follow_redirects=False)
        state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
        callback = await client.get(
            "/auth/callback/google",
            params={"state": state, "code": "abc"},
            follow_redirects=False,
        )
        assert callback.status_code == 302, callback.text

        _, challenge = _pkce_pair()
        resp = await client.get(
            "/oauth/authorize",
            params=_authorize_params(
                response_type="code id_token",
                scope="openid read",
                nonce="n-0S6_WzA2Mj",
                acr_values=BRONZE,
                code_challenge=challenge,
                code_challenge_method="S256",
            ),
        )
        assert resp.status_code == 302, resp.text
        claims = _unverified(_fragment(resp)["id_token"][0])
        assert claims["acr"] == BRONZE
        assert claims["amr"] == ["fed"]
