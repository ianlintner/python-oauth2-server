"""RFC / OAuth2 spec compliance tests — the Phase 1 acceptance gate.

Mirrors `tests/rfc_compliance.rs` from the Rust implementation test-for-test
(20 tests, snake_case names preserved) so the two suites stay diffable. This
file is self-contained: it only relies on `tests/conftest.py` fixtures and its
own helpers, not on other test modules.

One documented divergence from the Rust suite: the Python dynamic-registration
handler returns RFC 7591's own error code `invalid_client_metadata` for
malformed registration requests, where the Rust handler (non-spec-conformant)
returns `invalid_request`. `public_client_registration_with_client_credentials_is_rejected`
below asserts the Python behavior, which is already covered by
`tests/test_registration.py`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient

from oauth2_server.app import create_app
from oauth2_server.config import Config
from oauth2_server.models import DenylistEntry, Token
from oauth2_server.services.dpop import jwk_thumbprint
from tests.conftest import build_client_app
from tests.helpers import (
    generate_dpop_key,
    login_admin,
    login_session,
    make_dpop_proof,
    make_storage,
    post_token,
    reseed_client,
    seed_admin,
    seed_client,
    seed_user,
)
from tests.test_token_endpoint import run_code_flow

ISSUER = "https://auth.example.com"
JWT_SECRET = "unit-test-secret-not-for-production-0123456789abcdef"


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.rstrip(b"=").decode()


def _query(location: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlparse(location).query).items()}


async def _issue_code(
    client_app,
    *,
    client_id: str = "client1",
    redirect_uri: str = "https://a.example/cb",
    scope: str = "read",
    nonce: str | None = None,
    state: str | None = None,
) -> tuple[str, str]:
    """Log in, hit GET /oauth/authorize with PKCE, and return (code, verifier)."""
    await login_session(client_app)
    verifier, challenge = _pkce_pair()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if nonce is not None:
        params["nonce"] = nonce
    if state is not None:
        params["state"] = state
    resp = await client_app.get("/oauth/authorize", params=params)
    assert resp.status_code == 302, resp.text
    q = _query(resp.headers["location"])
    assert "error" not in q, f"authorize returned error: {q}"
    return q["code"], verifier


# ---------------------------------------------------------------------------
# RFC 9207: Authorization Server Issuer Identification
# ---------------------------------------------------------------------------


async def test_rfc9207_iss_included_in_authorization_response(client_app):
    await login_session(client_app)
    verifier, challenge = _pkce_pair()
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "abc",
        },
    )
    assert resp.status_code == 302, "authorize must redirect"
    q = _query(resp.headers["location"])
    assert q["iss"] == ISSUER, "RFC 9207: iss in redirect must equal the server issuer"
    assert q["state"] == "abc"


# ---------------------------------------------------------------------------
# RFC 9068: JWT Profile for Access Tokens
# ---------------------------------------------------------------------------


async def test_rfc9068_access_token_has_typ_at_jwt(client_app):
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials", "scope": "read"},
        basic_auth=("client1", "s3cret"),
    )
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    header = jwt.get_unverified_header(access_token)
    assert header.get("typ") == "at+JWT", (
        f"RFC 9068: typ header must be 'at+JWT', got {header.get('typ')!r}"
    )


async def test_rfc9068_jwt_iss_matches_configured_issuer(client_app):
    custom_issuer = "https://my-auth-server.example"
    async with build_client_app({"issuer": custom_issuer}) as app:
        resp = await post_token(
            app,
            {"grant_type": "client_credentials", "scope": "read"},
            basic_auth=("client1", "s3cret"),
        )
        assert resp.status_code == 200, resp.text
        access_token = resp.json()["access_token"]

        claims = jwt.decode(access_token, JWT_SECRET, algorithms=["HS256"], audience="client1")
        assert claims["iss"] == custom_issuer, "RFC 9068: iss must equal the configured issuer"


# ---------------------------------------------------------------------------
# RFC 7662: Token Introspection — nbf, jti, aud, iss fields
# ---------------------------------------------------------------------------


async def test_rfc7662_introspection_includes_nbf_jti_aud_iss(client_app):
    token_resp = await post_token(
        client_app,
        {"grant_type": "client_credentials", "scope": "read"},
        basic_auth=("client1", "s3cret"),
    )
    assert token_resp.status_code == 200, token_resp.text
    access_token = token_resp.json()["access_token"]

    intro_resp = await client_app.post(
        "/oauth/introspect",
        data={"token": access_token, "client_id": "client1", "client_secret": "s3cret"},
    )
    assert intro_resp.status_code == 200
    body = intro_resp.json()

    assert body["active"] is True, "introspected token must be active"
    assert body.get("nbf") is not None, "RFC 7662 §2.2: nbf must be present"
    assert body.get("jti") is not None, "RFC 7662 §2.2: jti must be present"
    assert body.get("aud") is not None, "RFC 7662 §2.2: aud must be present"
    assert body["aud"] == "client1", "aud must equal the client_id"
    assert body["iss"] == ISSUER, "iss in introspection must equal the server issuer"


async def test_rfc7662_introspection_nbf_le_iat(client_app):
    token_resp = await post_token(
        client_app,
        {"grant_type": "client_credentials", "scope": "read"},
        basic_auth=("client1", "s3cret"),
    )
    access_token = token_resp.json()["access_token"]

    intro_resp = await client_app.post(
        "/oauth/introspect",
        data={"token": access_token, "client_id": "client1", "client_secret": "s3cret"},
    )
    body = intro_resp.json()
    assert body["nbf"] <= body["iat"], f"nbf ({body['nbf']}) must be <= iat ({body['iat']})"


# ---------------------------------------------------------------------------
# Public clients (token_endpoint_auth_method = none) — RFC 6749 / RFC 7591
# ---------------------------------------------------------------------------


async def test_public_client_exchanges_code_without_secret(client_app):
    await seed_client(
        client_app.storage,
        client_id="client_public",
        client_secret="",
        redirect_uris='["https://native.example/cb"]',
        token_endpoint_auth_method="none",
    )

    code, verifier = await _issue_code(
        client_app,
        client_id="client_public",
        redirect_uri="https://native.example/cb",
        scope="read",
    )

    token_resp = await client_app.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "client_public",
            "code": code,
            "redirect_uri": "https://native.example/cb",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200, "public client must exchange code without secret"
    assert token_resp.json()["access_token"]


async def test_public_client_must_not_present_secret(client_app):
    await seed_client(
        client_app.storage,
        client_id="client_pub_secret",
        client_secret="",
        redirect_uris='["https://native.example/cb"]',
        token_endpoint_auth_method="none",
    )

    code, verifier = await _issue_code(
        client_app,
        client_id="client_pub_secret",
        redirect_uri="https://native.example/cb",
        scope="read",
    )

    token_resp = await client_app.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "client_pub_secret",
            "client_secret": "should_not_be_here",
            "code": code,
            "redirect_uri": "https://native.example/cb",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 401, (
        "presenting a secret for a public client must be rejected with 401"
    )
    assert token_resp.json()["error"] == "invalid_client"


# ---------------------------------------------------------------------------
# RFC 8414: Authorization Server Metadata — alternate well-known path
# ---------------------------------------------------------------------------


async def test_rfc8414_oauth_authorization_server_well_known_returns_metadata(client_app):
    resp = await client_app.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200, "/.well-known/oauth-authorization-server must return 200"
    body = resp.json()
    assert "issuer" in body, "metadata must contain 'issuer'"
    assert "token_endpoint" in body, "metadata must contain 'token_endpoint'"
    assert "authorization_endpoint" in body, "metadata must contain 'authorization_endpoint'"


async def test_rfc8414_both_well_known_paths_return_same_response(client_app):
    oidc_resp = await client_app.get("/.well-known/openid-configuration")
    as_resp = await client_app.get("/.well-known/oauth-authorization-server")
    assert oidc_resp.json() == as_resp.json(), (
        "Both well-known paths must return identical metadata"
    )


# ---------------------------------------------------------------------------
# Public client registration validation (RFC 7591 / registration handler)
# ---------------------------------------------------------------------------


async def test_public_client_registration_with_none_auth_method_succeeds(client_app):
    resp = await client_app.post(
        "/connect/register",
        json={
            "client_name": "My Native App",
            "redirect_uris": ["https://native.example/cb"],
            "grant_types": ["authorization_code"],
            "scope": "openid read",
            "token_endpoint_auth_method": "none",
        },
    )
    assert resp.status_code == 201, "public client registration must succeed"
    assert resp.json().get("client_id"), "must return client_id"


async def test_public_client_registration_with_client_credentials_is_rejected(client_app):
    resp = await client_app.post(
        "/connect/register",
        json={
            "client_name": "Bad Public Client",
            "redirect_uris": ["https://native.example/cb"],
            "grant_types": ["authorization_code", "client_credentials"],
            "scope": "read",
            "token_endpoint_auth_method": "none",
        },
    )
    assert resp.status_code == 400, "public client with client_credentials grant must be rejected"
    # NB: RFC 7591's own error vocabulary uses `invalid_client_metadata` for this
    # case; the Rust suite asserts `invalid_request` (a Rust-side inaccuracy).
    # See module docstring.
    assert resp.json()["error"] == "invalid_client_metadata"


# ---------------------------------------------------------------------------
# Chunk 1.C — UserInfo real claims from storage (OIDC Core §5.3/§5.4)
# ---------------------------------------------------------------------------


async def test_userinfo_returns_real_email_when_email_scope_requested(client_app):
    token_resp = await post_token(
        client_app,
        {"grant_type": "client_credentials", "scope": "openid email"},
        basic_auth=("client1", "s3cret"),
    )
    assert token_resp.status_code == 200
    access_token = token_resp.json()["access_token"]

    # client_credentials tokens have no user_id, so userinfo correctly rejects
    # them. The full auth-code flow with real user claims is tested separately
    # in test_userinfo_returns_real_claims_for_auth_code_flow.
    resp = await client_app.get(
        "/oauth/userinfo", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert resp.status_code == 401, "client_credentials token must be rejected by userinfo"


async def test_userinfo_returns_real_claims_for_auth_code_flow(client_app):
    code, verifier = await _issue_code(client_app, scope="openid email profile")

    token_resp = await client_app.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "client1",
            "client_secret": "s3cret",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200
    access_token = token_resp.json()["access_token"]

    userinfo_resp = await client_app.get(
        "/oauth/userinfo", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert userinfo_resp.status_code == 200
    claims = userinfo_resp.json()

    assert claims["sub"] == "u1", "sub must be user ID"
    assert claims["email"] == "user_rfc@example.test", (
        "email must come from storage when email scope requested"
    )
    assert claims["preferred_username"] == "user_rfc", (
        "preferred_username must come from storage when profile scope requested"
    )


async def test_id_token_includes_email_and_preferred_username_when_scopes_granted(client_app):
    code, verifier = await _issue_code(
        client_app, scope="openid email profile", nonce="test_nonce", state="test_state"
    )

    token_resp = await client_app.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "client1",
            "client_secret": "s3cret",
            "redirect_uri": "https://a.example/cb",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200, "token exchange must succeed"
    id_token = token_resp.json().get("id_token")
    assert id_token, "id_token must be present"

    decoded = jwt.decode(
        id_token,
        JWT_SECRET,
        algorithms=["HS256"],
        options={"verify_exp": False, "verify_aud": False},
    )

    assert decoded["email"] == "user_rfc@example.test", (
        "id_token must include email when email scope was granted"
    )
    assert decoded["preferred_username"] == "user_rfc", (
        "id_token must include preferred_username when profile scope was granted"
    )


# ---------------------------------------------------------------------------
# Chunk 1.D — OIDC prompt=none / prompt=login / max_age
# ---------------------------------------------------------------------------


async def test_prompt_none_without_session_returns_login_required(client_app):
    _verifier, challenge = _pkce_pair()
    # No login_session() call — no session cookie is carried.
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "keep_me",
            "prompt": "none",
        },
    )
    assert resp.status_code == 302, "must redirect"
    q = _query(resp.headers["location"])
    assert q["error"] == "login_required", (
        "OIDC: prompt=none without session must return login_required"
    )
    assert q["state"] == "keep_me", "state must be preserved in error redirect"
    assert "iss" in q, "iss must be present in error redirect (RFC 9207)"


async def test_prompt_login_forces_reauthentication(client_app):
    await login_session(client_app)
    _verifier, challenge = _pkce_pair()

    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
        },
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login", (
        "prompt=login must redirect to login even with active session"
    )


async def test_max_age_zero_forces_reauthentication(client_app):
    await login_session(client_app)
    _verifier, challenge = _pkce_pair()

    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "max_age": "0",
        },
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login", "max_age=0 must force re-authentication"


async def test_prompt_none_with_expired_max_age_returns_login_required(app_with_session):
    await login_session(app_with_session)

    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "prompt": "none",
            "max_age": "0",
            "state": "s1",
        },
    )
    assert resp.status_code == 302, "must redirect"
    q = _query(resp.headers["location"])
    assert q["error"] == "login_required", (
        "OIDC: prompt=none with an expired max_age must return login_required, "
        "not fall through to the interactive login UI"
    )
    assert q["state"] == "s1", "state must be preserved in error redirect"
    assert resp.headers["location"].startswith("https://a.example/cb")


async def test_prompt_none_combined_with_login_is_invalid_request(app_with_session):
    await login_session(app_with_session)

    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "prompt": "none login",
        },
    )
    assert resp.status_code == 302, "must redirect"
    q = _query(resp.headers["location"])
    assert q["error"] == "invalid_request", (
        "OIDC: prompt=none combined with any other prompt value is invalid_request"
    )


async def test_prompt_none_with_fresh_session_issues_code(app_with_session):
    await login_session(app_with_session)

    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "prompt": "none",
            "state": "fresh1",
        },
    )
    assert resp.status_code == 302, "must redirect"
    assert resp.headers["location"].startswith("https://a.example/cb")
    q = _query(resp.headers["location"])
    assert "code" in q, "prompt=none with a fresh session must issue a code"
    assert q["state"] == "fresh1", "state must be preserved in the redirect"
    assert q["iss"] == ISSUER, "RFC 9207: iss must be present in the redirect"


# ---------------------------------------------------------------------------
# Chunk 1.E — Logout with id_token_hint / cascade revocation
# ---------------------------------------------------------------------------


async def test_logout_with_invalid_aud_id_token_hint_returns_error(client_app):
    id_token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": "user_123",
            "aud": "unregistered_client",
            "exp": 9999999999,
            "iat": 0,
        },
        JWT_SECRET,
        algorithm="HS256",
    )

    resp = await client_app.get("/oauth/logout", params={"id_token_hint": id_token})
    assert resp.status_code == 400, "id_token_hint with unregistered aud must return 400"
    assert resp.json()["error"] == "invalid_request"


async def test_revoke_cascades_to_entire_token_family(client_app):
    code, verifier = await _issue_code(client_app, scope="read")

    token_resp = await client_app.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "client1",
            "client_secret": "s3cret",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "code_verifier": verifier,
        },
    )
    assert token_resp.status_code == 200
    body = token_resp.json()
    access_token = body["access_token"]
    refresh_token = body["refresh_token"]
    assert refresh_token, "refresh_token expected"

    revoke_resp = await client_app.post(
        "/oauth/revoke",
        data={"token": refresh_token, "client_id": "client1", "client_secret": "s3cret"},
    )
    assert revoke_resp.status_code == 200

    intro_resp = await client_app.post(
        "/oauth/introspect",
        data={"token": access_token, "client_id": "client1", "client_secret": "s3cret"},
    )
    assert intro_resp.status_code == 200
    assert intro_resp.json()["active"] is False, (
        "Access token must be inactive after revoking the refresh token (cascade revocation)"
    )


# ---------------------------------------------------------------------------
# Chunk 1.F — Discovery doc compliance
# ---------------------------------------------------------------------------


async def test_discovery_includes_iss_parameter_supported(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()

    assert body["authorization_response_iss_parameter_supported"] is True, (
        "RFC 9207: must advertise authorization_response_iss_parameter_supported"
    )

    prompts = body["prompt_values_supported"]
    assert "none" in prompts, "must support prompt=none"
    assert "login" in prompts, "must support prompt=login"

    methods = body["token_endpoint_auth_methods_supported"]
    assert "none" in methods, "must advertise 'none' in token_endpoint_auth_methods_supported"
    assert "client_secret_basic" in methods, "must still include client_secret_basic"

    claims = body["claims_supported"]
    assert "email" in claims, "claims_supported must include 'email'"
    assert "preferred_username" in claims, "claims_supported must include 'preferred_username'"


# ---------------------------------------------------------------------------
# Phase 2 compliance pins (Task 15)
#
# Each test below is a thin wrapper pinning one Phase 2 behavior that already
# has full coverage in its own dedicated module (named in each docstring).
# Keeping a copy here — with names matching the Rust `compliance_wave*.rs`
# suites — keeps this file the single diffable compliance surface for both
# implementations.
# ---------------------------------------------------------------------------


def _basic_header(client_id: str, client_secret: str) -> dict:
    raw = f"{client_id}:{client_secret}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


async def test_refresh_token_expires_after_ttl(client_app):
    """Full coverage: test_token_endpoint.py::test_expired_refresh_token_rejected."""
    resp, _ = await run_code_flow(client_app, scope="read")
    refresh = resp.json()["refresh_token"]
    row = await client_app.storage.get_token_by_refresh_token(refresh)
    aged = row.model_copy(update={"created_at": row.created_at - timedelta(seconds=86400 + 60)})
    await client_app.storage.revoke_token(row.access_token)
    await client_app.storage.save_token(
        aged.model_copy(
            update={"id": uuid.uuid4().hex, "access_token": "at-aged", "refresh_token": "rt-aged"}
        )
    )
    resp2 = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": "rt-aged"},
        basic_auth=("client1", "s3cret"),
    )
    assert resp2.status_code == 400, "refresh past created_at + refresh_token_ttl_secs must fail"
    body = resp2.json()
    assert body["error"] == "invalid_grant"
    assert "expired" in body["error_description"]


async def test_prompt_none_expired_max_age_login_required(app_with_session):
    """Full coverage: test_prompt_none_with_expired_max_age_returns_login_required above."""
    await login_session(app_with_session)

    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "prompt": "none",
            "max_age": "0",
            "state": "pin1",
        },
    )
    assert resp.status_code == 302
    q = _query(resp.headers["location"])
    assert q["error"] == "login_required", (
        "prompt=none with an expired max_age must return login_required, not the login UI"
    )
    assert q["state"] == "pin1"


async def test_rfc9126_par_round_trip(client_app):
    """Full coverage: test_par.py::test_par_request_uri_full_flow."""
    verifier, challenge = _pkce_pair()
    push_resp = await client_app.post(
        "/oauth/par",
        data={
            "client_id": "client1",
            "response_type": "code",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        headers=_basic_header("client1", "s3cret"),
    )
    assert push_resp.status_code == 201, push_resp.text
    request_uri = push_resp.json()["request_uri"]
    assert request_uri.startswith("urn:ietf:params:oauth:request-uri:")

    await login_session(client_app)
    authorize_resp = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client1", "response_type": "code"},
    )
    assert authorize_resp.status_code == 302, authorize_resp.text
    code = _query(authorize_resp.headers["location"])["code"]

    token_resp = await client_app.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
            "code_verifier": verifier,
        },
        headers=_basic_header("client1", "s3cret"),
    )
    assert token_resp.status_code == 200, token_resp.text
    assert "access_token" in token_resp.json(), (
        "RFC 9126: a pushed request_uri must complete the full authorization_code exchange"
    )


async def test_oidc_logout_redirects_with_exact_state(client_app):
    """Full coverage: test_logout.py::test_logout_redirects_with_exact_state."""
    await reseed_client(
        client_app,
        redirect_uris=json.dumps(["https://app.example.com/logged-out"]),
        post_logout_redirect_uris="",
    )

    resp = await client_app.get(
        "/oauth/logout",
        params={
            "post_logout_redirect_uri": "https://app.example.com/logged-out",
            "state": "pin-state",
        },
    )
    assert resp.status_code == 302, resp.text
    assert resp.headers["location"] == "https://app.example.com/logged-out?state=pin-state", (
        "OIDC RP-initiated logout must echo state exactly and add no other query params"
    )


async def test_backchannel_logout_token_shape(client_app):
    """Full coverage: test_logout.py::test_backchannel_logout_posts_valid_token."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    client_app.app.state.http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), timeout=10
    )

    await reseed_client(
        client_app,
        backchannel_logout_uri="https://rp.example/bc-logout",
        backchannel_logout_session_required=False,
    )

    id_token_hint = jwt.encode(
        {"iss": ISSUER, "sub": "u1", "aud": "client1", "exp": 9999999999, "iat": 0},
        JWT_SECRET,
        algorithm="HS256",
    )
    resp = await client_app.get("/oauth/logout", params={"id_token_hint": id_token_hint})
    assert resp.status_code == 200, resp.text

    assert len(captured) == 1, "back-channel logout must POST exactly once to the RP"
    logout_token = captured[0].content.decode().removeprefix("logout_token=")

    header = jwt.get_unverified_header(logout_token)
    assert header["typ"] == "logout+JWT", "back-channel logout token must be typed logout+JWT"

    claims = jwt.decode(
        logout_token, JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False}
    )
    assert claims["events"] == {"http://schemas.openid.net/event/backchannel-logout": {}}
    assert claims["sub"] == "u1"
    assert claims["aud"] == "client1"
    assert "jti" in claims
    assert "iat" in claims
    assert "exp" in claims


async def test_jwks_rs256_shape(client_app):
    """Full coverage: test_jwks_rs256.py::test_jwks_publishes_rs256_key_shape."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    async with build_client_app(
        {"id_token_private_key_pem": pem, "id_token_kid": "pin-rs256-key"}
    ) as app:
        resp = await app.get("/.well-known/jwks.json")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body["keys"]) == 1
        jwk = body["keys"][0]
        assert jwk["kid"] == "pin-rs256-key"
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert set(jwk) == {"kid", "kty", "use", "alg", "n", "e"}, (
            "JWKS entries must expose only the public-key material, never `d`/`p`/`q`"
        )


async def test_admin_rbac_bearer_allowlist(client_app):
    """Full coverage: test_admin_rbac.py bearer + admin_client_ids tests."""
    async with build_client_app({"admin_client_ids": ["client1"]}) as app:
        allowed = Token(
            id=uuid.uuid4().hex,
            access_token=uuid.uuid4().hex,
            client_id="client1",
            scope="admin read",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        await app.storage.save_token(allowed)
        resp = await app.get(
            "/admin/api/users", headers={"Authorization": f"Bearer {allowed.access_token}"}
        )
        assert resp.status_code == 200, (
            "admin-scoped bearer from an allowlisted client_id must pass the guard"
        )

        denied = Token(
            id=uuid.uuid4().hex,
            access_token=uuid.uuid4().hex,
            client_id="not-allowlisted-client",
            scope="admin read",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        await app.storage.save_token(denied)
        resp2 = await app.get(
            "/admin/api/users", headers={"Authorization": f"Bearer {denied.access_token}"}
        )
        assert resp2.status_code == 403, (
            "the 'admin' scope alone is not sufficient without OAUTH2_ADMIN_CLIENT_IDS membership"
        )
        assert resp2.json()["error"] == "insufficient_scope"


async def test_denylist_ip_blocked():
    """Full coverage: test_denylist_middleware.py::test_middleware_blocks_denylisted_ip."""
    config = Config(jwt_secret=JWT_SECRET, issuer=ISSUER)
    storage = await make_storage()
    await seed_client(storage)
    await seed_user(storage)
    app = create_app(config, storage)

    async with AsyncClient(
        transport=ASGITransport(app=app, client=("198.51.100.42", 123)),
        base_url=ISSUER,
    ) as client:
        await storage.add_denylist_entry(
            DenylistEntry(
                id=uuid.uuid4().hex,
                kind="ip",
                value="198.51.100.42",
                reason="pinned compliance test",
                created_at=datetime.now(timezone.utc),
            )
        )
        resp = await client.get("/health")
        assert resp.status_code == 403, "DenylistGuard must block every route, including /health"
        assert resp.json() == {
            "error": "access_denied",
            "error_description": "request source is denylisted",
        }


# --- Phase 3a compliance pins -------------------------------------------------


async def test_login_rate_limited_after_repeated_failures(client_app, monkeypatch):
    """Full coverage: test_ratelimit.py::test_login_blocked_after_repeated_failures."""
    import oauth2_server.routes.login as login_routes

    calls = []

    async def spy_verify_password_async(password, phc_hash):
        calls.append(password)
        return False

    monkeypatch.setattr(login_routes, "verify_password_async", spy_verify_password_async)

    for _ in range(10):
        resp = await client_app.post(
            "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
        )
        assert resp.status_code == 303
    assert len(calls) == 10

    resp = await client_app.post(
        "/auth/login", data={"username": "user_rfc", "password": "wrong-password"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/auth/login?error=too_many_attempts"
    assert int(resp.headers["retry-after"]) > 0
    assert len(calls) == 10, "the blocked attempt must short-circuit before credential verification"


async def test_denylisted_username_blocked_at_login(client_app):
    """Full coverage: test_denylist_middleware.py::test_denylisted_username_cannot_login."""
    await client_app.storage.add_denylist_entry(
        DenylistEntry(
            id=uuid.uuid4().hex,
            kind="username",
            value="user_rfc",
            reason="pinned compliance test",
            created_at=datetime.now(timezone.utc),
        )
    )

    resp = await login_session(client_app)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/auth/login?error=invalid_credentials"

    # No session was established: a follow-up authorize request still
    # requires login rather than proceeding as an authenticated user.
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
        },
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"


async def test_id_token_kid_matches_jwks_after_rotation():
    """Full coverage:
    test_jwks_rs256.py::test_id_token_signed_with_current_keyset_key_after_rotation.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    async with build_client_app(
        {"id_token_private_key_pem": pem, "id_token_kid": "pin-rotation-key"}
    ) as app:
        await seed_admin(app.storage)
        await login_admin(app)
        rotate_resp = await app.post("/admin/api/keys/rotate", json={"algorithm": "RS256"})
        assert rotate_resp.status_code == 200, rotate_resp.text
        new_kid = rotate_resp.json()["kid"]
        assert new_kid != "pin-rotation-key"

        resp, _code = await run_code_flow(app, scope="openid email")
        assert resp.status_code == 200, resp.text
        header = jwt.get_unverified_header(resp.json()["id_token"])
        assert header["alg"] == "RS256"
        assert header["kid"] == new_kid, "id_token must be signed with the rotated-in key (kid)"

        jwks_resp = await app.get("/.well-known/jwks.json")
        published_kids = {k["kid"] for k in jwks_resp.json()["keys"]}
        assert new_kid in published_kids, "the signing kid must be published in JWKS"


async def test_authorize_rejects_duplicate_query_params(app_with_session):
    """Full coverage: test_authorize.py::test_duplicate_query_parameter_rejected."""
    resp = await app_with_session.get(
        "/oauth/authorize",
        params=[
            ("response_type", "code"),
            ("response_type", "code"),
            ("client_id", "client1"),
            ("redirect_uri", "https://a.example/cb"),
            ("scope", "read"),
        ],
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert "duplicate query parameter" in body["error_description"]


# --- Phase 3b compliance pins (Task 7) --------------------------------------
#
# Each test below is a thin wrapper pinning one Phase 3b behavior that already
# has full coverage in its own dedicated module (named in each docstring).


async def test_dpop_bound_token_round_trip(client_app):
    """Full coverage: test_dpop_token.py::test_client_credentials_with_es256_proof_binds_cnf
    and test_introspect_with_matching_proof_active_true_and_cnf."""
    key = generate_dpop_key()
    proof, pub_jwk = make_dpop_proof(f"{ISSUER}/oauth/token", "POST", key)

    token_resp = await post_token(
        client_app,
        {"grant_type": "client_credentials", "scope": "read"},
        basic_auth=("client1", "s3cret"),
        headers={"DPoP": proof},
    )
    assert token_resp.status_code == 200, token_resp.text
    body = token_resp.json()
    assert body["token_type"] == "DPoP", (
        "RFC 9449: a DPoP-bound access token must report token_type 'DPoP'"
    )
    access_token = body["access_token"]
    claims = jwt.decode(access_token, options={"verify_signature": False})
    assert claims["cnf"]["jkt"] == jwk_thumbprint(pub_jwk), (
        "RFC 9449 §6.1: cnf.jkt must equal the DPoP proof's JWK thumbprint"
    )

    introspect_proof, _ = make_dpop_proof(f"{ISSUER}/oauth/introspect", "POST", key)
    introspect_resp = await client_app.post(
        "/oauth/introspect",
        data={"token": access_token},
        headers={**_basic_header("client1", "s3cret"), "DPoP": introspect_proof},
    )
    assert introspect_resp.status_code == 200, introspect_resp.text
    introspect_body = introspect_resp.json()
    assert introspect_body["active"] is True
    assert introspect_body["cnf"]["jkt"] == jwk_thumbprint(pub_jwk), (
        "RFC 9449 §7.1: introspection must echo the bound cnf.jkt for a matching proof"
    )


async def test_dpop_nonce_challenge_flow(client_app):
    """Full coverage: test_dpop_token.py::test_nonce_required_client_bootstrap."""
    await seed_client(
        client_app.storage,
        client_id="rfc-dpop-nonce-client",
        client_secret="nonce-secret",
        dpop_nonce_required=True,
        grant_types=json.dumps(["client_credentials"]),
    )
    key = generate_dpop_key()

    first_proof, _ = make_dpop_proof(f"{ISSUER}/oauth/token", "POST", key)
    first_resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("rfc-dpop-nonce-client", "nonce-secret"),
        headers={"DPoP": first_proof},
    )
    assert first_resp.status_code == 400, first_resp.text
    assert first_resp.json()["error"] == "use_dpop_nonce", (
        "RFC 9449 §8: a client bound to nonce enforcement must be challenged "
        "with use_dpop_nonce before a proof lacking a server-issued nonce is accepted"
    )
    nonce = first_resp.headers["DPoP-Nonce"]

    second_proof, pub_jwk = make_dpop_proof(f"{ISSUER}/oauth/token", "POST", key, nonce)
    second_resp = await post_token(
        client_app,
        {"grant_type": "client_credentials"},
        basic_auth=("rfc-dpop-nonce-client", "nonce-secret"),
        headers={"DPoP": second_proof},
    )
    assert second_resp.status_code == 200, second_resp.text
    body = second_resp.json()
    assert body["token_type"] == "DPoP"
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["cnf"]["jkt"] == jwk_thumbprint(pub_jwk), (
        "a proof embedding the challenged nonce from the SAME key must be accepted"
    )


async def test_rar_full_flow_with_type_validation(client_app):
    """Full coverage: test_rar.py::test_authorize_rejects_unknown_rar_type
    and test_full_flow_embeds_details_in_jwt_and_response."""
    await login_session(client_app)

    bad_resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "authorization_details": json.dumps([{"type": "payment_initiation"}]),
        },
    )
    assert bad_resp.status_code == 302, bad_resp.text
    q = _query(bad_resp.headers["location"])
    assert q["error"] == "invalid_authorization_details", (
        "RFC 9396 §5: an authorization_details type outside rar_types_supported "
        "must be rejected before a code is minted"
    )

    details = [{"type": "openid", "actions": ["read"]}]
    verifier, challenge = _pkce_pair()
    good_resp = await client_app.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "authorization_details": json.dumps(details),
        },
    )
    assert good_resp.status_code == 302, good_resp.text
    code = _query(good_resp.headers["location"])["code"]

    token_resp = await client_app.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
            "code_verifier": verifier,
        },
        headers=_basic_header("client1", "s3cret"),
    )
    assert token_resp.status_code == 200, token_resp.text
    body = token_resp.json()
    assert body["authorization_details"] == details, (
        "RFC 9396 §7.1: the AS must echo the validated authorization_details in the token response"
    )
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["authorization_details"] == details, (
        "RFC 9396: authorization_details must also be embedded in the access token"
    )


async def test_token_exchange_round_trip(client_app):
    """Full coverage: test_token_exchange.py::test_valid_subject_token_is_exchanged."""
    exchange_urn = "urn:ietf:params:oauth:grant-type:token-exchange"
    access_token_type_urn = "urn:ietf:params:oauth:token-type:access_token"

    await seed_client(
        client_app.storage,
        client_id="rfc-exchange-client",
        client_secret="exchange-secret",
        grant_types=json.dumps([exchange_urn]),
        scope="read profile",
    )
    subject_token = Token(
        id=uuid.uuid4().hex,
        access_token="rfc-subject-token",
        client_id="other-client",
        user_id="u1",
        scope="read",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    await client_app.storage.save_token(subject_token)

    resp = await post_token(
        client_app,
        {
            "grant_type": exchange_urn,
            "subject_token": "rfc-subject-token",
            "subject_token_type": access_token_type_urn,
        },
        basic_auth=("rfc-exchange-client", "exchange-secret"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issued_token_type"] == access_token_type_urn, (
        "RFC 8693 §2.2.1: issued_token_type must echo the URN of the issued token kind"
    )
    assert body["token_type"] == "Bearer"
    assert "refresh_token" not in body, "RFC 8693: token exchange never issues a refresh token"

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["sub"] == "u1", "the exchanged token must carry the SUBJECT token's user"
    assert claims["client_id"] == "rfc-exchange-client", (
        "the exchanged token must carry the EXCHANGING client's client_id"
    )
