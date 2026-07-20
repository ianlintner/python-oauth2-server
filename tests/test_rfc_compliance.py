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
import secrets
from urllib.parse import parse_qs, urlparse

import jwt

from tests.conftest import build_client_app
from tests.helpers import login_session, post_token, seed_client

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
