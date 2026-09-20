import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from oauth2_server.routes.wellknown import SCOPES_SUPPORTED
from tests.test_jwks_rs256 import _rs256_app
from tests.test_token_endpoint import run_code_flow


async def test_rfc8414_oauth_authorization_server_well_known_returns_metadata(client_app):
    resp = await client_app.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issuer"] == "https://auth.example.com"
    assert body["authorization_endpoint"] == "https://auth.example.com/oauth/authorize"
    assert body["token_endpoint"] == "https://auth.example.com/oauth/token"
    assert body["authorization_response_iss_parameter_supported"] is True


async def test_rfc8414_both_well_known_paths_return_same_response(client_app):
    resp1 = await client_app.get("/.well-known/oauth-authorization-server")
    resp2 = await client_app.get("/.well-known/openid-configuration")
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.content == resp2.content


async def test_discovery_includes_iss_parameter_supported(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["authorization_response_iss_parameter_supported"] is True


async def test_discovery_omits_claims_parameter_supported(client_app):
    """Divergence 59: the `claims` request parameter is parsed and honored
    for `id_token` claims, but the OIDC Core `claims_parameter_supported`
    metadata flag is deliberately NOT advertised (Rust parity) — support is
    partial, and advertising it would promise `userinfo` handling too."""
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert "claims_parameter_supported" not in body


async def test_discovery_advertises_none_auth_method(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert "none" in resp.json()["token_endpoint_auth_methods_supported"]


async def test_discovery_advertises_jwt_auth_methods(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_endpoint_auth_methods_supported"] == [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth",
        "none",
    ]
    assert body["introspection_endpoint_auth_methods_supported"] == [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth",
    ]
    assert body["revocation_endpoint_auth_methods_supported"] == [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth",
    ]


async def test_discovery_advertises_par(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["pushed_authorization_request_endpoint"] == "https://auth.example.com/oauth/par"
    assert body["require_pushed_authorization_requests"] is False
    assert body["request_uri_parameter_supported"] is True
    assert body["request_parameter_supported"] is True


async def test_jwks_returns_empty_keys(client_app):
    resp = await client_app.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert resp.json() == {"keys": []}


async def test_discovery_includes_session_management_fields(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["end_session_endpoint"] == "https://auth.example.com/oauth/logout"
    assert body["check_session_iframe"] == "https://auth.example.com/oauth/check_session"
    assert body["backchannel_logout_supported"] is True
    assert body["backchannel_logout_session_supported"] is True
    assert body["frontchannel_logout_supported"] is True
    assert body["frontchannel_logout_session_supported"] is True


async def _get_userinfo(client_app, access_token: str | None, *, in_query: bool = False):
    if in_query:
        return await client_app.get("/oauth/userinfo", params={"access_token": access_token})
    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    return await client_app.get("/oauth/userinfo", headers=headers)


async def test_userinfo_returns_real_claims_for_auth_code_flow(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email profile")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    info_resp = await _get_userinfo(client_app, access_token)
    assert info_resp.status_code == 200, info_resp.text
    body = info_resp.json()
    assert body["sub"] == "u1"
    assert body["email"] == "user_rfc@example.test"
    assert body["preferred_username"] == "user_rfc"


async def test_userinfo_returns_real_email_when_email_scope_requested(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    info_resp = await _get_userinfo(client_app, access_token)
    assert info_resp.status_code == 200, info_resp.text
    body = info_resp.json()
    assert body["email"] == "user_rfc@example.test"
    assert "preferred_username" not in body


async def test_userinfo_rejects_token_in_query(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    info_resp = await _get_userinfo(client_app, access_token, in_query=True)
    assert info_resp.status_code == 401
    assert info_resp.headers["www-authenticate"] == "Bearer"


async def test_userinfo_rejects_revoked_token(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    basic = base64.b64encode(b"client1:s3cret").decode()
    revoke = await client_app.post(
        "/oauth/revoke",
        data={"token": access_token},
        headers={"Authorization": f"Basic {basic}"},
    )
    assert revoke.status_code == 200, revoke.text

    info_resp = await _get_userinfo(client_app, access_token)
    assert info_resp.status_code == 401
    assert info_resp.json()["error"] == "invalid_token"


async def test_userinfo_foreign_jwt_rejected_not_500(client_app):
    """Verify that a validly-signed but foreign-shaped JWT returns 401, not 500.

    A JWT signed with the correct secret but with a payload that doesn't match
    the Claims model (e.g., minted by another system sharing the secret) should
    raise pydantic.ValidationError, which must be caught and treated as an
    invalid token (storage lookup path) rather than allowed to bubble up as a 500.
    """
    import jwt as pyjwt

    jwt_secret = "unit-test-secret-not-for-production-0123456789abcdef"
    foreign = pyjwt.encode(
        {"sub": "u1", "iss": "https://auth.example.com", "exp": 9999999999, "iat": 1},
        jwt_secret,
        algorithm="HS256",
    )
    resp = await _get_userinfo(client_app, foreign)
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


async def test_discovery_advertises_resource_indicators(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["resource_indicators_supported"] is True


async def test_wave4_rfc9728_protected_resource_metadata_returns_200(client_app):
    resp = await client_app.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200, resp.text


async def test_wave4_rfc9728_protected_resource_metadata_has_resource_field(client_app):
    resp = await client_app.get("/.well-known/oauth-protected-resource")
    assert resp.json()["resource"] == "https://auth.example.com"


async def test_wave4_rfc9728_protected_resource_metadata_has_authorization_servers(client_app):
    resp = await client_app.get("/.well-known/oauth-protected-resource")
    assert resp.json()["authorization_servers"] == ["https://auth.example.com"]


async def test_protected_resource_metadata_is_cacheable(client_app):
    resp = await client_app.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "public, max-age=3600"
    body = resp.json()
    assert body == {
        "resource": "https://auth.example.com",
        "authorization_servers": ["https://auth.example.com"],
        "bearer_methods_supported": ["header"],
        "dpop_signing_alg_values_supported": ["ES256", "RS256"],
        "token_introspection_endpoint": "https://auth.example.com/oauth/introspect",
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        "scopes_supported": SCOPES_SUPPORTED,
        "tls_client_certificate_bound_access_tokens": True,
    }


async def test_wave4_token_status_list_returns_200(client_app):
    resp = await client_app.get("/.well-known/oauth-authorization-server/status")
    assert resp.status_code == 200, resp.text


async def test_wave4_token_status_list_returns_valid_json(client_app):
    resp = await client_app.get("/.well-known/oauth-authorization-server/status")
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json() == {
        "status_list": {"bits": 1, "lst": "eNrb2FgAAQABAAE"},
        "issuer": "https://auth.example.com",
        "status_list_uri": "https://auth.example.com/.well-known/oauth-authorization-server/status",
    }


async def test_discovery_endpoint_aliases(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_introspection_endpoint"] == "https://auth.example.com/oauth/introspect"
    assert body["token_revocation_endpoint"] == "https://auth.example.com/oauth/revoke"
    assert body["service_documentation"] == "https://auth.example.com/docs"

    status_resp = await client_app.get("/.well-known/oauth-authorization-server/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["issuer"] == "https://auth.example.com"

    auth_server_resp = await client_app.get("/.well-known/oauth-authorization-server")
    assert auth_server_resp.status_code == 200
    assert "status_list" not in auth_server_resp.json()


async def test_discovery_claims_supported_parity(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["claims_supported"] == [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "nonce",
        "at_hash",
        "email",
        "preferred_username",
        "c_hash",
        "acr",
        "amr",
        "auth_time",
    ]


async def test_wave5_discovery_response_types_includes_code_id_token(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["response_types_supported"] == ["code", "code id_token"]


async def test_wave5_discovery_response_modes_includes_fragment(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["response_modes_supported"] == ["query", "form_post", "fragment"]


async def test_wave5_discovery_request_parameter_supported_is_true(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["request_parameter_supported"] is True


async def test_discovery_request_object_algs_match_implementation(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["request_object_signing_alg_values_supported"] == [
        "RS256",
        "HS256",
        "none",
    ]


async def test_wave4_rfc9470_acr_values_supported_advertised(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["acr_values_supported"]
    assert body["acr_values_supported"] == ["urn:mace:incommon:iap:bronze"]


async def test_wave4_oidc_claims_request_acr_auth_time_in_claims_supported(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    claims_supported = resp.json()["claims_supported"]
    for claim in ("acr", "auth_time", "amr", "c_hash"):
        assert claim in claims_supported


async def test_userinfo_includes_iss_and_aud(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email profile")
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    info_resp = await _get_userinfo(client_app, access_token)
    assert info_resp.status_code == 200, info_resp.text
    body = info_resp.json()
    assert body["iss"] == "https://auth.example.com"
    assert body["aud"] == "client1"
    assert body["sub"] == "u1"


async def test_discovery_advertises_introspection_signing_algs_without_rs256(client_app):
    """RFC 9701 §7: a client that may negotiate a JWT-secured introspection
    response needs to know which algorithms it must be able to verify — and
    with no RS256 key in the keyset, HS256 (the client's own secret) is the
    only one this server can produce."""
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["introspection_signing_alg_values_supported"] == ["HS256"]


@pytest.fixture(scope="module")
def rsa_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


async def test_discovery_advertises_rs256_introspection_signing_when_keyset_has_a_key(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        resp = await client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        assert resp.json()["introspection_signing_alg_values_supported"] == ["RS256", "HS256"]


async def test_wave4_rfc8705_mtls_advertised_in_discovery(client_app):
    """RFC 8705 §3.3: both mTLS client-authentication methods appear on all
    three auth-method lists, and certificate-bound access tokens are
    advertised (divergence 33 retired — mTLS is implemented now)."""
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    for field in (
        "token_endpoint_auth_methods_supported",
        "introspection_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_methods_supported",
    ):
        assert "tls_client_auth" in body[field], field
        assert "self_signed_tls_client_auth" in body[field], field
    assert body["tls_client_certificate_bound_access_tokens"] is True


async def test_protected_resource_metadata_advertises_mtls_binding(client_app):
    resp = await client_app.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    assert resp.json()["tls_client_certificate_bound_access_tokens"] is True
