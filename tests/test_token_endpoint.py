import base64
import hashlib
import secrets
import uuid
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import jwt

from tests.helpers import login_session, post_token, reseed_client, seed_client

JWT_SECRET = "unit-test-secret-not-for-production-0123456789abcdef"


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.rstrip(b"=").decode()


async def issue_code(
    client_app,
    *,
    client_id: str = "client1",
    redirect_uri: str = "https://a.example/cb",
    scope: str = "openid email",
    pkce: bool = True,
    nonce: str | None = None,
) -> tuple[str, str | None]:
    """Log in, hit GET /oauth/authorize, and return (code, code_verifier)."""
    await login_session(client_app)
    verifier: str | None = None
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }
    if pkce:
        verifier, challenge = _pkce_pair()
        params["code_challenge"] = challenge
        params["code_challenge_method"] = "S256"
    if nonce is not None:
        params["nonce"] = nonce
    resp = await client_app.get("/oauth/authorize", params=params)
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    return q["code"][0], verifier


async def run_code_flow(
    client_app,
    *,
    client_id: str = "client1",
    client_secret: str | None = "s3cret",
    redirect_uri: str = "https://a.example/cb",
    scope: str = "openid email",
    pkce: bool = True,
    nonce: str | None = None,
    code_verifier: str | None = "__use_issued__",
    extra_form: dict | None = None,
):
    """Run the full authorization_code flow and POST /oauth/token; returns (resp, code)."""
    code, issued_verifier = await issue_code(
        client_app,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        pkce=pkce,
        nonce=nonce,
    )
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }
    verifier = issued_verifier if code_verifier == "__use_issued__" else code_verifier
    if verifier is not None:
        data["code_verifier"] = verifier
    if extra_form:
        data.update(extra_form)
    basic_auth = (client_id, client_secret) if client_secret is not None else None
    resp = await post_token(client_app, data, basic_auth=basic_auth)
    return resp, code


async def test_client_credentials_issues_at_jwt(client_app):
    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert jwt.get_unverified_header(body["access_token"])["typ"] == "at+JWT"
    assert "refresh_token" not in body or body["refresh_token"] is None
    assert resp.headers["cache-control"] == "no-store"


async def test_wrong_secret_rejected_with_401(client_app):
    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "nope")
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"
    assert resp.headers["www-authenticate"] == "Basic"


async def test_urlencoded_basic_secret_decoded(client_app):
    # A client whose real secret contains "&" must still authenticate when the
    # secret is sent URL-encoded ("%26") inside the Basic auth header, per
    # RFC 6749 §2.3.1.
    await seed_client(client_app.storage, client_id="client2", client_secret="s&cret")
    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client2", "s%26cret")
    )
    assert resp.status_code == 200


async def test_unsupported_grant_type(client_app):
    resp = await post_token(
        client_app, {"grant_type": "password"}, basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


async def test_public_client_cannot_use_client_credentials(client_app):
    await seed_client(
        client_app.storage,
        client_id="public-client",
        client_secret="",
        token_endpoint_auth_method="none",
        grant_types='["client_credentials"]',
    )
    resp = await post_token(
        client_app, {"grant_type": "client_credentials", "client_id": "public-client"}
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def test_basic_auth_client_id_mismatched_with_form_rejected(client_app):
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials", "client_id": "other"},
        basic_auth=("client1", "s3cret"),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


async def test_basic_auth_secret_mismatched_with_form_rejected(client_app):
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials", "client_secret": "wrong"},
        basic_auth=("client1", "s3cret"),
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def _seed_public_client(client_app, client_id: str = "pubclient"):
    await seed_client(
        client_app.storage,
        client_id=client_id,
        client_secret="",
        redirect_uris='["https://a.example/cb"]',
        token_endpoint_auth_method="none",
    )


async def test_public_client_exchanges_code_without_secret(client_app):
    await _seed_public_client(client_app)
    resp, _code = await run_code_flow(
        client_app, client_id="pubclient", client_secret=None, scope="openid email"
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]


async def test_public_client_must_not_present_secret(client_app):
    await _seed_public_client(client_app)
    resp, _code = await run_code_flow(
        client_app,
        client_id="pubclient",
        client_secret=None,
        scope="openid email",
        extra_form={"client_secret": "unexpected"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def test_used_code_replay_revokes_family(client_app):
    resp1, code = await run_code_flow(client_app)
    assert resp1.status_code == 200, resp1.text
    first_refresh_token = resp1.json()["refresh_token"]

    resp2 = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
        },
        basic_auth=("client1", "s3cret"),
    )
    assert resp2.status_code == 400
    assert resp2.json()["error"] == "invalid_grant"

    # The whole family issued from the replayed code must now be revoked.
    resp3 = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": first_refresh_token},
        basic_auth=("client1", "s3cret"),
    )
    assert resp3.status_code == 400
    assert resp3.json()["error"] == "invalid_grant"


async def test_pkce_verifier_mismatch_rejected(client_app):
    wrong_verifier = secrets.token_urlsafe(32)
    resp, _code = await run_code_flow(client_app, code_verifier=wrong_verifier)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


async def test_refresh_rotation_and_reuse_revokes_family(client_app):
    resp1, _code = await run_code_flow(client_app)
    assert resp1.status_code == 200, resp1.text
    refresh_token1 = resp1.json()["refresh_token"]

    resp2 = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": refresh_token1},
        basic_auth=("client1", "s3cret"),
    )
    assert resp2.status_code == 200, resp2.text
    refresh_token2 = resp2.json()["refresh_token"]
    assert refresh_token2 != refresh_token1

    # Reusing the rotated-out refresh token is a replay: reject and revoke the family.
    resp3 = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": refresh_token1},
        basic_auth=("client1", "s3cret"),
    )
    assert resp3.status_code == 400
    assert resp3.json()["error"] == "invalid_grant"

    # The newly-rotated token was in the same family, so it's now revoked too.
    resp4 = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": refresh_token2},
        basic_auth=("client1", "s3cret"),
    )
    assert resp4.status_code == 400
    assert resp4.json()["error"] == "invalid_grant"


async def test_id_token_includes_email_and_preferred_username(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid email profile")
    assert resp.status_code == 200, resp.text
    id_token = resp.json()["id_token"]
    claims = jwt.decode(id_token, JWT_SECRET, algorithms=["HS256"], audience="client1")
    assert claims["email"] == "user_rfc@example.test"
    assert claims["preferred_username"] == "user_rfc"
    assert claims["c_hash"]
    assert claims["at_hash"]


async def test_id_token_echoes_nonce(client_app):
    resp, _code = await run_code_flow(client_app, scope="openid", nonce="nonce-value-123")
    assert resp.status_code == 200, resp.text
    id_token = resp.json()["id_token"]
    claims = jwt.decode(id_token, JWT_SECRET, algorithms=["HS256"], audience="client1")
    assert claims["nonce"] == "nonce-value-123"


async def test_expired_refresh_token_rejected(client_app):
    resp, _ = await run_code_flow(client_app, scope="read")
    refresh = resp.json()["refresh_token"]
    # Age the token row past the refresh TTL directly in storage.
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
    assert resp2.status_code == 400
    body = resp2.json()
    assert body["error"] == "invalid_grant"
    assert "expired" in body["error_description"]


async def test_refresh_reissues_id_token_for_openid_scope(client_app):
    resp, _ = await run_code_flow(client_app, scope="openid email")
    refresh = resp.json()["refresh_token"]
    resp2 = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": refresh},
        basic_auth=("client1", "s3cret"),
    )
    assert resp2.status_code == 200
    body = resp2.json()
    assert body.get("id_token")
    claims = jwt.decode(body["id_token"], options={"verify_signature": False})
    assert claims["sub"] == "u1"
    assert "nonce" not in claims  # OIDC Core §12.2: no nonce on refresh
    assert claims["aud"] == "client1"
    assert claims["email"] == "user_rfc@example.test"
    # OIDC Core §3.3.2.11: at_hash = base64url-no-pad(left-half(SHA-256(access_token))),
    # computed here the same way the implementation does, against the NEW access token.
    expected_at_hash = (
        base64.urlsafe_b64encode(hashlib.sha256(body["access_token"].encode()).digest()[:16])
        .rstrip(b"=")
        .decode()
    )
    assert claims["at_hash"] == expected_at_hash


async def test_refresh_without_openid_scope_has_no_id_token(client_app):
    resp, _ = await run_code_flow(client_app, scope="read")
    resp2 = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": resp.json()["refresh_token"]},
        basic_auth=("client1", "s3cret"),
    )
    assert resp2.json().get("id_token") is None


# --- grant-type allow-list enforcement (Task 4) -------------------------------


async def test_auth_code_grant_requires_allowlist(client_app):
    await reseed_client(client_app, grant_types=["client_credentials"])
    resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": "x",
            "redirect_uri": "https://a.example/cb",
        },
        basic_auth=("client1", "s3cret"),
    )
    assert (resp.status_code, resp.json()["error"]) == (400, "unauthorized_client")


async def test_refresh_grant_requires_allowlist(client_app):
    await reseed_client(client_app, grant_types=["client_credentials"])
    resp = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": "x"},
        basic_auth=("client1", "s3cret"),
    )
    assert (resp.status_code, resp.json()["error"]) == (400, "unauthorized_client")


async def test_device_grant_requires_allowlist(client_app):
    await reseed_client(client_app, grant_types=["client_credentials"])
    resp = await post_token(
        client_app,
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": "x",
        },
        basic_auth=("client1", "s3cret"),
    )
    assert (resp.status_code, resp.json()["error"]) == (400, "unauthorized_client")


async def test_client_credentials_excess_scope_rejected(client_app):
    resp = await post_token(
        client_app,
        {"grant_type": "client_credentials", "scope": "read admin:everything"},
        basic_auth=("client1", "s3cret"),
    )
    assert (resp.status_code, resp.json()["error"]) == (400, "invalid_scope")
