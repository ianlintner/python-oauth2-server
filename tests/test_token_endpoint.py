import jwt

from tests.helpers import post_token, seed_client


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
