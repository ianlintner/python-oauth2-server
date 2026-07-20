from tests.helpers import post_token, seed_client
from tests.test_token_endpoint import run_code_flow


async def post_introspect(
    client_app, token: str, basic_auth: tuple[str, str] | None = ("client1", "s3cret")
):
    import base64

    headers = {}
    if basic_auth is not None:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    return await client_app.post("/oauth/introspect", data={"token": token}, headers=headers)


async def post_revoke(client_app, token: str, basic_auth: tuple[str, str] | None):
    import base64

    headers = {}
    if basic_auth is not None:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    return await client_app.post("/oauth/revoke", data={"token": token}, headers=headers)


async def _client_credentials_token(client_app) -> str:
    resp = await post_token(
        client_app, {"grant_type": "client_credentials"}, basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


async def test_rfc7662_introspection_includes_nbf_jti_aud_iss(client_app):
    access_token = await _client_credentials_token(client_app)
    resp = await post_introspect(client_app, access_token, basic_auth=("client1", "s3cret"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["active"] is True
    assert body["nbf"] is not None
    assert body["jti"] is not None
    assert body["aud"] is not None
    assert body["iss"] == "https://auth.example.com"
    assert body["aud"] == "client1"


async def test_rfc7662_introspection_nbf_le_iat(client_app):
    access_token = await _client_credentials_token(client_app)
    resp = await post_introspect(client_app, access_token, basic_auth=("client1", "s3cret"))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["nbf"] <= body["iat"]


async def test_revoke_cascades_to_entire_token_family(client_app):
    resp, _code = await run_code_flow(client_app)
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]
    refresh_token = resp.json()["refresh_token"]

    revoke_resp = await post_revoke(client_app, access_token, basic_auth=("client1", "s3cret"))
    assert revoke_resp.status_code == 200
    assert revoke_resp.json() == {}

    access_introspect = await post_introspect(
        client_app, access_token, basic_auth=("client1", "s3cret")
    )
    assert access_introspect.json() == {"active": False}

    refresh_introspect = await post_introspect(
        client_app, refresh_token, basic_auth=("client1", "s3cret")
    )
    assert refresh_introspect.json() == {"active": False}


async def test_introspection_requires_client_auth(client_app):
    access_token = await _client_credentials_token(client_app)
    resp = await post_introspect(client_app, access_token, basic_auth=None)
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def test_introspection_cross_client_returns_inactive(client_app):
    await seed_client(
        client_app.storage,
        client_id="client2",
        client_secret="s3cret2",
        grant_types='["client_credentials"]',
    )
    access_token = await _client_credentials_token(client_app)
    resp = await post_introspect(client_app, access_token, basic_auth=("client2", "s3cret2"))
    assert resp.status_code == 200
    assert resp.json() == {"active": False}


async def test_revoke_cross_client_preserves_token(client_app):
    await seed_client(
        client_app.storage,
        client_id="client2",
        client_secret="s3cret2",
        grant_types='["client_credentials"]',
    )
    access_token = await _client_credentials_token(client_app)

    revoke_resp = await post_revoke(client_app, access_token, basic_auth=("client2", "s3cret2"))
    assert revoke_resp.status_code == 200
    assert revoke_resp.json() == {}

    introspect_resp = await post_introspect(
        client_app, access_token, basic_auth=("client1", "s3cret")
    )
    assert introspect_resp.json()["active"] is True


async def test_revoke_unknown_token_returns_200(client_app):
    resp = await post_revoke(client_app, "unknown-token-value", basic_auth=("client1", "s3cret"))
    assert resp.status_code == 200
    assert resp.json() == {}


async def test_introspect_unknown_token_inactive(client_app):
    resp = await post_introspect(
        client_app, "unknown-token-value", basic_auth=("client1", "s3cret")
    )
    assert resp.status_code == 200
    assert resp.json() == {"active": False}


async def test_refresh_token_introspects_with_refresh_expiry(client_app):
    resp, _ = await run_code_flow(client_app, scope="read")
    body = resp.json()
    intro = await post_introspect(client_app, body["refresh_token"])
    data = intro.json()
    assert data["active"] is True
    # exp reflects the refresh TTL (86400), not the access TTL (3600).
    assert data["exp"] - data["iat"] > 3600
