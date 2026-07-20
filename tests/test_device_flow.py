import re

import jwt

from tests.helpers import login_session, post_token, reseed_client, seed_client

_USER_CODE_RE = re.compile(r"^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$")


async def start_device_flow(client_app, *, client_id="client1", client_secret="s3cret", scope=None):
    import base64

    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    data = {"scope": scope} if scope else {}
    return await client_app.post(
        "/oauth/device_authorization",
        data=data,
        headers={"Authorization": f"Basic {basic}"},
    )


async def poll_device_token(
    client_app, device_code: str, *, client_id="client1", client_secret="s3cret", headers=None
):
    return await post_token(
        client_app,
        {"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": device_code},
        basic_auth=(client_id, client_secret),
        headers=headers,
    )


async def test_device_flow_pending_then_approved_returns_token(client_app):
    resp = await start_device_flow(client_app)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert _USER_CODE_RE.match(body["user_code"])
    assert body["interval"] == 5
    assert body["expires_in"] == 600
    assert body["verification_uri"] == "https://auth.example.com/oauth/device/verify"
    assert body["verification_uri_complete"] == (
        f"https://auth.example.com/oauth/device/verify?user_code={body['user_code']}"
    )
    assert len(body["device_code"]) >= 43
    assert resp.headers["cache-control"] == "no-store"

    device_code = body["device_code"]
    user_code = body["user_code"]

    pending = await poll_device_token(client_app, device_code)
    assert pending.status_code == 400
    assert pending.json()["error"] == "authorization_pending"

    login_resp = await login_session(client_app)
    assert login_resp.status_code == 303

    verify_resp = await client_app.post(
        "/oauth/device/verify", data={"user_code": user_code, "action": "approve"}
    )
    assert verify_resp.status_code == 200, verify_resp.text
    assert verify_resp.json() == {"status": "approved"}

    success = await poll_device_token(client_app, device_code)
    assert success.status_code == 200, success.text
    token_body = success.json()
    assert token_body["access_token"]
    assert token_body["refresh_token"]

    introspect_basic = ("client1", "s3cret")
    import base64

    raw = f"{introspect_basic[0]}:{introspect_basic[1]}".encode()
    introspect_resp = await client_app.post(
        "/oauth/introspect",
        data={"token": token_body["access_token"]},
        headers={"Authorization": "Basic " + base64.b64encode(raw).decode()},
    )
    assert introspect_resp.status_code == 200, introspect_resp.text
    introspect_body = introspect_resp.json()
    assert introspect_body["active"] is True
    assert introspect_body["sub"] == "u1"

    replay = await poll_device_token(client_app, device_code)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"


async def test_device_flow_denied(client_app):
    resp = await start_device_flow(client_app)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    device_code = body["device_code"]
    user_code = body["user_code"]

    await login_session(client_app)
    verify_resp = await client_app.post(
        "/oauth/device/verify", data={"user_code": user_code, "action": "deny"}
    )
    assert verify_resp.status_code == 200, verify_resp.text
    assert verify_resp.json() == {"status": "denied"}

    poll = await poll_device_token(client_app, device_code)
    assert poll.status_code == 400
    assert poll.json()["error"] == "access_denied"


async def test_device_flow_wrong_client_cannot_redeem(client_app):
    await seed_client(
        client_app.storage,
        client_id="client2",
        client_secret="s3cret2",
        grant_types='["urn:ietf:params:oauth:grant-type:device_code"]',
    )

    resp = await start_device_flow(client_app, client_id="client1", client_secret="s3cret")
    assert resp.status_code == 200, resp.text
    device_code = resp.json()["device_code"]

    poll = await poll_device_token(
        client_app, device_code, client_id="client2", client_secret="s3cret2"
    )
    assert poll.status_code == 400
    assert poll.json()["error"] == "invalid_grant"


async def test_discovery_advertises_device_authorization_endpoint(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert (
        resp.json()["device_authorization_endpoint"]
        == "https://auth.example.com/oauth/device_authorization"
    )


async def test_device_verify_requires_login(client_app):
    resp = await start_device_flow(client_app)
    assert resp.status_code == 200, resp.text
    user_code = resp.json()["user_code"]

    verify_resp = await client_app.post(
        "/oauth/device/verify", data={"user_code": user_code, "action": "approve"}
    )
    assert verify_resp.status_code == 401


async def test_device_authorization_requires_allowlist(client_app):
    await reseed_client(client_app, grant_types=["client_credentials"])
    resp = await start_device_flow(client_app)
    assert resp.status_code == 400
    assert resp.json()["error"] == "unauthorized_client"


async def test_device_flow_mints_id_token_for_openid_scope(client_app):
    """Parity with the Rust device-grant issuance site (oauth.rs:1830):
    when the granted scope includes "openid" and the device authorization
    has an approving user_id, the token response carries an id_token built
    the same way as the refresh-token branch (no nonce, no c_hash, at_hash
    over the newly-issued access token)."""
    resp = await start_device_flow(client_app, scope="openid email")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    device_code = body["device_code"]
    user_code = body["user_code"]

    login_resp = await login_session(client_app)
    assert login_resp.status_code == 303

    verify_resp = await client_app.post(
        "/oauth/device/verify", data={"user_code": user_code, "action": "approve"}
    )
    assert verify_resp.status_code == 200, verify_resp.text

    success = await poll_device_token(client_app, device_code)
    assert success.status_code == 200, success.text
    token_body = success.json()
    assert token_body.get("id_token")

    claims = jwt.decode(token_body["id_token"], options={"verify_signature": False})
    assert claims["sub"] == "u1"
    assert claims["aud"] == "client1"
    assert claims["email"] == "user_rfc@example.test"
    assert "nonce" not in claims
    assert "c_hash" not in claims
    assert claims["at_hash"]


async def test_device_flow_without_openid_scope_has_no_id_token(client_app):
    resp = await start_device_flow(client_app, scope="read")
    body = resp.json()
    device_code = body["device_code"]
    user_code = body["user_code"]

    await login_session(client_app)
    await client_app.post(
        "/oauth/device/verify", data={"user_code": user_code, "action": "approve"}
    )

    success = await poll_device_token(client_app, device_code)
    assert success.status_code == 200, success.text
    assert success.json().get("id_token") is None
