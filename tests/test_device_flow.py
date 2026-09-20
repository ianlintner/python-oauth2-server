import re

import jwt

import oauth2_server.services.device_poll as device_poll_module
from oauth2_server.services.device_poll import ENTRY_TTL_SECS, DevicePollTracker
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


async def test_device_flow_pending_then_approved_returns_token(client_app, monkeypatch):
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

    # RFC 8628 slow_down (services/device_poll.py): the pending poll above
    # and this one would otherwise land within the same tracked interval
    # (well under a second apart in a fast test run) and get "slow_down"
    # instead of a token. Advance the tracker's clock past the device's
    # 5s interval so this poll is treated as respecting it.
    real_monotonic = device_poll_module.time.monotonic
    monkeypatch.setattr(device_poll_module.time, "monotonic", lambda: real_monotonic() + 5)

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


# --- RFC 8628 §3.5 slow_down (services/device_poll.py) ---------------------


async def test_device_poll_faster_than_interval_returns_slow_down(client_app):
    resp = await start_device_flow(client_app)
    assert resp.status_code == 200, resp.text
    device_code = resp.json()["device_code"]

    first = await poll_device_token(client_app, device_code)
    assert first.status_code == 400
    assert first.json()["error"] == "authorization_pending"

    second = await poll_device_token(client_app, device_code)
    assert second.status_code == 400
    body = second.json()
    assert body["error"] == "slow_down"
    assert body["interval"] == 10
    assert second.headers["cache-control"] == "no-store"


async def test_device_poll_respecting_interval_returns_authorization_pending(
    client_app, monkeypatch
):
    resp = await start_device_flow(client_app)
    assert resp.status_code == 200, resp.text
    device_code = resp.json()["device_code"]

    first = await poll_device_token(client_app, device_code)
    assert first.status_code == 400
    assert first.json()["error"] == "authorization_pending"

    real_monotonic = device_poll_module.time.monotonic
    monkeypatch.setattr(device_poll_module.time, "monotonic", lambda: real_monotonic() + 5)

    second = await poll_device_token(client_app, device_code)
    assert second.status_code == 400
    assert second.json()["error"] == "authorization_pending"


async def test_slow_down_escalates_required_interval(client_app):
    resp = await start_device_flow(client_app)
    assert resp.status_code == 200, resp.text
    device_code = resp.json()["device_code"]

    first = await poll_device_token(client_app, device_code)
    assert first.json()["error"] == "authorization_pending"

    second = await poll_device_token(client_app, device_code)
    assert second.json()["error"] == "slow_down"
    assert second.json()["interval"] == 10

    third = await poll_device_token(client_app, device_code)
    assert third.json()["error"] == "slow_down"
    assert third.json()["interval"] == 15


async def test_slow_down_does_not_block_approved_redemption_after_wait(client_app, monkeypatch):
    resp = await start_device_flow(client_app)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    device_code = body["device_code"]
    user_code = body["user_code"]

    first = await poll_device_token(client_app, device_code)
    assert first.json()["error"] == "authorization_pending"

    await login_session(client_app)
    verify_resp = await client_app.post(
        "/oauth/device/verify", data={"user_code": user_code, "action": "approve"}
    )
    assert verify_resp.status_code == 200, verify_resp.text

    real_monotonic = device_poll_module.time.monotonic
    monkeypatch.setattr(device_poll_module.time, "monotonic", lambda: real_monotonic() + 5)

    success = await poll_device_token(client_app, device_code)
    assert success.status_code == 200, success.text
    assert success.json()["access_token"]


# --- DevicePollTracker unit tests -------------------------------------------


def test_device_poll_tracker_first_poll_is_allowed():
    tracker = DevicePollTracker()
    assert tracker.observe("dev1", 5) is None


def test_device_poll_tracker_forget_is_safe_on_unknown_code():
    tracker = DevicePollTracker()
    tracker.forget("does-not-exist")  # must not raise


def test_device_poll_tracker_forget_clears_violation_history(monkeypatch):
    real_monotonic = device_poll_module.time.monotonic
    tracker = DevicePollTracker()
    tracker.observe("dev1", 5)

    monkeypatch.setattr(device_poll_module.time, "monotonic", lambda: real_monotonic())
    assert tracker.observe("dev1", 5) == 10  # immediate re-poll: violation

    tracker.forget("dev1")

    # Forgotten code is treated as brand new: no leftover escalated interval.
    assert tracker.observe("dev1", 5) is None


def test_device_poll_tracker_sweeps_expired_entries(monkeypatch):
    real_monotonic = device_poll_module.time.monotonic
    tracker = DevicePollTracker()
    tracker.observe("dev1", 5)

    monkeypatch.setattr(
        device_poll_module.time, "monotonic", lambda: real_monotonic() + ENTRY_TTL_SECS + 1
    )

    # Entry swept: after 24h+1s of inactivity, a poll is treated as brand
    # new (allowed), not as a violation of stale state.
    assert tracker.observe("dev1", 5) is None
