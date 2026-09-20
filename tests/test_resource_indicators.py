"""RFC 8707 Resource Indicators — the `resource` parameter bound to the access-token `aud`.

Parity notes (Rust `crates/oauth2-actix/src/actors/token_actor.rs`):
- no resource -> `aud` stays `[client_id]`;
- the authorization_code grant uses the resource STORED on the code, ignoring
  any form value at redemption;
- refresh used to pass its own `resource` straight through; divergence 60
  now enforces RFC 8707 §2.2's "subset of the originally granted audience"
  rule and carries the old `aud` forward when no `resource` is sent.

Divergence 32 (beyond Rust): the value is validated as an absolute URI with no
fragment and rejected with `invalid_target` (RFC 8707 §2); Rust accepts any string.
"""

import base64
from urllib.parse import parse_qs, urlparse

import jwt

from tests.conftest import build_client_app
from tests.helpers import login_session, post_token
from tests.test_device_flow import start_device_flow
from tests.test_token_endpoint import _pkce_pair, run_code_flow

ISSUER = "https://auth.example.com"
REDIRECT_URI = "https://a.example/cb"
RESOURCE = "https://api.resource.test"
URN_RESOURCE = "urn:example:api"
OTHER_RESOURCE = "https://other.resource.test"
BASIC = ("client1", "s3cret")


def _claims(access_token: str) -> dict:
    return jwt.decode(access_token, options={"verify_signature": False})


async def _client_credentials(client_app, resource: str | None = None):
    data = {"grant_type": "client_credentials"}
    if resource is not None:
        data["resource"] = resource
    return await post_token(client_app, data, basic_auth=BASIC)


async def _authorize(client_app, resource: str | None = None) -> tuple[object, str]:
    """Log in and GET /oauth/authorize with PKCE + an optional `resource`."""
    await login_session(client_app)
    verifier, challenge = _pkce_pair()
    params = {
        "response_type": "code",
        "client_id": "client1",
        "redirect_uri": REDIRECT_URI,
        "scope": "read",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if resource is not None:
        params["resource"] = resource
    return await client_app.get("/oauth/authorize", params=params), verifier


async def test_vector_m_resource_to_aud_claim(client_app):
    resp = await _client_credentials(client_app, RESOURCE)
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]
    assert jwt.get_unverified_header(access_token)["typ"] == "at+JWT"
    claims = _claims(access_token)
    # Single audience serializes as a bare string (Rust serde parity).
    assert claims["aud"] == RESOURCE
    assert claims["client_id"] == "client1"
    assert claims["iss"] == ISSUER


async def test_rfc8707_resource_indicator_accepted_in_client_credentials(client_app):
    resp = await _client_credentials(client_app, RESOURCE)
    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "Bearer"


async def test_resource_absent_keeps_client_id_aud(client_app):
    resp = await _client_credentials(client_app)
    assert resp.status_code == 200, resp.text
    assert _claims(resp.json()["access_token"])["aud"] == "client1"


async def test_resource_on_authorize_is_stored_on_code_and_bound_to_token_aud(client_app):
    resp, verifier = await _authorize(client_app, RESOURCE)
    assert resp.status_code == 302, resp.text
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]

    stored = await client_app.storage.get_authorization_code(code)
    assert stored.resource == RESOURCE

    token_resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "client1",
            "code_verifier": verifier,
            # Rust parity: the stored value wins; this form value is ignored.
            "resource": OTHER_RESOURCE,
        },
        basic_auth=BASIC,
    )
    assert token_resp.status_code == 200, token_resp.text
    assert _claims(token_resp.json()["access_token"])["aud"] == RESOURCE


async def _code_flow(client_app, resource: str | None = None) -> dict:
    """Full authorization_code flow with an optional `resource`; token body."""
    resp, verifier = await _authorize(client_app, resource)
    assert resp.status_code == 302, resp.text
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
    token_resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "client1",
            "code_verifier": verifier,
        },
        basic_auth=BASIC,
    )
    assert token_resp.status_code == 200, token_resp.text
    return token_resp.json()


async def _refresh(client_app, refresh_token: str, resource: str | None = None):
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    if resource is not None:
        data["resource"] = resource
    return await post_token(client_app, data, basic_auth=BASIC)


async def test_refresh_with_in_set_resource_narrows(client_app):
    """Divergence 60: a `resource` already in the old token's `aud` is honored."""
    issued = await _code_flow(client_app, RESOURCE)
    assert _claims(issued["access_token"])["aud"] == RESOURCE

    refreshed = await _refresh(client_app, issued["refresh_token"], RESOURCE)
    assert refreshed.status_code == 200, refreshed.text
    assert _claims(refreshed.json()["access_token"])["aud"] == RESOURCE


async def test_refresh_with_out_of_set_resource_invalid_target_and_token_survives(client_app):
    """RFC 8707 §2.2: refresh may narrow the granted audience set, never widen it.

    The rejection lands BEFORE any revocation, so the refresh token (and its
    family) survives for the client's corrected retry.
    """
    issued = await _code_flow(client_app, RESOURCE)
    refresh_token = issued["refresh_token"]

    rejected = await _refresh(client_app, refresh_token, OTHER_RESOURCE)
    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["error"] == "invalid_target"
    assert "originally granted" in rejected.json()["error_description"]

    retried = await _refresh(client_app, refresh_token)
    assert retried.status_code == 200, retried.text
    assert _claims(retried.json()["access_token"])["aud"] == RESOURCE


async def test_refresh_without_resource_keeps_old_aud(client_app):
    """No `resource` on refresh carries the old `aud` forward (it does NOT
    widen back to `[client_id]`, which is what this port did through 4b)."""
    issued = await _code_flow(client_app, RESOURCE)
    refreshed = await _refresh(client_app, issued["refresh_token"])
    assert refreshed.status_code == 200, refreshed.text
    assert _claims(refreshed.json()["access_token"])["aud"] == RESOURCE


async def test_refresh_without_granted_resource_still_rejects_new_one(client_app):
    """A grant with no `resource` has `aud == [client_id]`; refresh cannot
    invent a resource audience that was never granted."""
    issued = await _code_flow(client_app)
    assert _claims(issued["access_token"])["aud"] == "client1"

    rejected = await _refresh(client_app, issued["refresh_token"], RESOURCE)
    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["error"] == "invalid_target"


async def test_refresh_opaque_mode_unchanged(client_app):
    """An opaque old access token carries no readable `aud`, so the subset
    check cannot apply and today's pass-through behavior is kept."""
    async with build_client_app({"access_tokens_opaque": True}) as opaque_app:
        issued = await _code_flow(opaque_app)
        refreshed = await _refresh(opaque_app, issued["refresh_token"], RESOURCE)
        assert refreshed.status_code == 200, refreshed.text
        assert "." not in refreshed.json()["access_token"]


async def test_resource_on_device_grant_binds_aud(client_app):
    start = await start_device_flow(client_app)
    assert start.status_code == 200, start.text
    device_code = start.json()["device_code"]
    user_code = start.json()["user_code"]

    await login_session(client_app)
    approve = await client_app.post(
        "/oauth/device/verify", data={"user_code": user_code, "action": "approve"}
    )
    assert approve.status_code == 200, approve.text

    resp = await post_token(
        client_app,
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "resource": RESOURCE,
        },
        basic_auth=BASIC,
    )
    assert resp.status_code == 200, resp.text
    assert _claims(resp.json()["access_token"])["aud"] == RESOURCE


async def test_invalid_resource_on_refresh_does_not_revoke_token_family(client_app):
    """A rejected `resource` must leave the refresh token (and its family) intact.

    The value is validated before the old token is revoked, so the client's
    corrected retry is an ordinary refresh — not refresh-token reuse, which
    would revoke the whole family.
    """
    resp, _ = await run_code_flow(client_app)
    assert resp.status_code == 200, resp.text
    refresh_token = resp.json()["refresh_token"]

    rejected = await post_token(
        client_app,
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "resource": "not-an-absolute-uri",
        },
        basic_auth=BASIC,
    )
    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["error"] == "invalid_target"

    retried = await post_token(
        client_app,
        {"grant_type": "refresh_token", "refresh_token": refresh_token},
        basic_auth=BASIC,
    )
    assert retried.status_code == 200, retried.text
    assert _claims(retried.json()["access_token"])["aud"] == "client1"


async def test_urn_resource_accepted_as_aud(client_app):
    # RFC 3986 §4.3: an absolute URI's hier-part need not carry an authority.
    resp = await _client_credentials(client_app, URN_RESOURCE)
    assert resp.status_code == 200, resp.text
    assert _claims(resp.json()["access_token"])["aud"] == URN_RESOURCE


async def test_scheme_only_resource_rejected_invalid_target(client_app):
    resp = await _client_credentials(client_app, "https:")
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_target"


async def test_relative_resource_rejected_invalid_target(client_app):
    resp = await _client_credentials(client_app, "/api/resource")
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["error"] == "invalid_target"
    assert body["error_description"] == "resource must be an absolute URI without a fragment"


async def test_resource_with_fragment_rejected_invalid_target(client_app):
    resp = await _client_credentials(client_app, "https://api.resource.test/data#section")
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_target"


async def test_authorize_invalid_resource_redirects_with_invalid_target(client_app):
    resp, _ = await _authorize(client_app, "not-an-absolute-uri")
    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    assert location.startswith(REDIRECT_URI)
    query = parse_qs(urlparse(location).query)
    assert query["error"] == ["invalid_target"]
    assert query["iss"] == [ISSUER]
    assert "code" not in query


async def test_introspection_aud_reflects_resource(client_app):
    resp = await _client_credentials(client_app, RESOURCE)
    assert resp.status_code == 200, resp.text
    access_token = resp.json()["access_token"]

    raw = f"{BASIC[0]}:{BASIC[1]}".encode()
    introspect = await client_app.post(
        "/oauth/introspect",
        data={"token": access_token},
        headers={"Authorization": "Basic " + base64.b64encode(raw).decode()},
    )
    assert introspect.status_code == 200, introspect.text
    body = introspect.json()
    assert body["active"] is True
    assert body["aud"] == RESOURCE
