"""RFC 9396 rich authorization requests (RAR).

Ported per `.superpowers/sdd/research-rar-token-exchange.md`: the Rust
server accepts `authorization_details` at authorize/PAR/token with almost no
validation (JSON-parse-only at the token endpoint, nothing at authorize/PAR)
despite discovery hardcoding `authorization_details_types_supported:
["openid"]` — and never echoes it in the token response or introspection.
This suite covers the FIXED gaps: type-allowlist validation, response echo
(RFC 9396 §7.1), introspection inclusion (§9.2), and "stored details win" at
authorization_code redemption — plus the KEPT gaps (refresh/device drop,
opaque-mode loss) as parity pins.
"""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, urlparse

import jwt

from tests.helpers import login_session, post_token

_VALID_DETAILS = [{"type": "openid", "actions": ["read"]}]


def _basic_header(client_id: str, client_secret: str) -> dict:
    raw = f"{client_id}:{client_secret}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


async def _authorize_and_get_code(client_app, **extra_query) -> str:
    await login_session(client_app)
    params = {
        "client_id": "client1",
        "response_type": "code",
        "redirect_uri": "https://a.example/cb",
        "scope": "read",
        **extra_query,
    }
    resp = await client_app.get("/oauth/authorize", params=params)
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    return q["code"][0]


# --- Discovery ---------------------------------------------------------------


async def test_discovery_advertises_rar_types(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    body = resp.json()
    assert body["authorization_details_types_supported"] == ["openid"]


# --- GET /oauth/authorize validation ------------------------------------------


async def test_authorize_rejects_unknown_rar_type(client_app):
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "client_id": "client1",
            "response_type": "code",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "authorization_details": json.dumps(
                [{"type": "payment_initiation", "actions": ["read"]}]
            ),
        },
    )
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"][0] == "invalid_authorization_details"
    assert "payment_initiation" in q["error_description"][0]


async def test_authorize_rejects_malformed_rar(client_app):
    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params={
            "client_id": "client1",
            "response_type": "code",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "authorization_details": "not-json{",
        },
    )
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"][0] == "invalid_authorization_details"
    assert "not valid JSON" in q["error_description"][0]


# --- Full flow: authorize -> token -> introspect ------------------------------


async def test_full_flow_embeds_details_in_jwt_and_response(client_app):
    code = await _authorize_and_get_code(
        client_app, authorization_details=json.dumps(_VALID_DETAILS)
    )

    token_resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
        },
        basic_auth=("client1", "s3cret"),
    )
    assert token_resp.status_code == 200, token_resp.text
    body = token_resp.json()
    assert body["authorization_details"] == _VALID_DETAILS

    access_token = body["access_token"]
    claims = jwt.decode(access_token, options={"verify_signature": False})
    assert claims["authorization_details"] == _VALID_DETAILS

    introspect_resp = await client_app.post(
        "/oauth/introspect",
        data={"token": access_token},
        headers=_basic_header("client1", "s3cret"),
    )
    assert introspect_resp.status_code == 200, introspect_resp.text
    introspect_body = introspect_resp.json()
    assert introspect_body["active"] is True
    assert introspect_body["authorization_details"] == _VALID_DETAILS


# --- Redemption divergence semantics ------------------------------------------


async def test_redemption_rejects_altered_details(client_app):
    code = await _authorize_and_get_code(
        client_app, authorization_details=json.dumps(_VALID_DETAILS)
    )

    altered = json.dumps([{"type": "openid", "actions": ["write"]}])
    bad_resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
            "authorization_details": altered,
        },
        basic_auth=("client1", "s3cret"),
    )
    assert bad_resp.status_code == 400, bad_resp.text
    assert bad_resp.json()["error"] == "invalid_authorization_details"
    assert (
        bad_resp.json()["error_description"]
        == "authorization_details must not be altered at redemption"
    )

    # The code must NOT have been consumed and the family must NOT have been
    # revoked — this is a validation error, not a replay. A follow-up
    # redemption with no (or a matching) authorization_details value still
    # succeeds using the STORED value.
    good_resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
        },
        basic_auth=("client1", "s3cret"),
    )
    assert good_resp.status_code == 200, good_resp.text
    assert good_resp.json()["authorization_details"] == _VALID_DETAILS


# --- client_credentials --------------------------------------------------------


async def test_client_credentials_details_validated_and_embedded(client_app):
    bad_resp = await post_token(
        client_app,
        {
            "grant_type": "client_credentials",
            "authorization_details": json.dumps(
                [{"type": "unsupported_type", "actions": ["read"]}]
            ),
        },
        basic_auth=("client1", "s3cret"),
    )
    assert bad_resp.status_code == 400, bad_resp.text
    assert bad_resp.json()["error"] == "invalid_authorization_details"

    good_resp = await post_token(
        client_app,
        {
            "grant_type": "client_credentials",
            "authorization_details": json.dumps(_VALID_DETAILS),
        },
        basic_auth=("client1", "s3cret"),
    )
    assert good_resp.status_code == 200, good_resp.text
    body = good_resp.json()
    assert body["authorization_details"] == _VALID_DETAILS

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["authorization_details"] == _VALID_DETAILS


# --- refresh_token drop (Rust parity) ------------------------------------------


async def test_refresh_drops_details(client_app):
    code = await _authorize_and_get_code(
        client_app, authorization_details=json.dumps(_VALID_DETAILS)
    )

    initial = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
        },
        basic_auth=("client1", "s3cret"),
    )
    assert initial.status_code == 200, initial.text
    initial_body = initial.json()
    assert initial_body["authorization_details"] == _VALID_DETAILS

    refreshed = await post_token(
        client_app,
        {
            "grant_type": "refresh_token",
            "refresh_token": initial_body["refresh_token"],
            "client_id": "client1",
        },
        basic_auth=("client1", "s3cret"),
    )
    assert refreshed.status_code == 200, refreshed.text
    refreshed_body = refreshed.json()
    assert "authorization_details" not in refreshed_body

    claims = jwt.decode(refreshed_body["access_token"], options={"verify_signature": False})
    assert "authorization_details" not in claims


# --- PAR-pushed details flow ---------------------------------------------------


async def test_par_pushed_details_flow(client_app):
    par_resp = await client_app.post(
        "/oauth/par",
        data={
            "client_id": "client1",
            "response_type": "code",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "authorization_details": json.dumps(_VALID_DETAILS),
        },
        headers=_basic_header("client1", "s3cret"),
    )
    assert par_resp.status_code == 201, par_resp.text
    request_uri = par_resp.json()["request_uri"]

    await login_session(client_app)
    auth_resp = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client1", "response_type": "code"},
    )
    assert auth_resp.status_code == 302, auth_resp.text
    q = parse_qs(urlparse(auth_resp.headers["location"]).query)
    code = q["code"][0]

    token_resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
        },
        basic_auth=("client1", "s3cret"),
    )
    assert token_resp.status_code == 200, token_resp.text
    body = token_resp.json()
    assert body["authorization_details"] == _VALID_DETAILS

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["authorization_details"] == _VALID_DETAILS
