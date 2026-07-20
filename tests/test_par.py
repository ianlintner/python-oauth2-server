"""RFC 9126 pushed authorization requests.

Ported from `tests/compliance_wave3.rs` (push-endpoint tests) plus new
authorize-side coverage the Rust suite lacks (single-use, expiry, client
mismatch, param precedence).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

from oauth2_server.services import par as par_service
from tests.helpers import login_session, post_token, seed_client


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.rstrip(b"=").decode()


def _basic_header(client_id: str, client_secret: str) -> dict:
    raw = f"{client_id}:{client_secret}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


# --- POST /oauth/par (ported from compliance_wave3.rs) -----------------------


async def test_rfc9126_par_public_client_returns_request_uri(client_app):
    await seed_client(
        client_app.storage,
        client_id="par_pub",
        client_secret="",
        redirect_uris='["https://example.com/cb"]',
        token_endpoint_auth_method="none",
    )
    resp = await client_app.post(
        "/oauth/par",
        content=(
            "client_id=par_pub&response_type=code&scope=read"
            "&redirect_uri=https%3A%2F%2Fexample.com%2Fcb"
        ),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["request_uri"].startswith("urn:ietf:params:oauth:request-uri:")
    assert body["expires_in"] == 60
    assert resp.headers["cache-control"] == "no-store"


async def test_rfc9126_par_missing_response_type_is_rejected(client_app):
    await seed_client(
        client_app.storage,
        client_id="par_nort",
        client_secret="",
        redirect_uris='["https://example.com/cb"]',
        token_endpoint_auth_method="none",
    )
    resp = await client_app.post(
        "/oauth/par",
        content="client_id=par_nort&scope=read",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert resp.json()["error_description"] == "Missing response_type in PAR request"


async def test_rfc9126_par_duplicate_param_is_rejected(client_app):
    await seed_client(
        client_app.storage,
        client_id="par_dup",
        client_secret="",
        redirect_uris='["https://example.com/cb"]',
        token_endpoint_auth_method="none",
    )
    resp = await client_app.post(
        "/oauth/par",
        content="client_id=par_dup&response_type=code&scope=read&scope=write",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert resp.json()["error_description"] == "Duplicate parameter in PAR request"


async def test_rfc9126_par_confidential_client_no_secret_rejected(client_app):
    await seed_client(
        client_app.storage,
        client_id="par_conf",
        client_secret="par_conf_secret",
        redirect_uris='["https://example.com/cb"]',
    )
    resp = await client_app.post(
        "/oauth/par",
        content="client_id=par_conf&response_type=code&scope=read",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def test_rfc9126_par_confidential_client_with_basic_auth_succeeds(client_app):
    await seed_client(
        client_app.storage,
        client_id="par_conf_ok",
        client_secret="par_conf_ok_secret",
        redirect_uris='["https://example.com/cb"]',
    )
    resp = await client_app.post(
        "/oauth/par",
        content="client_id=par_conf_ok&response_type=code&scope=read",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            **_basic_header("par_conf_ok", "par_conf_ok_secret"),
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["request_uri"].startswith("urn:ietf:params:oauth:request-uri:")


async def test_rfc9126_par_invalid_body_encoding_is_rejected(client_app):
    resp = await client_app.post(
        "/oauth/par",
        content=b"client_id=client1&response_type=code&scope=\xff\xfe",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert resp.json()["error_description"] == "Invalid PAR request body encoding"


# --- GET /oauth/authorize consumption (new coverage) --------------------------


async def _push_client1_par(client_app, **extra) -> str:
    data = {
        "client_id": "client1",
        "response_type": "code",
        "redirect_uri": "https://a.example/cb",
        "scope": "read",
        **extra,
    }
    resp = await client_app.post(
        "/oauth/par",
        data=data,
        headers=_basic_header("client1", "s3cret"),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["request_uri"]


async def test_par_request_uri_full_flow(client_app):
    verifier, challenge = _pkce_pair()
    request_uri = await _push_client1_par(
        client_app, code_challenge=challenge, code_challenge_method="S256"
    )

    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client1", "response_type": "code"},
    )
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    code = q["code"][0]

    token_resp = await post_token(
        client_app,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://a.example/cb",
            "client_id": "client1",
            "code_verifier": verifier,
        },
        basic_auth=("client1", "s3cret"),
    )
    assert token_resp.status_code == 200, token_resp.text
    assert "access_token" in token_resp.json()


async def test_par_request_uri_is_single_use(client_app):
    request_uri = await _push_client1_par(client_app)

    await login_session(client_app)
    first = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client1", "response_type": "code"},
    )
    assert first.status_code == 302, first.text

    second = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client1", "response_type": "code"},
    )
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_request"
    assert second.json()["error_description"] == "Unknown or expired request_uri"


async def test_par_request_uri_duplicate_query_param_does_not_consume_entry(client_app):
    """Task 6 review carry-over: the duplicate-query-param check (step 0 in
    `authorize()`) runs before PAR resolution (step 1), so a malformed
    request repeating `request_uri` must 400 without taking the entry out of
    the store — a well-formed follow-up request with the same (single-use)
    `request_uri` still succeeds."""
    request_uri = await _push_client1_par(client_app)

    await login_session(client_app)
    probe = await client_app.get(
        "/oauth/authorize",
        params=[
            ("request_uri", request_uri),
            ("request_uri", request_uri),
            ("client_id", "client1"),
            ("response_type", "code"),
        ],
    )
    assert probe.status_code == 400
    assert probe.json()["error"] == "invalid_request"
    assert "duplicate query parameter" in probe.json()["error_description"]

    follow_up = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client1", "response_type": "code"},
    )
    assert follow_up.status_code == 302, follow_up.text


async def test_par_request_uri_client_mismatch_consumes_entry(client_app):
    await seed_client(
        client_app.storage,
        client_id="client2",
        client_secret="s3cret2",
        redirect_uris='["https://b.example/cb"]',
    )
    request_uri = await _push_client1_par(client_app)

    await login_session(client_app)
    wrong = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client2", "response_type": "code"},
    )
    assert wrong.status_code == 401
    assert wrong.json()["error"] == "invalid_client"
    assert wrong.json()["error_description"] == "request_uri client_id mismatch"

    # The entry was consumed (destructively removed) even though the
    # binding check failed — Rust parity.
    again = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client1", "response_type": "code"},
    )
    assert again.status_code == 400
    assert again.json()["error_description"] == "Unknown or expired request_uri"


async def test_par_request_uri_expires(client_app, monkeypatch):
    request_uri = await _push_client1_par(client_app)

    real_monotonic = par_service.time.monotonic
    monkeypatch.setattr(par_service.time, "monotonic", lambda: real_monotonic() + 61)

    await login_session(client_app)
    resp = await client_app.get(
        "/oauth/authorize",
        params={"request_uri": request_uri, "client_id": "client1", "response_type": "code"},
    )
    assert resp.status_code == 400
    assert resp.json()["error_description"] == "Unknown or expired request_uri"
