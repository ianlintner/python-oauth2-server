import json
import secrets
from urllib.parse import parse_qs, urlparse

from tests.helpers import PKCE_CHALLENGE, login_session, reseed_client, seed_client


async def test_rfc9207_iss_included_in_authorization_response(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "state": "xyz",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["iss"] == ["https://auth.example.com"]
    assert q["state"] == ["xyz"]
    assert "code" in q


async def test_duplicate_query_parameter_rejected(app_with_session):
    resp = await app_with_session.get(
        "/oauth/authorize",
        params=[
            ("response_type", "code"),
            ("response_type", "code"),
            ("client_id", "client1"),
            ("redirect_uri", "https://a.example/cb"),
            ("scope", "read"),
        ],
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert "duplicate query parameter" in body["error_description"]


async def test_duplicate_query_parameter_rejected_before_client_validation(app_with_session):
    # A repeated key is rejected even when client_id doesn't correspond to
    # any registered client — the dupe check runs before anything else.
    resp = await app_with_session.get(
        "/oauth/authorize",
        params=[
            ("response_type", "code"),
            ("client_id", "no-such-client"),
            ("client_id", "no-such-client"),
        ],
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert "duplicate query parameter" in resp.json()["error_description"]


async def test_authorize_error_response_has_no_store_cache_control(app_with_session):
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "unknown-client",
            "redirect_uri": "https://a.example/cb",
        },
    )
    # An unknown client is unredirectable -> 401 invalid_client (RFC 6749 §4.1.1).
    assert resp.status_code == 401
    assert resp.headers["cache-control"] == "no-store"


async def test_unregistered_redirect_uri_never_redirects(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://evil.example/cb",
        },
    )
    assert resp.status_code == 400


async def test_public_client_requires_s256_pkce(app_with_session):
    await seed_client(
        app_with_session.storage,
        client_id="public-client",
        client_secret="",
        redirect_uris='["https://pub.example/cb"]',
        token_endpoint_auth_method="none",
    )
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "public-client",
            "redirect_uri": "https://pub.example/cb",
            "scope": "read",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["invalid_request"]


async def test_plain_pkce_method_rejected(app_with_session):
    await login_session(app_with_session)
    challenge = secrets.token_urlsafe(32)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "plain",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["invalid_request"]


async def test_implicit_response_type_rejected(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "token",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["unsupported_response_type"]


# --- return_to staleness hardening (login-CSRF) -------------------------------
#
# GET /oauth/authorize stores `return_to` (+ `return_to_ts`) in the session
# before redirecting to /auth/login. A stale return_to from an abandoned
# (possibly attacker-initiated) authorization request must NOT be replayed on
# a later unrelated login — only a fresh, timestamped return_to is honored.

_AUTHORIZE_PARAMS = {
    "response_type": "code",
    "client_id": "client1",
    "code_challenge": PKCE_CHALLENGE,
    "code_challenge_method": "S256",
    "redirect_uri": "https://a.example/cb",
    "scope": "read",
}


async def test_fresh_return_to_is_replayed_after_login(app_with_session):
    # Unauthenticated authorize request -> redirected to login, return_to saved.
    resp = await app_with_session.get("/oauth/authorize", params=_AUTHORIZE_PARAMS)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/auth/login"

    # Logging in promptly replays the pending authorize URL.
    resp = await login_session(app_with_session)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/oauth/authorize?")


async def test_stale_return_to_is_not_replayed_after_login(app_with_session, monkeypatch):
    import oauth2_server.routes.login as login_routes

    resp = await app_with_session.get("/oauth/authorize", params=_AUTHORIZE_PARAMS)
    assert resp.status_code == 302

    # Advance the clock past the freshness window, as seen by the login route.
    real_time = login_routes.time.time
    monkeypatch.setattr(
        login_routes.time,
        "time",
        lambda: real_time() + login_routes.RETURN_TO_MAX_AGE_SECS + 1,
    )

    resp = await login_session(app_with_session)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/", "stale return_to must not be replayed"


async def test_login_without_pending_authorize_does_not_replay(app_with_session):
    # A login not initiated by an authorize redirect has no return_to to honor.
    resp = await login_session(app_with_session)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


async def test_authorize_requires_authorization_code_grant(app_with_session):
    await reseed_client(app_with_session, grant_types=["client_credentials"])
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "state": "xyz",
        },
    )
    assert resp.status_code == 302
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["unauthorized_client"]
    assert q["state"] == ["xyz"]
    assert "iss" in q


# --- OIDC Core §5.5 `claims` request parameter (divergence 44) ---------------


async def test_claims_request_stored_on_code(app_with_session):
    claims = {"userinfo": {"email": {"essential": True}}}
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "claims": json.dumps(claims),
        },
    )
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    code = q["code"][0]

    stored = await app_with_session.storage.get_authorization_code(code)
    assert stored.claims_request == json.dumps(claims)


async def test_malformed_claims_rejected_via_redirect(app_with_session):
    await login_session(app_with_session)

    for bad_claims in (
        "not-json{",
        json.dumps(["not", "an", "object"]),
        json.dumps("a string"),
        "42",
    ):
        resp = await app_with_session.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "client1",
                "code_challenge": PKCE_CHALLENGE,
                "code_challenge_method": "S256",
                "redirect_uri": "https://a.example/cb",
                "scope": "read",
                "claims": bad_claims,
                "state": "xyz",
            },
        )
        assert resp.status_code == 302, resp.text
        q = parse_qs(urlparse(resp.headers["location"]).query)
        assert q["error"] == ["invalid_request"]
        assert q["error_description"] == ["claims must be a JSON object"]
        assert q["state"] == ["xyz"]


async def test_oversized_claims_rejected_via_redirect(app_with_session):
    """Divergence 57: `claims` is length-checked BEFORE `json.loads` sees it."""
    await login_session(app_with_session)
    oversized = json.dumps({"id_token": {"email": {"value": "x" * 9000}}})
    assert len(oversized) > 8192
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "claims": oversized,
        },
    )
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["invalid_request"]
    assert "exceeds the maximum length of 8192" in q["error_description"][0]
    assert "code" not in q


async def test_over_nested_claims_no_500(app_with_session):
    """A deeply nested `claims` is an `invalid_request` redirect, never a 500."""
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client1",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "redirect_uri": "https://a.example/cb",
            "scope": "read",
            "claims": "[" * 50 + "]" * 50,
        },
    )
    assert resp.status_code == 302, resp.text
    q = parse_qs(urlparse(resp.headers["location"]).query)
    assert q["error"] == ["invalid_request"]
    assert "exceeds the maximum nesting depth of 10" in q["error_description"][0]


# --- RFC 6749 §4.1.1 / §3.1.2 + RFC 8252 §7.3 loopback redirect matching ---


async def test_missing_client_id_rejected_400(app_with_session):
    # RFC 6749 §4.1.1: an authorization request WITHOUT client_id is a 400
    # (malformed request) — distinct from an *unknown* client_id, which is a
    # 401 invalid_client below.
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "redirect_uri": "https://client.example/callback",
            "state": "s-no-client",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


async def test_unknown_client_rejected_401_invalid_client(app_with_session):
    # RFC 6749 §4.1.1: an authorization request with an unknown client_id is
    # rejected with invalid_client — and, being unredirectable (no trusted
    # redirect_uri), carries HTTP 401 (the Rust reference's status), never a
    # redirect to the (untrusted) request's redirect_uri.
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "no-such-client",
            "redirect_uri": "https://client.example/callback",
            "state": "s-unknown-client",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


async def _seed_loopback_client(app_with_session, client_id, redirect_uris):
    import json

    await seed_client(
        app_with_session.storage,
        client_id=client_id,
        client_secret="",
        redirect_uris=json.dumps(redirect_uris),
        token_endpoint_auth_method="none",
    )


async def test_loopback_ipv4_redirect_matches_any_port(app_with_session):
    # RFC 8252 §7.3 / RFC 6749 §3.1.2: a loopback redirect URI registered
    # without a port (http://127.0.0.1/cb) matches any port at request time.
    await _seed_loopback_client(app_with_session, "client-loopback-v4", ["http://127.0.0.1/cb"])
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client-loopback-v4",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "redirect_uri": "http://127.0.0.1:9999/cb",
            "scope": "read",
            "state": "s-xyz",
        },
    )
    assert resp.status_code == 302, resp.text
    location = urlparse(resp.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == "http://127.0.0.1:9999/cb"
    q = parse_qs(location.query)
    assert q["state"] == ["s-xyz"]
    assert "code" in q


async def test_loopback_ipv6_redirect_matches_any_port(app_with_session):
    # RFC 8252 §7.3: the same wildcard applies to the [::1] loopback literal.
    await _seed_loopback_client(app_with_session, "client-loopback-v6", ["http://[::1]/cb"])
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client-loopback-v6",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "redirect_uri": "http://[::1]:9999/cb",
            "scope": "read",
            "state": "s-xyz",
        },
    )
    assert resp.status_code == 302, resp.text
    location = urlparse(resp.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == "http://[::1]:9999/cb"
    q = parse_qs(location.query)
    assert q["state"] == ["s-xyz"]
    assert "code" in q


async def test_loopback_localhost_hostname_does_not_wildcard_port(app_with_session):
    # RFC 8252 §7.3 scopes the any-port exception to loopback IP *literals*;
    # the `localhost` hostname (§8.3) does NOT receive it, so a registered
    # http://localhost/cb must be an exact match -> :7777 is rejected 400.
    await _seed_loopback_client(app_with_session, "client-localhost", ["http://localhost/cb"])
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client-localhost",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "redirect_uri": "http://localhost:7777/cb",
            "scope": "read",
            "state": "s-xyz",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


async def test_loopback_port_wildcard_does_not_relax_path(app_with_session):
    # RFC 8252 §7.3: the any-port exception is exactly a port wildcard — the
    # request path must still be an exact match, else reject 400 and never
    # redirect to the untrusted URI.
    await _seed_loopback_client(app_with_session, "client-loopback-v4", ["http://127.0.0.1/cb"])
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client-loopback-v4",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "redirect_uri": "http://127.0.0.1:9999/other",
            "state": "s-v4-path",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


async def test_loopback_wildcard_does_not_relax_a_registered_port_or_host(app_with_session):
    # The wildcard never applies to a non-loopback host, nor does it relax a
    # specific registered port. A host mismatch (127.0.0.1 vs example.com)
    # must still reject.
    await _seed_loopback_client(app_with_session, "client-loopback-v4", ["http://127.0.0.1/cb"])
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "client-loopback-v4",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "redirect_uri": "http://evil.example:9999/cb",
            "state": "s-v4-host",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
