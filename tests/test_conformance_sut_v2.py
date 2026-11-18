"""SUT interface v2 (`contract/sut-interface.md` section 7): capability
advertisement, `test-clock` and `dpop-nonce-mode`.

Everything here is conformance-mode only: with the mode off none of the
`/conformance/*` paths exist and the clock cannot move.
"""

from __future__ import annotations

import base64
import time
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import ASGITransport, AsyncClient

from oauth2_server import clock
from oauth2_server.app import build
from tests.helpers import (
    PKCE_CHALLENGE,
    PKCE_VERIFIER,
    generate_dpop_key,
    make_dpop_proof,
)

SECRET = "unit-test-secret-not-for-production-0123456789abcdef"
ISSUER = "http://localhost:8080"
TOKEN_URL = f"{ISSUER}/oauth/token"
USERINFO_URL = f"{ISSUER}/oauth/userinfo"
REDIRECT = "https://client.example/callback"

SEED = """
issuer: http://localhost:8080
clients:
  - client_id: client-a
    client_secret: test-only-secret
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: [https://client.example/callback]
    grant_types: [authorization_code, refresh_token, client_credentials]
    scopes: [openid, read]
users:
  - username: alice
    password: test-only-password
    auto_approve_clients: [client-a]
"""

BASIC = "Basic " + base64.b64encode(b"client-a:test-only-secret").decode()


@pytest.fixture(autouse=True)
def _isolated_clock():
    clock.reset()
    yield
    clock.reset()


@pytest.fixture
def conformance_env(monkeypatch, tmp_path):
    seed = tmp_path / "seed.yaml"
    seed.write_text(SEED, encoding="utf-8")
    monkeypatch.setenv("OAUTH2_JWT_SECRET", SECRET)
    monkeypatch.setenv("OAUTH2_CONFORMANCE_MODE", "1")
    monkeypatch.setenv("OAUTH2_CONFORMANCE_SEED", str(seed))
    monkeypatch.setenv("OAUTH2_ENV", "test")
    monkeypatch.delenv("OAUTH2_DATABASE_URL", raising=False)
    return monkeypatch


def _http(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url=ISSUER)


async def _code(client) -> str:
    params = {
        "response_type": "code",
        "client_id": "client-a",
        "redirect_uri": REDIRECT,
        "code_challenge": PKCE_CHALLENGE,
        "code_challenge_method": "S256",
        "scope": "openid read",
        "state": "s",
    }
    first = await client.get("/oauth/authorize", params=params)
    cookie = first.headers["set-cookie"].split(";", 1)[0]
    login = await client.post(
        "/auth/login",
        data={"username": "alice", "password": "test-only-password"},
        headers={"cookie": cookie},
    )
    cookie = login.headers["set-cookie"].split(";", 1)[0]
    final = await client.get("/oauth/authorize", params=params, headers={"cookie": cookie})
    return parse_qs(urlparse(final.headers["location"]).query)["code"][0]


def _exchange_form(code: str) -> dict:
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": PKCE_VERIFIER,
    }


# -- gating: nothing exists outside conformance mode ---------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/conformance/capabilities"),
        ("POST", "/conformance/clock"),
        ("POST", "/conformance/dpop-nonce"),
    ],
)
async def test_v2_paths_do_not_exist_with_the_mode_off(monkeypatch, method, path):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", SECRET)
    for var in ("OAUTH2_CONFORMANCE_MODE", "OAUTH2_CONFORMANCE_SEED"):
        monkeypatch.delenv(var, raising=False)
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        body = {"advance_seconds": 5} if "clock" in path else {"required": True}
        resp = await client.request(method, path, json=body if method == "POST" else None)
        assert resp.status_code == 404
    # ...and the clock never moved.
    assert clock.offset() == 0


# -- capabilities ----------------------------------------------------------------


async def test_capabilities_advertise_exactly_what_is_implemented(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        resp = await client.get("/conformance/capabilities")
        assert resp.status_code == 200
        # Schema: interface_version const 2, no mtls/instances unless advertised.
        assert resp.json() == {
            "interface_version": 2,
            "capabilities": ["test-clock", "dpop-nonce-mode"],
        }


# -- test-clock ------------------------------------------------------------------


async def test_clock_advances_cumulatively_and_reports_now(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        before = int(time.time())
        first = await client.post("/conformance/clock", json={"advance_seconds": 100})
        assert first.status_code == 200
        assert before + 100 <= first.json()["now"] <= before + 103
        second = await client.post("/conformance/clock", json={"advance_seconds": 50})
        assert before + 150 <= second.json()["now"] <= before + 153
        zero = await client.post("/conformance/clock", json={"advance_seconds": 0})
        assert zero.status_code == 200
        assert clock.offset() == 150


@pytest.mark.parametrize(
    "body",
    [
        {"advance_seconds": -1},
        {"advance_seconds": 1.5},
        {"advance_seconds": 31_536_001},
        {"advance_seconds": "10"},
        {"advance_seconds": True},
        {"advance_seconds": None},
        {},
        [],
        "10",
    ],
)
async def test_clock_rejects_anything_but_a_bounded_integer(conformance_env, body):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        resp = await client.post("/conformance/clock", json=body)
        assert resp.status_code == 400
        assert clock.offset() == 0


async def test_clock_error_description_is_fixed_not_a_reflected_exception(conformance_env):
    """The range-overflow rejection must return a fixed, safe message, not
    the text of whatever exception ``clock.advance`` happens to raise."""
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        resp = await client.post("/conformance/clock", json={"advance_seconds": 31_536_001})
        assert resp.status_code == 400
        body = resp.json()
        assert body["error"] == "invalid_request"
        assert body["error_description"] == "advance_seconds must be between 0 and 31536000"
        # No exception/stack-trace material must leak into the response.
        for value in body.values():
            assert "Traceback" not in str(value)
            assert "ValueError" not in str(value)


async def test_clock_rejects_non_json_body(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        resp = await client.post("/conformance/clock", content=b"advance_seconds=5")
        assert resp.status_code == 400
        assert clock.offset() == 0


async def test_clock_is_reset_when_the_process_restarts(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        await client.post("/conformance/clock", json={"advance_seconds": 500})
    assert clock.offset() == 500
    app2 = build()
    async with app2.router.lifespan_context(app2):
        assert clock.offset() == 0


async def test_advancing_expires_an_authorization_code(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        code = await _code(client)
        await client.post("/conformance/clock", json={"advance_seconds": 601})
        resp = await client.post(
            "/oauth/token", data=_exchange_form(code), headers={"authorization": BASIC}
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"


async def test_a_fresh_code_still_works_without_advancing(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        code = await _code(client)
        resp = await client.post(
            "/oauth/token", data=_exchange_form(code), headers={"authorization": BASIC}
        )
        assert resp.status_code == 200


async def test_issued_timestamps_reflect_the_advanced_clock(conformance_env):
    import jwt

    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        await client.post("/conformance/clock", json={"advance_seconds": 5000})
        real_now = int(time.time())
        resp = await client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "scope": "read"},
            headers={"authorization": BASIC},
        )
        assert resp.status_code == 200
        access = resp.json()["access_token"]
        claims = jwt.decode(access, options={"verify_signature": False})
        assert real_now + 5000 - 2 <= claims["iat"] <= real_now + 5000 + 2
        assert claims["exp"] - claims["iat"] == resp.json()["expires_in"]
        # introspection sees the token as active at the advanced "now"...
        active = await client.post(
            "/oauth/introspect", data={"token": access}, headers={"authorization": BASIC}
        )
        assert active.json()["active"] is True
        # ...and as expired once the clock passes its lifetime.
        await client.post("/conformance/clock", json={"advance_seconds": 3601})
        gone = await client.post(
            "/oauth/introspect", data={"token": access}, headers={"authorization": BASIC}
        )
        assert gone.json()["active"] is False


async def test_dpop_iat_window_follows_the_advanced_clock(conformance_env):
    app = build()
    key = generate_dpop_key()
    async with app.router.lifespan_context(app), _http(app) as client:
        stale_iat = int(time.time())  # minted against real time
        await client.post("/conformance/clock", json={"advance_seconds": 3600})
        proof, _ = make_dpop_proof(TOKEN_URL, "POST", key, iat=stale_iat)
        resp = await client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "scope": "read"},
            headers={"authorization": BASIC, "dpop": proof},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_dpop_proof"
        # a proof minted for the advanced "now" is accepted
        fresh, _ = make_dpop_proof(TOKEN_URL, "POST", key, iat=time.time() + 3600)
        ok = await client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "scope": "read"},
            headers={"authorization": BASIC, "dpop": fresh},
        )
        assert ok.status_code == 200
        assert ok.json()["token_type"] == "DPoP"


# -- dpop-nonce-mode -------------------------------------------------------------


async def _cc(client, proof: str | None):
    headers = {"authorization": BASIC}
    if proof:
        headers["dpop"] = proof
    return await client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "read"},
        headers=headers,
    )


async def test_nonce_mode_is_off_by_default(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        proof, _ = make_dpop_proof(TOKEN_URL, "POST")
        resp = await _cc(client, proof)
        assert resp.status_code == 200
        assert "dpop-nonce" not in resp.headers


@pytest.mark.parametrize("bad", [{}, {"required": "yes"}, {"required": 1}, {"required": None}, []])
async def test_nonce_toggle_rejects_a_non_boolean(conformance_env, bad):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        resp = await client.post("/conformance/dpop-nonce", json=bad)
        assert resp.status_code == 400
        # still off
        proof, _ = make_dpop_proof(TOKEN_URL, "POST")
        assert (await _cc(client, proof)).status_code == 200


async def test_nonce_mode_challenges_then_accepts_the_issued_nonce(conformance_env):
    app = build()
    key = generate_dpop_key()
    async with app.router.lifespan_context(app), _http(app) as client:
        toggled = await client.post("/conformance/dpop-nonce", json={"required": True})
        assert toggled.status_code == 200
        assert toggled.json() == {"required": True}

        proof, _ = make_dpop_proof(TOKEN_URL, "POST", key)
        challenge = await _cc(client, proof)
        assert challenge.status_code == 400
        assert challenge.json()["error"] == "use_dpop_nonce"
        nonce = challenge.headers["dpop-nonce"]
        assert nonce

        retry, _ = make_dpop_proof(TOKEN_URL, "POST", key, nonce=nonce)
        ok = await _cc(client, retry)
        assert ok.status_code == 200
        assert ok.json()["token_type"] == "DPoP"

        # switching it back off restores the default behavior
        off = await client.post("/conformance/dpop-nonce", json={"required": False})
        assert off.json() == {"required": False}
        plain, _ = make_dpop_proof(TOKEN_URL, "POST")
        assert (await _cc(client, plain)).status_code == 200


async def test_nonce_mode_does_not_touch_non_dpop_requests(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        await client.post("/conformance/dpop-nonce", json={"required": True})
        resp = await _cc(client, None)
        assert resp.status_code == 200
        assert resp.json()["token_type"].lower() == "bearer"


async def test_nonce_mode_applies_to_resource_requests(conformance_env):
    app = build()
    key = generate_dpop_key()
    async with app.router.lifespan_context(app), _http(app) as client:
        # obtain a DPoP-bound user token while nonces are not required
        code = await _code(client)
        proof, _ = make_dpop_proof(TOKEN_URL, "POST", key)
        issued = await client.post(
            "/oauth/token",
            data=_exchange_form(code),
            headers={"authorization": BASIC, "dpop": proof},
        )
        assert issued.status_code == 200, issued.text
        token = issued.json()["access_token"]
        ath = (
            base64.urlsafe_b64encode(__import__("hashlib").sha256(token.encode()).digest())
            .rstrip(b"=")
            .decode()
        )

        await client.post("/conformance/dpop-nonce", json={"required": True})

        resource, _ = make_dpop_proof(USERINFO_URL, "GET", key, extra_claims={"ath": ath})
        challenged = await client.get(
            "/oauth/userinfo", headers={"authorization": f"DPoP {token}", "dpop": resource}
        )
        assert challenged.status_code == 401
        assert 'error="use_dpop_nonce"' in challenged.headers["www-authenticate"]
        nonce = challenged.headers["dpop-nonce"]

        again, _ = make_dpop_proof(USERINFO_URL, "GET", key, nonce=nonce, extra_claims={"ath": ath})
        ok = await client.get(
            "/oauth/userinfo", headers={"authorization": f"DPoP {token}", "dpop": again}
        )
        assert ok.status_code == 200, ok.text


async def test_nonce_mode_resets_on_restart(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), _http(app) as client:
        await client.post("/conformance/dpop-nonce", json={"required": True})
    app2 = build()
    async with app2.router.lifespan_context(app2), _http(app2) as client:
        proof, _ = make_dpop_proof(TOKEN_URL, "POST")
        assert (await _cc(client, proof)).status_code == 200
