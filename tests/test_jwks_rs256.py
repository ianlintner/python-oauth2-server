"""RS256 signing, key rotation, and JWKS publication — integration tests.

Ported per the Task 13 brief / `.superpowers/sdd/research-keys-rs256.md`
`tests_to_port` "GAP" entry (Rust has no end-to-end coverage for these
endpoints; the Python port adds it). A single 2048-bit RSA key pair is
generated once (module-scoped fixture, RSA keygen costs ~100ms) and reused
by every test below.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from oauth2_server.models import Claims
from oauth2_server.security import decode_access_token
from tests.conftest import build_client_app
from tests.helpers import login_admin, seed_admin
from tests.test_introspection import post_introspect
from tests.test_token_endpoint import run_code_flow

ISSUER = "https://auth.example.com"

_WARNING = (
    "Key rotation is in-memory only. Rotated keys will be lost on restart. "
    "DB persistence is not yet implemented."
)


@pytest.fixture(scope="module")
def rsa_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode()


def _rs256_app(rsa_pem: str, **overrides):
    """`build_client_app` wired with the shared test RSA key, kid
    `"test-rs256-key"` (so `id_token_alg` defaults to RS256)."""
    return build_client_app(
        {"id_token_private_key_pem": rsa_pem, "id_token_kid": "test-rs256-key", **overrides}
    )


def _b64url_uint(raw: str) -> int:
    padded = raw + "=" * (-len(raw) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def _public_key_from_jwk(jwk: dict):
    numbers = rsa.RSAPublicNumbers(_b64url_uint(jwk["e"]), _b64url_uint(jwk["n"]))
    return numbers.public_key()


# ---------------------------------------------------------------------------
# JWKS publication
# ---------------------------------------------------------------------------


async def test_jwks_publishes_rs256_key_shape(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        resp = await client.get("/.well-known/jwks.json")
        assert resp.status_code == 200, resp.text
        assert resp.headers["cache-control"] == "public, max-age=3600"

        body = resp.json()
        assert len(body["keys"]) == 1
        jwk = body["keys"][0]
        assert jwk["kid"] == "test-rs256-key"
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert set(jwk) == {"kid", "kty", "use", "alg", "n", "e"}

        private_key = serialization.load_pem_private_key(rsa_pem.encode(), password=None)
        public_numbers = private_key.public_key().public_numbers()
        assert _b64url_uint(jwk["n"]) == public_numbers.n
        assert _b64url_uint(jwk["e"]) == public_numbers.e


async def test_jwks_empty_for_hs256_only(client_app):
    resp = await client_app.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert resp.json() == {"keys": []}


# ---------------------------------------------------------------------------
# Access + id token signing
# ---------------------------------------------------------------------------


async def test_access_token_signed_rs256_with_kid_matching_jwks(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        resp, _code = await run_code_flow(client, scope="openid email")
        assert resp.status_code == 200, resp.text
        access_token = resp.json()["access_token"]

        header = jwt.get_unverified_header(access_token)
        assert header["alg"] == "RS256"
        assert header["kid"] == "test-rs256-key"

        jwks_resp = await client.get("/.well-known/jwks.json")
        kids = [k["kid"] for k in jwks_resp.json()["keys"]]
        assert header["kid"] in kids


async def test_id_token_rs256_verifiable_via_jwks(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        resp, _code = await run_code_flow(client, scope="openid email")
        assert resp.status_code == 200, resp.text
        id_token = resp.json()["id_token"]

        header = jwt.get_unverified_header(id_token)
        assert header["alg"] == "RS256"
        assert header["kid"] == "test-rs256-key"

        jwks_resp = await client.get("/.well-known/jwks.json")
        jwk = jwks_resp.json()["keys"][0]
        public_key = _public_key_from_jwk(jwk)

        claims = jwt.decode(id_token, public_key, algorithms=["RS256"], audience="client1")
        assert claims["iss"] == ISSUER
        assert claims["sub"] == "u1"


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


async def test_rotate_keeps_old_key_in_jwks_during_grace(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        resp, _code = await run_code_flow(client, scope="openid email")
        assert resp.status_code == 200, resp.text
        old_access_token = resp.json()["access_token"]
        old_kid = jwt.get_unverified_header(old_access_token)["kid"]

        await seed_admin(client.storage)
        await login_admin(client)
        rotate_resp = await client.post("/admin/api/keys/rotate", json={"algorithm": "RS256"})
        assert rotate_resp.status_code == 200, rotate_resp.text
        new_kid = rotate_resp.json()["kid"]
        assert new_kid != old_kid

        jwks_resp = await client.get("/.well-known/jwks.json")
        kids = {k["kid"] for k in jwks_resp.json()["keys"]}
        assert {old_kid, new_kid} <= kids

        config = client.app.state.config
        keyset = client.app.state.keyset
        claims = decode_access_token(
            old_access_token, config.jwt_secret, config.issuer, keyset=keyset
        )
        assert claims.sub == "u1"


async def test_rotate_response_shape_and_warning(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        await seed_admin(client.storage)
        await login_admin(client)

        resp = await client.post("/admin/api/keys/rotate", json={})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["algorithm"] == "RS256"
        assert isinstance(body["kid"], str) and body["kid"].startswith("rs256-")
        assert isinstance(body["created_at"], str)
        assert body["grace_period_hours"] == 24
        assert body["warning"] == _WARNING


async def test_rotate_rejects_unknown_algorithm(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        await seed_admin(client.storage)
        await login_admin(client)

        resp = await client.post("/admin/api/keys/rotate", json={"algorithm": "bogus"})
        assert resp.status_code == 400, resp.text
        assert resp.json() == {
            "error": "invalid_request",
            "error_description": "Unknown algorithm: bogus",
        }


async def test_rotate_rejects_oversized_grace_period(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        await seed_admin(client.storage)
        await login_admin(client)

        resp = await client.post("/admin/api/keys/rotate", json={"grace_period_hours": 10**18})
        assert resp.status_code == 400, resp.text
        assert resp.json() == {
            "error": "invalid_request",
            "error_description": "grace_period_hours is too large",
        }


async def test_rotate_rejects_negative_grace_period(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        await seed_admin(client.storage)
        await login_admin(client)

        resp = await client.post("/admin/api/keys/rotate", json={"grace_period_hours": -1})
        assert resp.status_code == 400, resp.text
        assert resp.json() == {
            "error": "invalid_request",
            "error_description": "grace_period_hours must be non-negative",
        }


async def test_admin_keys_list_hides_material(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        await seed_admin(client.storage)
        await login_admin(client)

        resp = await client.get("/admin/api/keys")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        kids = {k["kid"] for k in body["keys"]}
        assert kids == {"hs256-initial", "test-rs256-key"}
        for key in body["keys"]:
            assert set(key) == {"kid", "algorithm", "is_current", "created_at", "expires_at"}


async def test_pre_rotation_token_still_introspects_active(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        resp, _code = await run_code_flow(client, scope="openid email")
        assert resp.status_code == 200, resp.text
        access_token = resp.json()["access_token"]

        await seed_admin(client.storage)
        await login_admin(client)
        rotate_resp = await client.post("/admin/api/keys/rotate", json={"algorithm": "RS256"})
        assert rotate_resp.status_code == 200, rotate_resp.text

        introspect_resp = await post_introspect(client, access_token)
        assert introspect_resp.status_code == 200, introspect_resp.text
        assert introspect_resp.json()["active"] is True


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def test_discovery_advertises_rs256_when_configured(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        resp = await client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        assert resp.json()["id_token_signing_alg_values_supported"] == ["RS256"]


async def test_discovery_advertises_hs256_by_default(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    assert resp.json()["id_token_signing_alg_values_supported"] == ["HS256"]


# ---------------------------------------------------------------------------
# Logout id_token_hint — RS256 verification (routes/logout.py TODO(task-13))
# ---------------------------------------------------------------------------


async def test_logout_accepts_rs256_id_token_hint(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        resp, _code = await run_code_flow(client, scope="openid email")
        assert resp.status_code == 200, resp.text
        id_token_hint = resp.json()["id_token"]

        logout_resp = await client.get("/oauth/logout", params={"id_token_hint": id_token_hint})
        assert logout_resp.status_code == 200, logout_resp.text


async def test_logout_rejects_rs256_hint_when_pem_not_configured(client_app):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    hint = jwt.encode(
        {"iss": ISSUER, "sub": "u1", "aud": "client1", "exp": 9999999999, "iat": 0},
        pem,
        algorithm="RS256",
    )
    resp = await client_app.get("/oauth/logout", params={"id_token_hint": hint})
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# Rotation-safe id_token signing + keyset-aware hint/access verification
# (Task 3a-4 / research-keys-rs256.md gotchas: Rust always signs id_tokens
# from the static env PEM, so an RP verifying via JWKS breaks once that key
# is rotated out and pruned. The Python port signs id_tokens with the
# keyset's *current* RS256 key instead, and widens logout hint / access
# token verification to consult the keyset rather than a single static
# secret/PEM.)
# ---------------------------------------------------------------------------


async def test_id_token_pre_rotation_unchanged(rsa_pem):
    """No rotation: id_token kid/signature come from the seeded keyset key,
    which *is* the env PEM (`seed_keyset`) — output must be identical to
    signing straight from `config.id_token_private_key_pem`."""
    async with _rs256_app(rsa_pem) as client:
        resp, _code = await run_code_flow(client, scope="openid email")
        assert resp.status_code == 200, resp.text
        id_token = resp.json()["id_token"]

        header = jwt.get_unverified_header(id_token)
        assert header["alg"] == "RS256"
        assert header["kid"] == "test-rs256-key"

        jwks_resp = await client.get("/.well-known/jwks.json")
        jwk = jwks_resp.json()["keys"][0]
        assert jwk["kid"] == "test-rs256-key"
        public_key = _public_key_from_jwk(jwk)

        claims = jwt.decode(id_token, public_key, algorithms=["RS256"], audience="client1")
        assert claims["iss"] == ISSUER
        assert claims["sub"] == "u1"


async def test_id_token_signed_with_current_keyset_key_after_rotation(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        await seed_admin(client.storage)
        await login_admin(client)
        rotate_resp = await client.post("/admin/api/keys/rotate", json={"algorithm": "RS256"})
        assert rotate_resp.status_code == 200, rotate_resp.text
        new_kid = rotate_resp.json()["kid"]
        assert new_kid != "test-rs256-key"

        resp, _code = await run_code_flow(client, scope="openid email")
        assert resp.status_code == 200, resp.text
        id_token = resp.json()["id_token"]

        header = jwt.get_unverified_header(id_token)
        assert header["alg"] == "RS256"
        assert header["kid"] == new_kid

        jwks_resp = await client.get("/.well-known/jwks.json")
        jwk = next(k for k in jwks_resp.json()["keys"] if k["kid"] == new_kid)
        public_key = _public_key_from_jwk(jwk)

        claims = jwt.decode(id_token, public_key, algorithms=["RS256"], audience="client1")
        assert claims["iss"] == ISSUER
        assert claims["sub"] == "u1"


async def test_logout_accepts_hint_signed_by_rotated_out_key_during_grace(rsa_pem):
    async with _rs256_app(rsa_pem) as client:
        resp, _code = await run_code_flow(client, scope="openid email")
        assert resp.status_code == 200, resp.text
        id_token_hint = resp.json()["id_token"]
        old_kid = jwt.get_unverified_header(id_token_hint)["kid"]
        assert old_kid == "test-rs256-key"

        await seed_admin(client.storage)
        await login_admin(client)
        rotate_resp = await client.post("/admin/api/keys/rotate", json={"algorithm": "RS256"})
        assert rotate_resp.status_code == 200, rotate_resp.text
        assert rotate_resp.json()["kid"] != old_kid

        # The old key is now non-current but still within its grace period,
        # so a hint it signed pre-rotation must still verify -- not a 400.
        logout_resp = await client.get("/oauth/logout", params={"id_token_hint": id_token_hint})
        assert logout_resp.status_code == 200, logout_resp.text


async def test_logout_rejects_hint_signed_by_pruned_key_after_grace(rsa_pem):
    """Once the old key's grace period has elapsed and it's been physically
    pruned from the keyset, a hint it signed must be rejected outright --
    not resurrected via the static `config.id_token_private_key_pem`
    fallback (which happens to equal the original signing key here, since
    `_rs256_app` seeds the keyset from that same PEM). See the invariant
    comment on `_rs256_hint_verify_materials` in routes/logout.py: that
    fallback is only for a keyset with *zero* active RS256 keys, which
    never happens here because rotation always leaves a current key."""
    async with _rs256_app(rsa_pem) as client:
        resp, _code = await run_code_flow(client, scope="openid email")
        assert resp.status_code == 200, resp.text
        id_token_hint = resp.json()["id_token"]
        old_kid = jwt.get_unverified_header(id_token_hint)["kid"]
        assert old_kid == "test-rs256-key"

        await seed_admin(client.storage)
        await login_admin(client)

        rotate_resp = await client.post(
            "/admin/api/keys/rotate",
            json={"algorithm": "RS256", "grace_period_hours": 0},
        )
        assert rotate_resp.status_code == 200, rotate_resp.text
        assert rotate_resp.json()["kid"] != old_kid

        # `grace_period_hours=0` sets `expires_at = now` at rotation time, so
        # the old key is *usually* already pruned by the `prune_expired()`
        # call inside the rotate handler above -- but `is_active()` compares
        # with a strict `<`, so that's a timing race, not a guarantee. Force
        # the old key's expiry into the definite past directly on the
        # keyset so the second rotate's prune below is deterministic
        # regardless of how fast this test happens to run.
        keyset = client.app.state.keyset
        for key in keyset._keys:
            if key.kid == old_kid:
                key.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        # Rotate again -- `prune_expired()` runs inside `rotate_key` and
        # physically removes the now-expired old key from the keyset.
        rotate_resp2 = await client.post("/admin/api/keys/rotate", json={"algorithm": "RS256"})
        assert rotate_resp2.status_code == 200, rotate_resp2.text
        assert keyset.find(old_kid) is None

        logout_resp = await client.get("/oauth/logout", params={"id_token_hint": id_token_hint})
        assert logout_resp.status_code == 400, logout_resp.text
        assert logout_resp.json() == {
            "error": "invalid_request",
            "error_description": "invalid id_token_hint",
        }


async def test_hs256_rotation_decodes_with_active_keys(client_app):
    await seed_admin(client_app.storage)
    await login_admin(client_app)

    rotate_resp = await client_app.post("/admin/api/keys/rotate", json={"algorithm": "HS256"})
    assert rotate_resp.status_code == 200, rotate_resp.text

    keyset = client_app.app.state.keyset
    config = client_app.app.state.config
    rotated_key = keyset.current_for_alg("HS256")
    assert rotated_key.kid == rotate_resp.json()["kid"]

    claims = Claims.new("u1", "client1", "read", 3600, config.issuer)
    # A kid-less token signed with the newly-rotated HS256 key (as if the
    # `kid` header didn't survive transport, or an older caller minted it
    # via the legacy no-keyset path with the rotated key's material).
    # decode_access_token must try every active keyset key before giving up
    # on the static `jwt_secret` -- otherwise rotating the HS256 key is a
    # no-op for any token that doesn't carry a resolvable kid.
    token = jwt.encode(
        claims.to_payload(),
        rotated_key.key_material,
        algorithm="HS256",
        headers={"typ": "at+JWT"},
    )

    decoded = decode_access_token(
        token, "definitely-not-" + config.jwt_secret, config.issuer, keyset=keyset
    )
    assert decoded.sub == "u1"
