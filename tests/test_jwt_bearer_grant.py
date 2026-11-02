"""RFC 7523 §2.1 JWT bearer authorization grant
(`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`).

Every validation failure must surface as 400 `invalid_grant` (RFC 7523 §3.1).
The trusted issuer's JWKS is served through a mocked transport so no network
is touched.
"""

from __future__ import annotations

import json
import time
import uuid

import httpx
import jwt
import pytest

from oauth2_server.models import TrustedIssuer
from oauth2_server.services.jwks_cache import JwksCache
from tests.conftest import build_client_app
from tests.helpers import generate_rsa_keypair, post_token, seed_client

BEARER_URN = "urn:ietf:params:oauth:grant-type:jwt-bearer"
EXT_ISS = "https://idp.example.org"
JWKS_URI = "https://idp.example.org/jwks.json"
AUD = "https://auth.example.com"


async def _setup(client_app, *, jwks: dict, **issuer_overrides):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks)

    client_app.app.state.jwks_cache = JwksCache(
        httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    await seed_client(
        client_app.storage,
        client_id="jb_client",
        client_secret="jb_secret",
        grant_types=json.dumps([BEARER_URN]),
        scope="read profile",
    )
    fields = {"id": uuid.uuid4().hex, "issuer": EXT_ISS, "jwks_uri": JWKS_URI}
    fields.update(issuer_overrides)
    await client_app.storage.save_trusted_issuer(TrustedIssuer(**fields))


def _assertion(key, *, kid="client-key-1", **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": EXT_ISS,
        "sub": "u1",
        "aud": AUD,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 60,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


async def _redeem(client_app, assertion: str, **extra):
    return await post_token(
        client_app,
        {"grant_type": BEARER_URN, "assertion": assertion, **extra},
        basic_auth=("jb_client", "jb_secret"),
    )


def _assert_invalid_grant(resp):
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_grant"


async def test_valid_assertion_issues_access_token(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    resp = await _redeem(client_app, _assertion(key))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["access_token"]
    assert body["scope"] == "read profile"
    assert "refresh_token" not in body
    row = await client_app.storage.get_token_by_access_token(body["access_token"])
    assert row is not None and row.user_id == "u1"


async def test_requested_scope_subset_honoured_and_excess_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    ok = await _redeem(client_app, _assertion(key), scope="read")
    assert ok.status_code == 200
    assert ok.json()["scope"] == "read"
    bad = await _redeem(client_app, _assertion(key), scope="read admin")
    assert bad.status_code == 400
    assert bad.json()["error"] == "invalid_scope"


async def test_bad_signature_rejected(client_app):
    _, jwks = generate_rsa_keypair()
    other_key, _ = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(other_key)))


async def test_unknown_issuer_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, iss="https://evil.example")))


async def test_disabled_issuer_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, enabled=False)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key)))


async def test_wrong_audience_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, aud="https://other.example")))


async def test_registry_allowed_audience_accepted(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, allowed_audiences=json.dumps(["https://api.example"]))
    resp = await _redeem(client_app, _assertion(key, aud="https://api.example"))
    assert resp.status_code == 200, resp.text


async def test_expired_assertion_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    now = int(time.time())
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, iat=now - 600, exp=now - 300)))


async def test_future_iat_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    now = int(time.time())
    _assert_invalid_grant(
        await _redeem(client_app, _assertion(key, iat=now + 3600, exp=now + 3660))
    )


async def test_missing_jti_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, jti=None)))


async def test_replayed_jti_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    assertion = _assertion(key, jti="fixed-jti")
    assert (await _redeem(client_app, assertion)).status_code == 200
    _assert_invalid_grant(await _redeem(client_app, assertion))


async def test_unknown_subject_without_jit_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, sub="nobody")))


async def test_jit_provision_creates_user(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, jit_provision=True)
    resp = await _redeem(client_app, _assertion(key, sub="fresh-user"))
    assert resp.status_code == 200, resp.text
    assert await client_app.storage.get_user_by_id("fresh-user") is not None


async def test_email_mapping_resolves_existing_user(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, subject_mapping="email")
    resp = await _redeem(
        client_app,
        _assertion(key, sub="ext-123", email="user_rfc@example.test", email_verified=True),
    )
    assert resp.status_code == 200, resp.text
    row = await client_app.storage.get_token_by_access_token(resp.json()["access_token"])
    assert row is not None and row.user_id == "u1"


async def test_client_not_in_issuer_allow_list_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, allowed_client_ids=json.dumps(["someone_else"]))
    _assert_invalid_grant(await _redeem(client_app, _assertion(key)))


async def test_missing_assertion_is_invalid_request(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    resp = await post_token(
        client_app, {"grant_type": BEARER_URN}, basic_auth=("jb_client", "jb_secret")
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


async def test_malformed_assertion_rejected(client_app):
    _, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, "not-a-jwt"))


async def test_client_without_grant_is_unauthorized_client(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    await seed_client(
        client_app.storage,
        client_id="plain",
        client_secret="plain_secret",
        grant_types=json.dumps(["client_credentials"]),
    )
    resp = await post_token(
        client_app,
        {"grant_type": BEARER_URN, "assertion": _assertion(key)},
        basic_auth=("plain", "plain_secret"),
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "unauthorized_client"


@pytest.mark.parametrize("path", ["/.well-known/openid-configuration"])
async def test_discovery_advertises_jwt_bearer(client_app, path):
    resp = await client_app.get(path)
    assert BEARER_URN in resp.json()["grant_types_supported"]


async def test_build_client_app_still_importable():
    # guards the shared fixture import used above
    async with build_client_app() as c:
        assert c.app is not None


@pytest.mark.parametrize("raw", ["[123]", "not json", '{"a": 1}', '["ok", 5]'])
async def test_malformed_client_allow_list_denies(client_app, raw):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, allowed_client_ids=raw)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key)))


async def test_assertion_outliving_replay_window_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    now = int(time.time())
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, exp=now + 3600)))


async def test_small_future_iat_within_skew_accepted(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    now = int(time.time())
    resp = await _redeem(client_app, _assertion(key, iat=now + 5))
    assert resp.status_code == 200, resp.text


async def test_nonfinite_iat_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, iat=float("nan"))))


async def test_blank_email_claim_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, subject_mapping="email")
    _assert_invalid_grant(
        await _redeem(client_app, _assertion(key, email="   ", email_verified=True))
    )


async def test_ambiguous_email_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, subject_mapping="email")
    first = await client_app.storage.get_user_by_id("u1")
    dup = first.model_copy(update={"id": "u1-dup", "username": "u1-dup"})
    await client_app.storage.save_user(dup)
    _assert_invalid_grant(
        await _redeem(
            client_app, _assertion(key, email="user_rfc@example.test", email_verified=True)
        )
    )


@pytest.mark.parametrize("verified", [None, False, "true", 1])
async def test_email_mapping_requires_email_verified_true(client_app, verified):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, subject_mapping="email")
    claims = {"email": "user_rfc@example.test", "email_verified": verified}
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, **claims)))


@pytest.mark.parametrize(
    ("claim", "value"),
    [("exp", 10**30), ("exp", -(10**30)), ("iat", 10**30), ("exp", 10**400), ("iat", 10**400)],
)
async def test_extreme_timestamps_are_invalid_grant(client_app, claim, value):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key, **{claim: value})))


async def test_email_mapping_never_provisions_unknown_user(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, subject_mapping="email", jit_provision=True)
    resp = await _redeem(
        client_app, _assertion(key, sub="new-sub", email="nobody@example.test", email_verified=True)
    )
    _assert_invalid_grant(resp)
    assert await client_app.storage.get_user_by_id("new-sub") is None


async def test_jit_user_gets_valid_unguessable_password_hash(client_app):
    from oauth2_server.security import verify_password

    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, jit_provision=True)
    resp = await _redeem(client_app, _assertion(key, sub="jit-pw"))
    assert resp.status_code == 200, resp.text
    user = await client_app.storage.get_user_by_id("jit-pw")
    assert user.password_hash.startswith("$argon2")
    assert verify_password("", user.password_hash) is False


@pytest.mark.parametrize("verified", [None, False, "true", 1])
async def test_jit_does_not_persist_unverified_email(client_app, verified):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, jit_provision=True)
    extra = {} if verified is None else {"email_verified": verified}
    resp = await _redeem(
        client_app, _assertion(key, sub="jit-unv", email="victim@example.test", **extra)
    )
    assert resp.status_code == 200, resp.text
    user = await client_app.storage.get_user_by_id("jit-unv")
    assert not user.email


async def test_jit_persists_verified_email(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks, jit_provision=True)
    resp = await _redeem(
        client_app,
        _assertion(key, sub="jit-ver", email="ok@example.test", email_verified=True),
    )
    assert resp.status_code == 200, resp.text
    assert (await client_app.storage.get_user_by_id("jit-ver")).email == "ok@example.test"


def _alt_key(alg: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if alg == "ES256":
        priv = ec.generate_private_key(ec.SECP256R1())
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(priv.public_key(), as_dict=True)
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key(), as_dict=True)
    jwk.update({"kid": "client-key-1", "use": "sig"})
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem, {"keys": [jwk]}


def _signed(pem, alg):
    now = int(time.time())
    claims = {
        "iss": EXT_ISS, "sub": "u1", "aud": AUD, "jti": uuid.uuid4().hex,
        "iat": now, "exp": now + 60,
    }  # fmt: skip
    return jwt.encode(claims, pem, algorithm=alg, headers={"kid": "client-key-1"})


@pytest.mark.parametrize("alg", ["PS256", "ES256"])
async def test_ps256_es256_assertions_redeem(client_app, alg):
    pem, jwks = _alt_key(alg)
    await _setup(client_app, jwks=jwks)
    resp = await _redeem(client_app, _signed(pem, alg))
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize("alg,jwks_alg", [("ES256", "RS256"), ("RS256", "ES256")])
async def test_key_type_mismatch_rejected(client_app, alg, jwks_alg):
    pem, _ = _alt_key(alg)
    _, jwks = _alt_key(jwks_alg)
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _signed(pem, alg)))


async def test_replay_guard_at_capacity_fails_closed_not_open(client_app):
    from oauth2_server.services.client_assertion import JtiReplayGuard

    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    client_app.app.state.jti_guard = JtiReplayGuard(max_entries=1)
    first = _assertion(key)
    assert (await _redeem(client_app, first)).status_code == 200
    # a second, different assertion cannot evict the live first entry
    _assert_invalid_grant(await _redeem(client_app, _assertion(key)))
    # and the first remains a replay
    _assert_invalid_grant(await _redeem(client_app, first))


@pytest.mark.parametrize(
    "typ",
    [
        "oauth-id-jag+jwt",
        "OAUTH-ID-JAG+JWT",
        "Oauth-Id-Jag+Jwt",
        "application/oauth-id-jag+jwt",
        "Application/OAuth-ID-JAG+JWT",
    ],
)
async def test_id_jag_typ_rejected_case_insensitively(client_app, typ):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    now = int(time.time())
    claims = {
        "iss": EXT_ISS,
        "sub": "u1",
        "aud": AUD,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 60,
    }
    tok = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "client-key-1", "typ": typ})
    _assert_invalid_grant(await _redeem(client_app, tok))


async def test_plain_jwt_typ_still_accepted(client_app):
    key, jwks = generate_rsa_keypair()
    await _setup(client_app, jwks=jwks)
    now = int(time.time())
    claims = {
        "iss": EXT_ISS,
        "sub": "u1",
        "aud": AUD,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 60,
    }
    tok = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "client-key-1", "typ": "JWT"})
    assert (await _redeem(client_app, tok)).status_code == 200


async def test_kidless_selection_skips_enc_key(client_app):
    key, jwks = generate_rsa_keypair()
    sig = jwks["keys"][0]
    enc = dict(sig, kid="enc-1", use="enc")
    await _setup(client_app, jwks={"keys": [enc, sig]})
    now = int(time.time())
    claims = {
        "iss": EXT_ISS,
        "sub": "u1",
        "aud": AUD,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 60,
    }
    tok = jwt.encode(claims, key, algorithm="RS256")  # no kid
    assert (await _redeem(client_app, tok)).status_code == 200


@pytest.mark.parametrize("extra", [{"use": "enc"}, {"key_ops": ["encrypt"]}])
async def test_non_signature_key_rejected_even_by_kid(client_app, extra):
    key, jwks = generate_rsa_keypair()
    jwks["keys"][0].pop("use")
    jwks["keys"][0].update(extra)
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key)))


async def test_explicit_jwk_alg_mismatch_rejected_by_kid(client_app):
    key, jwks = generate_rsa_keypair()
    jwks["keys"][0]["alg"] = "PS256"  # key restricted to PS256; assertion is RS256
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key)))


async def test_explicit_jwk_alg_other_family_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    jwks["keys"][0]["alg"] = "ES256"
    await _setup(client_app, jwks=jwks)
    _assert_invalid_grant(await _redeem(client_app, _assertion(key)))


async def test_kidless_selection_skips_alg_incompatible_key(client_app):
    key, jwks = generate_rsa_keypair()
    good = jwks["keys"][0]
    _, other = generate_rsa_keypair(kid="other")
    wrong = dict(other["keys"][0], alg="PS256")  # different material, PS256-only
    await _setup(client_app, jwks={"keys": [wrong, good]})
    now = int(time.time())
    claims = {
        "iss": EXT_ISS,
        "sub": "u1",
        "aud": AUD,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 60,
    }
    tok = jwt.encode(claims, key, algorithm="RS256")  # no kid
    assert (await _redeem(client_app, tok)).status_code == 200


async def test_kidless_all_keys_alg_incompatible_rejected(client_app):
    key, jwks = generate_rsa_keypair()
    jwks["keys"][0]["alg"] = "PS256"
    await _setup(client_app, jwks=jwks)
    now = int(time.time())
    claims = {
        "iss": EXT_ISS,
        "sub": "u1",
        "aud": AUD,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + 60,
    }
    _assert_invalid_grant(await _redeem(client_app, jwt.encode(claims, key, algorithm="RS256")))


@pytest.mark.parametrize("alg", ["RS256", "PS256", "ES256"])
async def test_matching_explicit_jwk_alg_accepted(client_app, alg):
    pem, jwks = _alt_key("ES256" if alg == "ES256" else "RS256")
    jwks["keys"][0]["alg"] = alg
    await _setup(client_app, jwks=jwks)
    resp = await _redeem(client_app, _signed(pem, alg))
    assert resp.status_code == 200, resp.text
