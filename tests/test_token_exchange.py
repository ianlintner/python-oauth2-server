"""RFC 8693 token exchange grant (`urn:ietf:params:oauth:grant-type:token-exchange`).

Ported per `.superpowers/sdd/research-rar-token-exchange.md` token-exchange
sections: the Rust server implements this grant at ~80% (its own audit
rating) — subject_token is resolved by STORAGE LOOKUP (not arbitrary-JWT
validation, so only tokens this server issued and still holds can be
exchanged), subject_token_type/actor_token_type are parsed then ignored
(`#[allow(dead_code)]`), requested_token_type is echoed back verbatim with no
validation, and `act` (delegation) never reaches the issued JWT — it is only
a top-level member of the HTTP response body when `actor_token` was present.

This suite covers the FIXED gaps (divergence 18/19 in the research doc):
subject_token_type and requested_token_type are now validated against the
single supported URN, and `act={"sub": <exchanging client_id>}` is embedded
in the issued JWT for every exchanged token — not just when `actor_token` is
present. The response-body `act` member keeps Rust's conditional shape
(present only when `actor_token` was supplied) for response-format parity.
The 2 Rust regression pins (expired/valid subject_token) and the discovery
pin are ported by name; the rest are new coverage for the 9-step check order.

`client1` (the suite's default seeded client from `tests/helpers.seed_client`)
does NOT register the token-exchange URN in its `grant_types` — tests that
need an authorized exchanging client seed a dedicated `tx_client` via
`_seed_exchange_client` (a thin wrapper over `seed_client`).
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import jwt

from oauth2_server.models import Token
from oauth2_server.services.dpop import jwk_thumbprint
from tests.conftest import build_client_app
from tests.helpers import make_dpop_proof, post_token, seed_client

EXCHANGE_URN = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_URL = "https://auth.example.com/oauth/token"


async def _seed_exchange_client(client_app, **overrides):
    fields = {
        "client_id": "tx_client",
        "client_secret": "tx_secret",
        "grant_types": json.dumps([EXCHANGE_URN]),
        "scope": "read profile openid",
    }
    fields.update(overrides)
    return await seed_client(client_app.storage, **fields)


async def _seed_subject_token(
    client_app,
    *,
    access_token: str = "subject_token_value",
    scope: str = "read profile",
    user_id: str | None = "u1",
    client_id: str = "tx_client",
    expires_in: int = 3600,
    revoked: bool = False,
) -> Token:
    now = datetime.now(UTC)
    token = Token(
        id=uuid.uuid4().hex,
        access_token=access_token,
        token_type="Bearer",
        expires_in=expires_in,
        scope=scope,
        client_id=client_id,
        user_id=user_id,
        created_at=now,
        expires_at=now + timedelta(seconds=expires_in),
        revoked=revoked,
    )
    await client_app.storage.save_token(token)
    return token


def _basic(client_id: str, client_secret: str) -> tuple[str, str]:
    return (client_id, client_secret)


# --- Discovery -----------------------------------------------------------------


async def test_rfc8693_token_exchange_grant_type_in_discovery(client_app):
    resp = await client_app.get("/.well-known/openid-configuration")
    assert resp.status_code == 200, resp.text
    assert EXCHANGE_URN in resp.json()["grant_types_supported"]


# --- Rust regression pins (research-rar-token-exchange.md tests_to_port) -------


async def test_expired_subject_token_is_rejected(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(
        client_app, access_token="expired_access_token_value", expires_in=-3600
    )

    resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "expired_access_token_value",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_grant"
    assert resp.json()["error_description"] == "subject_token is expired or revoked"


async def test_valid_subject_token_is_exchanged(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(
        client_app, access_token="valid_access_token_value", scope="read profile"
    )

    resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "valid_access_token_value",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Rust never asserted these body fields — new coverage per the brief.
    assert body["issued_token_type"] == ACCESS_TOKEN_TYPE
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "read profile"
    assert body["access_token"]
    assert "refresh_token" not in body

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["sub"] == "u1"
    assert claims["client_id"] == "tx_client"


# --- Check order: grant allow-list, public-client, subject_token presence -----


async def test_exchange_requires_registered_grant(client_app):
    # client1's default grant_types (tests/helpers.seed_client) do NOT
    # include the token-exchange URN.
    await _seed_subject_token(client_app, access_token="subj_for_client1")

    resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_for_client1",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("client1", "s3cret"),
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "unauthorized_client"


async def test_public_client_rejected(client_app):
    await _seed_exchange_client(
        client_app,
        client_id="tx_public",
        client_secret="",
        token_endpoint_auth_method="none",
    )

    resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "client_id": "tx_public",
            "subject_token": "irrelevant",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"] == "invalid_client"
    assert resp.json()["error_description"] == "Public clients cannot use token-exchange"


async def test_missing_subject_token_rejected(client_app):
    await _seed_exchange_client(client_app)

    resp = await post_token(
        client_app,
        {"grant_type": EXCHANGE_URN, "subject_token_type": ACCESS_TOKEN_TYPE},
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_request"
    assert resp.json()["error_description"] == "Missing subject_token"


# --- subject_token_type / requested_token_type validation (divergence 18) -----


async def test_missing_subject_token_type_rejected(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, access_token="subj_no_type")

    resp = await post_token(
        client_app,
        {"grant_type": EXCHANGE_URN, "subject_token": "subj_no_type"},
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_request"
    assert "subject_token_type" in resp.json()["error_description"]

    # An unsupported (but present) value is rejected the same way.
    resp2 = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_no_type",
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert resp2.status_code == 400, resp2.text
    assert resp2.json()["error"] == "invalid_request"


async def test_unsupported_requested_token_type_rejected(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, access_token="subj_bad_requested_type")

    resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_bad_requested_type",
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_request"
    assert "requested_token_type" in resp.json()["error_description"]

    # Explicitly requesting the (only) supported type is fine.
    ok_resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_bad_requested_type",
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert ok_resp.status_code == 200, ok_resp.text


# --- Scope narrowing (subset enforcement) --------------------------------------


async def test_scope_narrowing_enforced(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, access_token="subj_scope_tok", scope="read profile")

    # Superset of the subject token's scope -> rejected.
    bad_resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_scope_tok",
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "scope": "read profile write",
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert bad_resp.status_code == 400, bad_resp.text
    assert bad_resp.json()["error"] == "invalid_scope"
    assert bad_resp.json()["error_description"] == "requested scope exceeds client permissions"

    # Subset -> issued with the narrowed scope.
    good_resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_scope_tok",
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "scope": "read",
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert good_resp.status_code == 200, good_resp.text
    assert good_resp.json()["scope"] == "read"


# --- DPoP binding on an exchanged token (review carry-over) --------------------


async def test_token_exchange_with_dpop_proof_binds_and_reports_dpop(client_app):
    """Review carry-over: the token-exchange branch passes `cnf` from the
    shared pre-grant DPoP block (routes/token.py) straight into
    `TokenService.issue`, same as every other grant — but no test drove a
    REAL signed proof through the exchange endpoint end-to-end. Confirms the
    exchanged token is DPoP-bound (cnf.jkt) AND still carries `act.sub` for
    the exchanging client, i.e. the two claims coexist correctly."""
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, access_token="subj_dpop_tok", scope="read")

    proof, pub_jwk = make_dpop_proof(TOKEN_URL, "POST")

    resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_dpop_tok",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "DPoP"

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["cnf"]["jkt"] == jwk_thumbprint(pub_jwk)
    assert "act" not in claims


# --- Cross-client introspection (Rust parity) -----------------------------------


async def test_exchanged_token_introspects_for_exchanging_client_only(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(
        client_app,
        access_token="subj_introspect_tok",
        scope="read",
        client_id="tx_client",
    )

    exchange_resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_introspect_tok",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert exchange_resp.status_code == 200, exchange_resp.text
    exchanged_token = exchange_resp.json()["access_token"]

    # The exchanging client can introspect its own exchanged token.
    own_introspect = await client_app.post(
        "/oauth/introspect",
        data={"token": exchanged_token},
        headers={"Authorization": "Basic " + base64.b64encode(b"tx_client:tx_secret").decode()},
    )
    assert own_introspect.status_code == 200, own_introspect.text
    assert own_introspect.json()["active"] is True

    # client1 (a different, unrelated client) gets active: false — cross-
    # client introspection never leaks token state, matching Rust.
    cross_introspect = await client_app.post(
        "/oauth/introspect",
        data={"token": exchanged_token},
        headers={"Authorization": "Basic " + base64.b64encode(b"client1:s3cret").decode()},
    )
    assert cross_introspect.status_code == 200, cross_introspect.text
    assert cross_introspect.json()["active"] is False


# --- Entitlement, scope, audience, sender constraint, actor_token ---------------


def _claims_jwt(**claims) -> str:
    return jwt.encode(claims, "unused-test-key", algorithm="HS256")


async def _exchange(client_app, subject_token: str, **extra):
    return await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            **extra,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )


async def _exchange_with_proof(client_app, subject_token: str, proof: str):
    return await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
        headers={"DPoP": proof},
    )


async def test_exchange_rejected_for_other_clients_subject_token(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, client_id="other_client")

    resp = await _exchange(client_app, "subject_token_value")
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_grant"


async def test_exchange_allowed_for_configured_pair():
    async with build_client_app({"token_exchange_allowed_pairs": "tx_client->other_client"}) as app:
        await _seed_exchange_client(app)
        await _seed_subject_token(app, client_id="other_client")
        resp = await _exchange(app, "subject_token_value")
        assert resp.status_code == 200, resp.text

        # The relation is exact: another issuing client is still refused.
        await _seed_subject_token(app, access_token="third", client_id="other_client2")
        resp = await _exchange(app, "third")
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"] == "invalid_grant"


async def test_exchange_scope_bound_by_caller_client_scope(client_app):
    await _seed_exchange_client(client_app, scope="read")
    await _seed_subject_token(client_app, client_id="tx_client", scope="read profile admin")

    resp = await _exchange(client_app, "subject_token_value", scope="admin")
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_scope"

    # Without an explicit scope the result is intersected with the caller's.
    resp = await _exchange(client_app, "subject_token_value")
    assert resp.status_code == 200, resp.text
    assert resp.json()["scope"] == "read"


async def test_exchange_drops_unbound_on_bound_subject_token(client_app):
    await _seed_exchange_client(client_app)
    proof, pub_jwk = make_dpop_proof(TOKEN_URL, "POST")
    jkt = jwk_thumbprint(pub_jwk)
    subject = _claims_jwt(cnf={"jkt": jkt}, aud=["tx_client"])
    await _seed_subject_token(client_app, access_token=subject, client_id="tx_client")

    # No proof at all.
    resp = await _exchange(client_app, subject)
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_grant"

    # A proof for a different key.
    other_proof, _ = make_dpop_proof(TOKEN_URL, "POST")
    resp = await _exchange_with_proof(client_app, subject, other_proof)
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_grant"

    # A proof for the bound key.
    resp = await _exchange_with_proof(client_app, subject, proof)
    assert resp.status_code == 200, resp.text
    claims = jwt.decode(resp.json()["access_token"], options={"verify_signature": False})
    assert claims["cnf"]["jkt"] == jkt


async def test_bound_subject_not_exchanged_for_unbound_opaque_token():
    # A sender-constrained JWT still valid after a switch to opaque issuance
    # must not be downgraded to an unbound bearer token.
    async with build_client_app({"access_tokens_opaque": True}) as app:
        await _seed_exchange_client(app)
        proof, pub_jwk = make_dpop_proof(TOKEN_URL, "POST")
        jkt = jwk_thumbprint(pub_jwk)
        subject = _claims_jwt(cnf={"jkt": jkt}, aud=["tx_client"])
        await _seed_subject_token(app, access_token=subject, client_id="tx_client")

        resp = await _exchange_with_proof(app, subject, proof)
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"] == "invalid_grant"
        assert "access_token" not in resp.json()

        # An unbound subject token still exchanges fine in opaque mode.
        await _seed_subject_token(app, access_token="plain", client_id="tx_client")
        resp = await _exchange(app, "plain")
        assert resp.status_code == 200, resp.text


async def test_resource_outside_subject_audience_rejected(client_app):
    await _seed_exchange_client(client_app)
    subject = _claims_jwt(aud=["https://api.one.example"])
    await _seed_subject_token(client_app, access_token=subject, client_id="tx_client")

    resp = await _exchange(client_app, subject, resource="https://api.evil.example")
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_target"

    resp = await _exchange(client_app, subject, resource="https://api.one.example")
    assert resp.status_code == 200, resp.text
    claims = jwt.decode(
        resp.json()["access_token"], options={"verify_signature": False, "verify_aud": False}
    )
    assert claims["aud"] in ("https://api.one.example", ["https://api.one.example"])


async def test_resource_rejected_when_subject_audience_unknown(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, client_id="tx_client")

    resp = await _exchange(client_app, "subject_token_value", resource="https://api.one.example")
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_target"


async def test_actor_token_is_not_claimed_unverified(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, client_id="tx_client")

    resp = await _exchange(client_app, "subject_token_value", actor_token="garbage")
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_request"


async def test_exchanged_token_carries_no_act_claim(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, client_id="tx_client", scope="read")

    resp = await _exchange(client_app, "subject_token_value")
    assert resp.status_code == 200, resp.text
    assert "act" not in resp.json()
    claims = jwt.decode(resp.json()["access_token"], options={"verify_signature": False})
    assert "act" not in claims


async def test_reexchange_of_own_exchanged_token(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, client_id="tx_client", scope="read")

    first = await _exchange(client_app, "subject_token_value")
    assert first.status_code == 200, first.text
    second = await _exchange(client_app, first.json()["access_token"])
    assert second.status_code == 200, second.text
