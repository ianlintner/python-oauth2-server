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
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from oauth2_server.models import Token
from oauth2_server.services.dpop import jwk_thumbprint
from tests.conftest import build_client_app
from tests.helpers import make_dpop_proof, post_token, seed_client

EXCHANGE_URN = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_URL = "https://auth.example.com/oauth/token"


async def _seed_exchange_client(client_app, **overrides):
    fields = dict(
        client_id="tx_client",
        client_secret="tx_secret",
        grant_types=json.dumps([EXCHANGE_URN]),
        scope="read profile openid",
    )
    fields.update(overrides)
    return await seed_client(client_app.storage, **fields)


async def _seed_subject_token(
    client_app,
    *,
    access_token: str = "subject_token_value",
    scope: str = "read profile",
    user_id: str | None = "u1",
    client_id: str = "other_client",
    expires_in: int = 3600,
    revoked: bool = False,
) -> Token:
    now = datetime.now(timezone.utc)
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


# --- act (delegation) semantics -------------------------------------------------


async def test_act_embedded_when_actor_token_present(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, access_token="subj_act_tok", scope="read")

    resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_act_tok",
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "actor_token": "some-opaque-actor-token",
            "actor_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Response-body `act` mirrors Rust: present only when actor_token was
    # supplied on this request.
    assert body["act"] == {"sub": "tx_client"}

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["act"] == {"sub": "tx_client"}


async def test_act_embedded_in_jwt_even_without_actor_token(client_app):
    """Fixed gap vs Rust (research doc gotchas): Rust's `act` claim never
    enters any issued JWT — only the response body, and only when
    `actor_token` was present. This port always embeds `act` in the JWT for
    exchanged tokens (impersonation is happening regardless of whether the
    caller declared an actor_token), while keeping the response-body `act`
    member Rust-conditional (see `test_act_embedded_when_actor_token_present`
    and `test_act_omitted_from_body_without_actor_token`)."""
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, access_token="subj_act_tok_2", scope="read")

    resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_act_tok_2",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "act" not in body

    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert claims["act"] == {"sub": "tx_client"}


async def test_opaque_mode_response_body_act_survives_while_token_is_opaque():
    # PHASE2-BACKLOG.md correction: opaque mode (`access_tokens_opaque`)
    # drops `cnf`/`authorization_details` from BOTH the JWT and the response
    # body, but `act` is the exception — `routes/token.py` computes `act`
    # locally and sets `body["act"] = act` unconditionally (gated only on
    # `actor_token` presence, not on opaque mode), so the response-body `act`
    # member survives even though the access token itself is a bare opaque
    # string with nowhere to carry the JWT claim.
    async with build_client_app({"access_tokens_opaque": True}) as opaque_app:
        await _seed_exchange_client(opaque_app)
        await _seed_subject_token(opaque_app, access_token="subj_act_opaque_tok", scope="read")

        resp = await post_token(
            opaque_app,
            {
                "grant_type": EXCHANGE_URN,
                "subject_token": "subj_act_opaque_tok",
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "actor_token": "some-opaque-actor-token",
                "actor_token_type": ACCESS_TOKEN_TYPE,
            },
            basic_auth=_basic("tx_client", "tx_secret"),
        )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["act"] == {"sub": "tx_client"}

        # An opaque access token is a bare random string, not a JWT — so
        # there is no JWT claim for `act` to have survived into.
        with pytest.raises(jwt.PyJWTError):
            jwt.decode(body["access_token"], options={"verify_signature": False})


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
    assert claims["act"] == {"sub": "tx_client"}


# --- Cross-client introspection (Rust parity) -----------------------------------


async def test_exchanged_token_introspects_for_exchanging_client_only(client_app):
    await _seed_exchange_client(client_app)
    await _seed_subject_token(
        client_app,
        access_token="subj_introspect_tok",
        scope="read",
        client_id="other_client",
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


# --- Nested act delegation chains (RFC 8693 §4.1, divergence 55) --------------


async def test_two_hop_exchange_nests_act(client_app):
    """Exchanging a token that was ITSELF produced by a prior exchange (by a
    DIFFERENT client) nests the prior `act` under the new one: `{"sub": <new
    client_id>, "act": {"sub": <prior client_id>}}`."""
    await _seed_exchange_client(client_app)
    await seed_client(
        client_app.storage,
        client_id="tx_client2",
        client_secret="tx_secret2",
        grant_types=json.dumps([EXCHANGE_URN]),
        scope="read profile openid",
    )
    await _seed_subject_token(client_app, access_token="subj_hop1", scope="read")

    first = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_hop1",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert first.status_code == 200, first.text
    first_token = first.json()["access_token"]

    second = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": first_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client2", "tx_secret2"),
    )
    assert second.status_code == 200, second.text
    claims = jwt.decode(second.json()["access_token"], options={"verify_signature": False})
    assert claims["act"] == {"sub": "tx_client2", "act": {"sub": "tx_client"}}


async def test_three_hop_exchange_nests_twice(client_app):
    """A third hop (by a third client) nests one level deeper still."""
    await _seed_exchange_client(client_app)
    await seed_client(
        client_app.storage,
        client_id="tx_client2",
        client_secret="tx_secret2",
        grant_types=json.dumps([EXCHANGE_URN]),
        scope="read profile openid",
    )
    await seed_client(
        client_app.storage,
        client_id="tx_client3",
        client_secret="tx_secret3",
        grant_types=json.dumps([EXCHANGE_URN]),
        scope="read profile openid",
    )
    await _seed_subject_token(client_app, access_token="subj_hop2", scope="read")

    first = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_hop2",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert first.status_code == 200, first.text

    second = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": first.json()["access_token"],
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client2", "tx_secret2"),
    )
    assert second.status_code == 200, second.text

    third = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": second.json()["access_token"],
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client3", "tx_secret3"),
    )
    assert third.status_code == 200, third.text
    claims = jwt.decode(third.json()["access_token"], options={"verify_signature": False})
    assert claims["act"] == {
        "sub": "tx_client3",
        "act": {"sub": "tx_client2", "act": {"sub": "tx_client"}},
    }


async def test_same_client_reexchange_collapses(client_app):
    """When the SAME client re-exchanges a token it already holds `act` for
    (`prior["sub"] == client.client_id`), the chain does NOT nest — it stays
    flat `{"sub": client_id}`."""
    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, access_token="subj_same_client", scope="read")

    first = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_same_client",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert first.status_code == 200, first.text

    second = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": first.json()["access_token"],
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert second.status_code == 200, second.text
    claims = jwt.decode(second.json()["access_token"], options={"verify_signature": False})
    assert claims["act"] == {"sub": "tx_client"}


async def test_over_depth_act_chain_rejected(client_app, monkeypatch):
    """A subject token whose `act` claim already nests deeper than the
    10-level limit is rejected with `invalid_request`, per
    `services/limits.py::check_depth`. Crafting a genuinely 11-deep chain via
    real exchanges would take 11 real hops/clients, so this test instead
    monkeypatches `decode_unverified_claims` (as used by
    `routes/token.py`'s token-exchange branch) to return a pre-built 11-deep
    `act` for the subject token under test — an acceptable unit-ish
    shortcut for a route-level depth-limit test."""
    from oauth2_server.routes import token as token_route

    await _seed_exchange_client(client_app)
    await _seed_subject_token(client_app, access_token="subj_over_depth", scope="read")

    deep_act: dict = {"sub": "client_0"}
    for i in range(1, 11):
        deep_act = {"sub": f"client_{i}", "act": deep_act}

    real_decode = token_route.decode_unverified_claims

    def fake_decode(token: str) -> dict:
        if token == "subj_over_depth":
            return {"act": deep_act}
        return real_decode(token)

    monkeypatch.setattr(token_route, "decode_unverified_claims", fake_decode)

    resp = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_over_depth",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_request"


async def test_response_body_act_matches_jwt_claim(client_app):
    """The response-body `act` (still conditional on `actor_token`) is the
    SAME nested object as the JWT `act` claim, not just a flat `{"sub":
    ...}`."""
    await _seed_exchange_client(client_app)
    await seed_client(
        client_app.storage,
        client_id="tx_client2",
        client_secret="tx_secret2",
        grant_types=json.dumps([EXCHANGE_URN]),
        scope="read profile openid",
    )
    await _seed_subject_token(client_app, access_token="subj_body_match", scope="read")

    first = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": "subj_body_match",
            "subject_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client", "tx_secret"),
    )
    assert first.status_code == 200, first.text

    second = await post_token(
        client_app,
        {
            "grant_type": EXCHANGE_URN,
            "subject_token": first.json()["access_token"],
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "actor_token": "some-opaque-actor-token",
            "actor_token_type": ACCESS_TOKEN_TYPE,
        },
        basic_auth=_basic("tx_client2", "tx_secret2"),
    )
    assert second.status_code == 200, second.text
    body = second.json()
    claims = jwt.decode(body["access_token"], options={"verify_signature": False})
    assert body["act"] == claims["act"] == {"sub": "tx_client2", "act": {"sub": "tx_client"}}


async def test_opaque_mode_act_split_unchanged():
    """Opaque mode's documented body-survives/JWT-claim-dropped split
    (`test_opaque_mode_response_body_act_survives_while_token_is_opaque`)
    still holds now that nesting logic is present. An opaque access token is
    a bare random string, so a SECOND exchange of it cannot recover a prior
    `act` via `decode_unverified_claims` (it isn't a JWT — no claims to
    read) — nesting simply doesn't trigger, and `act` stays the flat
    `{"sub": <exchanging client_id>}` for the second hop too, exactly as for
    a first hop."""
    async with build_client_app({"access_tokens_opaque": True}) as opaque_app:
        await _seed_exchange_client(opaque_app)
        await seed_client(
            opaque_app.storage,
            client_id="tx_client2",
            client_secret="tx_secret2",
            grant_types=json.dumps([EXCHANGE_URN]),
            scope="read profile openid",
        )
        await _seed_subject_token(opaque_app, access_token="subj_opaque_nest", scope="read")

        first = await post_token(
            opaque_app,
            {
                "grant_type": EXCHANGE_URN,
                "subject_token": "subj_opaque_nest",
                "subject_token_type": ACCESS_TOKEN_TYPE,
            },
            basic_auth=_basic("tx_client", "tx_secret"),
        )
        assert first.status_code == 200, first.text

        second = await post_token(
            opaque_app,
            {
                "grant_type": EXCHANGE_URN,
                "subject_token": first.json()["access_token"],
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "actor_token": "some-opaque-actor-token",
                "actor_token_type": ACCESS_TOKEN_TYPE,
            },
            basic_auth=_basic("tx_client2", "tx_secret2"),
        )
        assert second.status_code == 200, second.text
        body = second.json()
        assert body["act"] == {"sub": "tx_client2"}

        with pytest.raises(jwt.PyJWTError):
            jwt.decode(body["access_token"], options={"verify_signature": False})
