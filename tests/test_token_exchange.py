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

from oauth2_server.models import Token
from tests.helpers import post_token, seed_client

EXCHANGE_URN = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


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
