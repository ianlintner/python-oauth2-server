"""Divergence 59 — the stored `claims` request honored in the minted id_token.

OIDC Core §5.5 lets a client ask for individual claims via the `claims`
request parameter. Through Phase 4b this port validated the parameter and
stored it on the authorization code but never read it back. This suite pins
the narrow, deliberately non-widening semantics that Phase 4c added:

* a requested claim is only ever delivered when the GRANTED SCOPE already
  permits it — `claims` can never widen a grant;
* a `value` / `values` constraint that the actual claim value does not
  satisfy OMITS the claim;
* an unsatisfiable `essential` claim still returns a successful response
  (OIDC Core §5.5.1 makes `essential` a hint, not a hard requirement);
* `acr` / `auth_time` stay absent at code redemption — the token endpoint has
  no session to attest to them (the `userinfo` member is not honored at all,
  and `claims_parameter_supported` stays unadvertised).
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import jwt

from oauth2_server.services.claims_request import select_id_token_claims
from tests.helpers import login_session, post_token
from tests.test_token_endpoint import _pkce_pair

REDIRECT_URI = "https://a.example/cb"
BASIC = ("client1", "s3cret")


async def _id_token_for(client_app, *, claims: dict | None, scope: str = "openid email profile"):
    """Run a code flow carrying `claims=` and return the decoded id_token."""
    await login_session(client_app)
    verifier, challenge = _pkce_pair()
    params = {
        "response_type": "code",
        "client_id": "client1",
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if claims is not None:
        params["claims"] = json.dumps(claims)
    authz = await client_app.get("/oauth/authorize", params=params)
    assert authz.status_code == 302, authz.text
    code = parse_qs(urlparse(authz.headers["location"]).query)["code"][0]

    resp = await post_token(
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
    assert resp.status_code == 200, resp.text
    return jwt.decode(resp.json()["id_token"], options={"verify_signature": False})


# --- unit: select_id_token_claims --------------------------------------------


def test_select_returns_empty_for_none():
    selection = select_id_token_claims(None, scope="openid email")
    assert not selection.requested


def test_select_returns_empty_for_garbage():
    selection = select_id_token_claims("not-json{", scope="openid email")
    assert not selection.requested


def test_select_ignores_userinfo_member():
    raw = json.dumps({"userinfo": {"email": None}})
    assert not select_id_token_claims(raw, scope="openid email").requested


def test_select_scope_gates_email_and_preferred_username():
    raw = json.dumps({"id_token": {"email": None, "preferred_username": None}})
    assert select_id_token_claims(raw, scope="openid").requested == set()
    assert select_id_token_claims(raw, scope="openid email").requested == {"email"}
    assert select_id_token_claims(raw, scope="openid profile").requested == {"preferred_username"}


def test_select_records_value_constraints():
    raw = json.dumps({"id_token": {"email": {"value": "a@example.test"}}})
    selection = select_id_token_claims(raw, scope="openid email")
    assert selection.requested == {"email"}
    assert selection.allows("email", "a@example.test")
    assert not selection.allows("email", "b@example.test")
    # An unconstrained (or unrequested) claim is never filtered out.
    assert selection.allows("preferred_username", "anything")


# --- end-to-end --------------------------------------------------------------


async def test_claims_request_acr_and_auth_time_omitted_without_session(client_app):
    """`acr`/`auth_time` need a session fact the token endpoint does not have."""
    decoded = await _id_token_for(client_app, claims={"id_token": {"acr": None, "auth_time": None}})
    assert "acr" not in decoded
    assert "auth_time" not in decoded


async def test_claims_request_cannot_widen_scope(client_app):
    decoded = await _id_token_for(
        client_app, claims={"id_token": {"email": {"essential": True}}}, scope="openid"
    )
    assert "email" not in decoded
    assert decoded["sub"] == "u1"


async def test_claims_request_essential_unmet_still_succeeds(client_app):
    decoded = await _id_token_for(
        client_app,
        claims={"id_token": {"acr": {"essential": True, "values": ["urn:example:loa3"]}}},
    )
    assert "acr" not in decoded
    assert decoded["sub"] == "u1"


async def test_claims_request_value_mismatch_omits_claim(client_app):
    decoded = await _id_token_for(
        client_app, claims={"id_token": {"email": {"value": "someone.else@example.test"}}}
    )
    assert "email" not in decoded
    # The unconstrained sibling claim is untouched.
    assert decoded["preferred_username"] == "user_rfc"


async def test_claims_request_value_match_keeps_claim(client_app):
    decoded = await _id_token_for(
        client_app,
        claims={"id_token": {"email": {"values": ["user_rfc@example.test", "x@example.test"]}}},
    )
    assert decoded["email"] == "user_rfc@example.test"


async def test_no_claims_request_keeps_scope_gated_claims(client_app):
    decoded = await _id_token_for(client_app, claims=None)
    assert decoded["email"] == "user_rfc@example.test"
    assert decoded["preferred_username"] == "user_rfc"
