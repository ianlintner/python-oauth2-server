"""RFC 9101 JWT-Secured Authorization Requests (`request=` at /oauth/authorize).

Ported from `tests/compliance_wave5.rs` (the `wave5_jar_*` cases) and
`tests/rfc9700_compliance.rs::test_vector_q_jar_request_parameter_integration`,
plus the Python-side coverage the Rust suite lacks (RS256, `client_id`
binding, PAR interaction, `response_mode`/`response_type` overlay).

Rust-parity behaviors pinned here:
- dispatch is on the client's REGISTERED `token_endpoint_auth_method`, never
  on the JWT's own `alg` header;
- `aud` must be `{issuer}/oauth/authorize`, and `exp` + `iss` are mandatory
  for signed JARs (`iss == client_id`);
- JAR claims beat BOTH the query string and PAR-pushed values;
- `request` is read from the QUERY only — a JAR pushed inside a PAR body is
  ignored;
- every JAR failure is a 400 JSON body (they precede redirect_uri
  validation, so no redirect target is trusted yet).

Divergence 41: JAR *verification* failures carry `invalid_request_object`
(RFC 9101 §5) rather than Rust's flat `invalid_request`, and a JAR payload
carrying a `client_id` claim that disagrees with the query `client_id` is
rejected outright.
"""

from __future__ import annotations

import base64
import json
import time
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest

from tests.helpers import generate_rsa_keypair, login_session, reseed_client
from tests.test_token_endpoint import _pkce_pair

ISSUER = "https://auth.example.com"
AUTHORIZE_URL = f"{ISSUER}/oauth/authorize"
REDIRECT_URI = "https://a.example/cb"


# --- JAR builders -------------------------------------------------------------


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_unsigned_jar(payload: dict, *, header: dict | None = None, signature: str = "") -> str:
    """Build an `alg=none` JAR: base64url-nopad header + payload, and (per RFC
    7515 §6) an EMPTY signature segment. `header`/`signature` are overridable
    so the negative cases can present a signed-looking JWT to a public
    client."""
    header_b64 = _b64u(json.dumps(header or {"alg": "none", "typ": "JWT"}).encode())
    payload_b64 = _b64u(json.dumps(payload).encode())
    return f"{header_b64}.{payload_b64}.{signature}"


def make_hs256_jar(payload: dict, secret: str) -> str:
    return jwt.encode(payload, secret, algorithm="HS256")


def make_rs256_jar(payload: dict, private_key: bytes, kid: str | None = None) -> str:
    return jwt.encode(
        payload, private_key, algorithm="RS256", headers={"kid": kid} if kid else None
    )


def _signed_claims(client: str, **overrides) -> dict:
    """The `iss`/`aud`/`exp` envelope every signed JAR needs, before the
    request parameters are layered on. A claim passed as `None` is removed."""
    claims: dict = {
        "iss": client,
        "aud": AUTHORIZE_URL,
        "exp": int(time.time()) + 300,
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _query(location: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(location).query)


def _fragment(location: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(location).fragment)


async def _authorize(client_app, **params):
    return await client_app.get("/oauth/authorize", params=params)


# --- public clients: unsigned (alg=none) JARs ---------------------------------


async def test_wave5_jar_public_client_unsigned_succeeds(client_app):
    await reseed_client(client_app, token_endpoint_auth_method="none", client_secret="")
    await login_session(client_app)
    _, challenge = _pkce_pair()
    # No iss/aud/exp: an unsigned JAR is not verified, so none are required.
    jar = make_unsigned_jar(
        {
            "redirect_uri": REDIRECT_URI,
            "scope": "openid read",
            "nonce": "jar_nonce_pub",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        scope="read",
        request=jar,
    )
    assert resp.status_code == 302, resp.text
    assert "code" in _query(resp.headers["location"])


async def test_wave2_c1_public_client_jar_rejects_non_none_alg_header(client_app):
    await reseed_client(client_app, token_endpoint_auth_method="none", client_secret="")
    await login_session(client_app)
    _, challenge = _pkce_pair()
    # A real HS256 signature is irrelevant — the client is registered `none`,
    # so anything but `alg=none` is refused before any verification happens.
    jar = make_hs256_jar(
        _signed_claims("client1", code_challenge=challenge, code_challenge_method="S256"),
        "attacker-secret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == (
        "JAR from public client must use alg=none; signed JARs require a "
        "confidential client authentication method"
    )


async def test_wave2_c1_public_client_jar_rejects_nonempty_signature_with_alg_none(client_app):
    await reseed_client(client_app, token_endpoint_auth_method="none", client_secret="")
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_unsigned_jar(
        {"code_challenge": challenge, "code_challenge_method": "S256"},
        signature="bm90LWEtc2lnbmF0dXJl",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == "JAR with alg=none must have an empty signature"


async def test_jar_not_a_jwt_is_rejected(client_app):
    await login_session(client_app)
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request="not-a-jwt",
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == (
        "JAR request is not a valid JWT (expected header.payload.signature)"
    )


@pytest.mark.parametrize(
    ("jar", "expected"),
    [
        ("!!!!.eyJhIjoxfQ.", "JAR JWT header is not valid base64url"),
        (f"{_b64u(b'not json')}.eyJhIjoxfQ.", "JAR JWT header is not valid JSON"),
    ],
    ids=["bad_base64", "bad_json"],
)
async def test_jar_malformed_header_is_rejected(client_app, jar, expected):
    await reseed_client(client_app, token_endpoint_auth_method="none", client_secret="")
    await login_session(client_app)
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == expected


# --- confidential clients: HS256 ----------------------------------------------


async def test_wave5_jar_confidential_client_hs256_succeeds(client_app):
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1",
            redirect_uri=REDIRECT_URI,
            scope="openid read",
            nonce="jar_nonce_hs",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        "s3cret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        scope="read",
        request=jar,
    )
    assert resp.status_code == 302, resp.text
    assert "code" in _query(resp.headers["location"])


async def test_wave5_jar_tampered_hs256_is_rejected(client_app):
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims("client1", code_challenge=challenge, code_challenge_method="S256"),
        "wrong-secret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request_object"
    assert body["error_description"].startswith("JAR HS256 verification failed: ")


@pytest.mark.parametrize(
    ("overrides", "expected_prefix"),
    [
        ({"exp": None}, "JAR HS256 verification failed: "),
        ({"aud": "https://auth.example.com/oauth/token"}, "JAR HS256 verification failed: "),
        ({"iss": None}, "JAR HS256 verification failed: "),
    ],
    ids=["missing_exp", "wrong_aud", "missing_iss"],
)
async def test_jar_required_claims(client_app, overrides, expected_prefix):
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1", code_challenge=challenge, code_challenge_method="S256", **overrides
        ),
        "s3cret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request_object"
    assert body["error_description"].startswith(expected_prefix)


async def test_jar_missing_exp_rejected(client_app):
    await login_session(client_app)
    jar = make_hs256_jar(_signed_claims("client1", exp=None), "s3cret")
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request_object"


async def test_jar_wrong_aud_rejected(client_app):
    await login_session(client_app)
    jar = make_hs256_jar(_signed_claims("client1", aud="https://evil.example/"), "s3cret")
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request_object"


async def test_jar_iss_mismatch_rejected(client_app):
    """`iss` present and correctly signed, but naming a different client."""
    await login_session(client_app)
    jar = make_hs256_jar(_signed_claims("client1", iss="someone-else"), "s3cret")
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request_object"
    assert body["error_description"] == "JAR 'iss' claim must equal client_id"


async def test_jar_client_id_mismatch_rejected(client_app):
    """Divergence 41: a `client_id` claim must agree with the query's."""
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1",
            client_id="other-client",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        "s3cret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request_object"
    assert body["error_description"] == "JAR client_id does not match"


async def test_jar_matching_client_id_claim_is_accepted(client_app):
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1",
            client_id="client1",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        "s3cret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 302, resp.text


async def test_jar_unsupported_auth_method_is_rejected(client_app):
    await reseed_client(client_app, token_endpoint_auth_method="tls_client_auth")
    await login_session(client_app)
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=make_unsigned_jar({"scope": "read"}),
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == (
        "Unsupported token_endpoint_auth_method 'tls_client_auth' for JAR signing"
    )


# --- private_key_jwt clients: RS256 -------------------------------------------


async def test_jar_private_key_jwt_rs256_succeeds(client_app):
    pem, jwks = generate_rsa_keypair()
    await reseed_client(
        client_app, token_endpoint_auth_method="private_key_jwt", jwks=json.dumps(jwks)
    )
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_rs256_jar(
        _signed_claims(
            "client1",
            redirect_uri=REDIRECT_URI,
            scope="read",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        pem,
        kid="client-key-1",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 302, resp.text
    assert "code" in _query(resp.headers["location"])


async def test_jar_private_key_jwt_rejects_hs256_alg_confusion(client_app):
    """A `private_key_jwt` client is pinned to RS256: an HS256 JAR signed with
    the (public) JWKS modulus or any other material must not verify."""
    _, jwks = generate_rsa_keypair()
    await reseed_client(
        client_app, token_endpoint_auth_method="private_key_jwt", jwks=json.dumps(jwks)
    )
    await login_session(client_app)
    jar = make_hs256_jar(_signed_claims("client1", scope="read"), "s3cret")
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request_object"
    assert body["error_description"].startswith("JAR RS256 verification failed: ")


async def test_jar_private_key_jwt_unknown_kid_is_rejected(client_app):
    pem, jwks = generate_rsa_keypair()
    await reseed_client(
        client_app, token_endpoint_auth_method="private_key_jwt", jwks=json.dumps(jwks)
    )
    await login_session(client_app)
    jar = make_rs256_jar(_signed_claims("client1", scope="read"), pem, kid="no-such-kid")
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == "No matching kid in client JWKS for JAR"


# --- overlay precedence -------------------------------------------------------


async def test_vector_q_jar_state_beats_query_state(client_app):
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1",
            state="jar_state",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        "s3cret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        state="query_state",
        request=jar,
    )
    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    assert _query(location)["state"] == ["jar_state"]
    assert "query_state" not in location


async def test_vector_q_tampered_jar_state_is_rejected(client_app):
    """The tampered half of vector (q): flipping the signed `state` must not
    silently fall back to the query's."""
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1",
            state="jar_state",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        "s3cret",
    )
    header, payload, signature = jar.split(".")
    tampered_payload = _b64u(
        json.dumps(
            _signed_claims(
                "client1",
                state="attacker_state",
                code_challenge=challenge,
                code_challenge_method="S256",
            )
        ).encode()
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        state="query_state",
        request=f"{header}.{tampered_payload}.{signature}",
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request_object"


async def test_jar_non_string_claim_is_ignored(client_app):
    """Rust reads overlay claims through `as_str()`: a non-string value is
    invisible, so the query value survives."""
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1",
            state=12345,
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        "s3cret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        state="query_state",
        request=jar,
    )
    assert resp.status_code == 302, resp.text
    assert _query(resp.headers["location"])["state"] == ["query_state"]


async def test_jar_response_mode_wins(client_app):
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1",
            response_mode="form_post",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        "s3cret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        response_mode="query",
        request=jar,
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/html")
    assert 'action="https://a.example/cb"' in resp.text


async def test_jar_response_type_hybrid_validated(client_app):
    """The JAR's `response_type` is the effective one: `code id_token` in the
    JAR turns a `response_type=code` query into a hybrid request, fragment
    delivery and all."""
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1",
            response_type="code id_token",
            scope="openid read",
            nonce="jar-nonce",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        "s3cret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 302, resp.text
    fragment = _fragment(resp.headers["location"])
    assert "code" in fragment
    assert "id_token" in fragment


async def test_jar_unsupported_response_type_is_rejected(client_app):
    await login_session(client_app)
    jar = make_hs256_jar(_signed_claims("client1", response_type="token"), "s3cret")
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == (
        "Unsupported response_type in JAR; supported values: code, code id_token"
    )


# --- PAR interaction ----------------------------------------------------------


def _basic_header(client_id: str, client_secret: str) -> dict:
    raw = f"{client_id}:{client_secret}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


async def _push(client_app, body: str) -> str:
    resp = await client_app.post(
        "/oauth/par",
        content=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            **_basic_header("client1", "s3cret"),
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["request_uri"]


async def test_jar_overrides_par_values(client_app):
    await login_session(client_app)
    _, challenge = _pkce_pair()
    request_uri = await _push(
        client_app,
        "client_id=client1&response_type=code&scope=read&state=par_state"
        f"&redirect_uri=https%3A%2F%2Fa.example%2Fcb"
        f"&code_challenge={challenge}&code_challenge_method=S256",
    )
    jar = make_hs256_jar(_signed_claims("client1", state="jar_state"), "s3cret")
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        request_uri=request_uri,
        request=jar,
    )
    assert resp.status_code == 302, resp.text
    assert _query(resp.headers["location"])["state"] == ["jar_state"]


async def test_jar_in_par_body_is_ignored(client_app):
    """`request` is read from the QUERY only — a JAR smuggled into a PAR body
    is neither verified nor overlaid (it is not a PAR merge key)."""
    await login_session(client_app)
    _, challenge = _pkce_pair()
    forged = make_hs256_jar(_signed_claims("client1", state="forged_state"), "wrong-secret")
    request_uri = await _push(
        client_app,
        "client_id=client1&response_type=code&scope=read&state=par_state"
        f"&redirect_uri=https%3A%2F%2Fa.example%2Fcb"
        f"&code_challenge={challenge}&code_challenge_method=S256&request={forged}",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        request_uri=request_uri,
    )
    assert resp.status_code == 302, resp.text
    assert _query(resp.headers["location"])["state"] == ["par_state"]


# --- RFC 9700 §4.7 require_state (checked pre-overlay, against the query) -----


async def test_require_state_client_without_query_state_is_rejected(client_app):
    await reseed_client(client_app, require_state=True)
    await login_session(client_app)
    _, challenge = _pkce_pair()
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == (
        "state parameter is required for this client (RFC 9700 §4.7)"
    )


async def test_require_state_is_not_satisfied_by_a_jar_state(client_app):
    """Rust checks `require_state` BEFORE the JAR overlay: the outer request
    must carry `state` even when the JAR supplies one."""
    await reseed_client(client_app, require_state=True)
    await login_session(client_app)
    _, challenge = _pkce_pair()
    jar = make_hs256_jar(
        _signed_claims(
            "client1", state="jar_state", code_challenge=challenge, code_challenge_method="S256"
        ),
        "s3cret",
    )
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        request=jar,
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


async def test_require_state_client_with_query_state_succeeds(client_app):
    await reseed_client(client_app, require_state=True)
    await login_session(client_app)
    _, challenge = _pkce_pair()
    resp = await _authorize(
        client_app,
        response_type="code",
        client_id="client1",
        redirect_uri=REDIRECT_URI,
        state="query_state",
        code_challenge=challenge,
        code_challenge_method="S256",
    )
    assert resp.status_code == 302, resp.text
