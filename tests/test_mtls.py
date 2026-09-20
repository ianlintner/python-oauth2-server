"""Phase 4c Task 1 shared infrastructure: mTLS header plumbing (divergence
47 — proxy-supplied client-certificate headers are read ONLY when
`trust_proxy_headers` is enabled) and the shared unverified-claims decoder.

Plumbing only: no request behavior changes yet — the mTLS tuple is threaded
into `ClientService.authenticate` but not acted on (Task 2).
"""

from __future__ import annotations

import base64
import json

import pytest
from starlette.requests import Request

import oauth2_server.services.device_poll as device_poll_module
from oauth2_server.config import Config
from oauth2_server.security import decode_unverified_claims
from oauth2_server.services.clients import ClientService, is_valid_redirect_uri
from oauth2_server.services.dpop import jwk_thumbprint
from oauth2_server.services.mtls import mtls_headers
from tests.conftest import build_client_app
from tests.helpers import (
    generate_rsa_keypair,
    login_session,
    make_dpop_proof,
    post_token,
    reseed_client,
)
from tests.test_token_endpoint import run_code_flow

MTLS_HEADERS = {
    "X-Client-Cert-Thumbprint": "abc123",
    "X-SSL-Client-S-DN": "CN=client1,O=Example",
}


def _request(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/oauth/token",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        }
    )


def _config(**overrides) -> Config:
    return Config(
        jwt_secret="unit-test-secret-not-for-production-0123456789abcdef",
        issuer="https://auth.example.com",
        **overrides,
    )


def test_mtls_headers_ignored_without_trust_proxy():
    assert mtls_headers(_request(MTLS_HEADERS), _config()) == (None, None)


def test_mtls_headers_read_with_trust_proxy():
    config = _config(trust_proxy_headers=True)
    assert mtls_headers(_request(MTLS_HEADERS), config) == ("abc123", "CN=client1,O=Example")


def test_mtls_headers_empty_values_are_none():
    config = _config(trust_proxy_headers=True)
    headers = {"X-Client-Cert-Thumbprint": "", "X-SSL-Client-S-DN": ""}
    assert mtls_headers(_request(headers), config) == (None, None)


def test_mtls_headers_thumbprint_is_trimmed_but_dn_is_verbatim():
    """The DN is compared BYTE-EXACTLY against the registered value, so this
    module must not silently normalize it: only an exactly-empty DN header
    reads as absent. The thumbprint is an opaque base64url token, so trimming
    the proxy's padding whitespace there is safe."""
    config = _config(trust_proxy_headers=True)
    headers = {"X-Client-Cert-Thumbprint": "  abc123  ", "X-SSL-Client-S-DN": "  CN=a,O=b  "}
    assert mtls_headers(_request(headers), config) == ("abc123", "  CN=a,O=b  ")

    blank_thumbprint = {"X-Client-Cert-Thumbprint": "   ", "X-SSL-Client-S-DN": "   "}
    assert mtls_headers(_request(blank_thumbprint), config) == (None, "   ")


def test_mtls_headers_absent_headers_are_none():
    assert mtls_headers(_request({}), _config(trust_proxy_headers=True)) == (None, None)


@pytest.mark.parametrize("send_headers", [False, True])
async def test_authenticate_accepts_mtls_kwarg_without_behavior_change(send_headers):
    async with build_client_app(config_overrides={"trust_proxy_headers": True}) as client_app:
        response = await post_token(
            client_app,
            {"grant_type": "client_credentials", "scope": "read"},
            basic_auth=("client1", "s3cret"),
            headers=dict(MTLS_HEADERS) if send_headers else None,
        )
    assert response.status_code == 200
    assert response.json()["access_token"]


async def test_authenticate_accepts_mtls_kwarg_directly():
    async with build_client_app() as client_app:
        service = ClientService.from_app(client_app.app.state)
        client = await service.authenticate(
            {"client_id": "client1", "client_secret": "s3cret"},
            None,
            mtls=("abc123", "CN=client1,O=Example"),
        )
    assert client.client_id == "client1"


def test_is_valid_redirect_uri_is_shared_from_clients_service():
    # Moved verbatim out of `routes/register.py` so the admin routes can
    # reuse it; register keeps a thin alias.
    from oauth2_server.routes.register import _is_valid_redirect_uri

    assert _is_valid_redirect_uri is is_valid_redirect_uri
    assert is_valid_redirect_uri("https://app.example.com/cb") is True
    assert is_valid_redirect_uri("https://app.example.com/cb#frag") is False
    assert is_valid_redirect_uri("ftp://app.example.com/cb") is False
    assert is_valid_redirect_uri("https:///cb") is False


@pytest.mark.parametrize("value", ["", "not-a-jwt", "a.b.c", 123, None])
def test_decode_unverified_claims_returns_empty_on_garbage(value):
    assert decode_unverified_claims(value) == {}


def test_decode_unverified_claims_reads_claims_without_verifying():
    import jwt

    token = jwt.encode({"cnf": {"jkt": "thumb"}, "sub": "u1"}, "some-other-secret")
    claims = decode_unverified_claims(token)
    assert claims["cnf"] == {"jkt": "thumb"}
    assert claims["sub"] == "u1"


# --- Task 2: RFC 8705 client authentication --------------------------------

CERT_THUMBPRINT = "Zm9vYmFyLXRodW1icHJpbnQtMzItYnl0ZXMtYjY0dQ"
CLIENT_DN = "CN=client1,O=Example"
CLIENT_CREDENTIALS = {"grant_type": "client_credentials", "scope": "read"}


def _cert_headers(thumbprint: str | None = CERT_THUMBPRINT, dn: str | None = None) -> dict:
    headers = {}
    if thumbprint is not None:
        headers["X-Client-Cert-Thumbprint"] = thumbprint
    if dn is not None:
        headers["X-SSL-Client-S-DN"] = dn
    return headers


def _trusting_app():
    return build_client_app(config_overrides={"trust_proxy_headers": True})


async def test_vector_p_mtls_subject_dn_validation():
    """RFC 8705 §2.1 `tls_client_auth`: the presented Subject DN must equal
    the registered one exactly."""
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        ok = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn=CLIENT_DN),
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["access_token"]

        bad = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn="CN=attacker,O=Example"),
        )
        assert bad.status_code == 401, bad.text
        assert bad.json() == {
            "error": "invalid_client",
            "error_description": "tls_client_auth: client certificate Subject DN does not match",
        }


async def test_tls_client_auth_missing_certificate_rejected():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        resp = await post_token(client_app, {**CLIENT_CREDENTIALS, "client_id": "client1"})
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"] == (
            "tls_client_auth requires a TLS client certificate "
            "(X-Client-Cert-Thumbprint header missing)"
        )


async def test_tls_client_auth_empty_dn_accepts_any_certificate():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn="",
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn="CN=whoever,O=Anywhere"),
        )
        assert resp.status_code == 200, resp.text


async def test_tls_client_auth_dn_configured_header_missing_rejected():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"] == (
            "tls_client_auth requires X-SSL-Client-S-DN header when Subject DN is configured"
        )


async def test_tls_client_auth_whitespace_only_dn_does_not_accept_any_certificate():
    """A whitespace-only registered DN must NOT fail open.

    Only an EXACTLY empty `tls_client_certificate_subject_dn` means "any
    certificate the proxy vouched for" (Rust parity). Trimming the configured
    value first would turn a DN of spaces into that wildcard, so any client
    certificate would authenticate this client.
    """
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn="   ",
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json() == {
            "error": "invalid_client",
            "error_description": (
                "tls_client_auth requires X-SSL-Client-S-DN header when Subject DN is configured"
            ),
        }


async def test_tls_client_auth_dn_comparison_is_byte_exact_about_whitespace():
    """A presented DN that differs from the registered one only by
    surrounding whitespace is a mismatch — the compare is byte-exact."""
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn=f"  {CLIENT_DN}  "),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"] == (
            "tls_client_auth: client certificate Subject DN does not match"
        )


async def test_tls_client_auth_ignores_form_client_secret():
    """A form `client_secret` never substitutes for a certificate: the row
    still carries a secret, but the registered method is certificate-bound."""
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="s3cret",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1", "client_secret": "s3cret"},
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"].startswith(
            "tls_client_auth requires a TLS client certificate"
        )


async def test_tls_client_auth_rejected_without_trust_proxy():
    """Divergence 47: without `trust_proxy_headers` the headers are not read
    at all, so a forged certificate header authenticates nobody."""
    async with build_client_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn=CLIENT_DN),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"].startswith(
            "tls_client_auth requires a TLS client certificate"
        )


def _self_signed_jwks(thumbprint: str = CERT_THUMBPRINT) -> dict:
    _pem, jwks = generate_rsa_keypair()
    jwks["keys"][0]["x5t#S256"] = thumbprint
    return jwks


async def test_self_signed_matches_registered_jwk():
    jwks = _self_signed_jwks()
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="self_signed_tls_client_auth",
            client_secret="",
            jwks=json.dumps(jwks),
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["access_token"]


async def test_self_signed_unknown_thumbprint_rejected():
    jwks = _self_signed_jwks("some-other-thumbprint")
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="self_signed_tls_client_auth",
            client_secret="",
            jwks=json.dumps(jwks),
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json() == {
            "error": "invalid_client",
            "error_description": (
                "self_signed_tls_client_auth: certificate does not match a registered JWK"
            ),
        }
        # The presented thumbprint is never echoed back.
        assert CERT_THUMBPRINT not in resp.text


async def test_self_signed_without_certificate_rejected():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="self_signed_tls_client_auth",
            client_secret="",
            jwks=json.dumps(_self_signed_jwks()),
        )
        resp = await post_token(client_app, {**CLIENT_CREDENTIALS, "client_id": "client1"})
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"] == (
            "self_signed_tls_client_auth requires a TLS client certificate "
            "(X-Client-Cert-Thumbprint header missing)"
        )


async def test_self_signed_without_jwks_rejected():
    """A legacy row with no key material cannot match any certificate, and
    says so with the same fixed message as a mismatch."""
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="self_signed_tls_client_auth",
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(),
        )
        assert resp.status_code == 401, resp.text
        assert resp.json()["error_description"] == (
            "self_signed_tls_client_auth: certificate does not match a registered JWK"
        )


async def test_mtls_authenticates_at_par_and_introspect():
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        headers = _cert_headers(dn=CLIENT_DN)

        par = await client_app.post(
            "/oauth/par",
            content="client_id=client1&response_type=code&scope=read",
            headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
        )
        assert par.status_code == 201, par.text
        assert par.json()["request_uri"].startswith("urn:ietf:params:oauth:request-uri:")

        token = await post_token(
            client_app, {**CLIENT_CREDENTIALS, "client_id": "client1"}, headers=headers
        )
        assert token.status_code == 200, token.text
        access_token = token.json()["access_token"]

        introspect = await client_app.post(
            "/oauth/introspect",
            data={"token": access_token, "client_id": "client1"},
            headers=headers,
        )
        assert introspect.status_code == 200, introspect.text
        assert introspect.json()["active"] is True


# --- Task 3: certificate-bound access tokens (cnf x5t#S256) ----------------

TOKEN_URL = "https://auth.example.com/oauth/token"
OTHER_THUMBPRINT = "b3RoZXItdGh1bWJwcmludC0zMi1ieXRlcy1iNjR1Cg"


def _unverified_cnf(access_token: str) -> dict | None:
    return decode_unverified_claims(access_token).get("cnf")


async def test_cert_bound_token_carries_x5t_s256_cnf():
    """RFC 8705 §3: a token issued over a (trusted-proxy) mTLS connection is
    bound to the certificate thumbprint via `cnf["x5t#S256"]`, stored
    verbatim. `token_type` stays "Bearer" — only DPoP binding flips it."""
    async with _trusting_app() as client_app:
        await reseed_client(
            client_app,
            token_endpoint_auth_method="tls_client_auth",
            tls_client_certificate_subject_dn=CLIENT_DN,
            client_secret="",
        )
        resp = await post_token(
            client_app,
            {**CLIENT_CREDENTIALS, "client_id": "client1"},
            headers=_cert_headers(dn=CLIENT_DN),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "Bearer"
        assert _unverified_cnf(body["access_token"]) == {"x5t#S256": CERT_THUMBPRINT}


async def test_cert_binding_applies_to_any_auth_method():
    """Rust parity: binding keys off the (trust-gated) thumbprint header
    alone, not off the client's registered authentication method."""
    async with _trusting_app() as client_app:
        resp = await post_token(
            client_app,
            CLIENT_CREDENTIALS,
            basic_auth=("client1", "s3cret"),
            headers=_cert_headers(),
        )
        assert resp.status_code == 200, resp.text
        assert _unverified_cnf(resp.json()["access_token"]) == {"x5t#S256": CERT_THUMBPRINT}


async def test_cert_binding_ignored_without_trust_proxy():
    """Divergence 47: an untrusted proxy's header binds nothing."""
    async with build_client_app() as client_app:
        resp = await post_token(
            client_app,
            CLIENT_CREDENTIALS,
            basic_auth=("client1", "s3cret"),
            headers=_cert_headers(),
        )
        assert resp.status_code == 200, resp.text
        assert _unverified_cnf(resp.json()["access_token"]) is None


async def test_dpop_beats_mtls_when_both_present():
    """`cnf` precedence: a valid DPoP proof wins over the certificate
    thumbprint, and only DPoP flips `token_type`."""
    proof, pub_jwk = make_dpop_proof(TOKEN_URL, "POST")
    async with _trusting_app() as client_app:
        resp = await post_token(
            client_app,
            CLIENT_CREDENTIALS,
            basic_auth=("client1", "s3cret"),
            headers={**_cert_headers(), "DPoP": proof},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["token_type"] == "DPoP"
        assert _unverified_cnf(body["access_token"]) == {"jkt": jwk_thumbprint(pub_jwk)}


async def test_device_grant_never_binds_x5t(monkeypatch):
    """Rust parity: the device grant hardcodes `cnf: None`, certificate or
    not."""
    async with _trusting_app() as client_app:
        headers = _cert_headers()
        start = await client_app.post(
            "/oauth/device_authorization",
            data={},
            headers={
                "Authorization": "Basic " + base64.b64encode(b"client1:s3cret").decode(),
                **headers,
            },
        )
        assert start.status_code == 200, start.text
        device_code = start.json()["device_code"]
        user_code = start.json()["user_code"]

        assert (await login_session(client_app)).status_code == 303
        verify = await client_app.post(
            "/oauth/device/verify", data={"user_code": user_code, "action": "approve"}
        )
        assert verify.status_code == 200, verify.text

        # RFC 8628 slow_down: advance the poll tracker's clock past the
        # device's 5s interval so this poll isn't rate-limited (same trick as
        # tests/test_device_flow.py).
        real_monotonic = device_poll_module.time.monotonic
        monkeypatch.setattr(device_poll_module.time, "monotonic", lambda: real_monotonic() + 5)
        token = await post_token(
            client_app,
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            },
            basic_auth=("client1", "s3cret"),
            headers=headers,
        )
        assert token.status_code == 200, token.text
        assert token.json()["token_type"] == "Bearer"
        assert _unverified_cnf(token.json()["access_token"]) is None


async def test_refresh_salvages_cert_binding_unchanged():
    """The refresh grant carries the OLD token's `cnf` forward verbatim —
    `_salvage_old_cnf` is kind-agnostic, so an `x5t#S256` binding survives
    rotation (and stays a Bearer token)."""
    async with _trusting_app() as client_app:
        issued, _code = await run_code_flow(
            client_app, scope="openid email", headers=_cert_headers()
        )
        assert issued.status_code == 200, issued.text
        assert _unverified_cnf(issued.json()["access_token"]) == {"x5t#S256": CERT_THUMBPRINT}

        refreshed = await post_token(
            client_app,
            {"grant_type": "refresh_token", "refresh_token": issued.json()["refresh_token"]},
            basic_auth=("client1", "s3cret"),
        )
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["token_type"] == "Bearer"
        assert _unverified_cnf(refreshed.json()["access_token"]) == {"x5t#S256": CERT_THUMBPRINT}


async def test_introspection_of_cert_bound_token_requires_matching_thumbprint():
    """Divergence 49: a cert-bound token introspected without a matching
    (trusted) thumbprint header collapses to `{"active": false}` — the same
    oracle-free shape as the DPoP `jkt` block."""
    async with _trusting_app() as client_app:
        issued = await post_token(
            client_app,
            CLIENT_CREDENTIALS,
            basic_auth=("client1", "s3cret"),
            headers=_cert_headers(),
        )
        assert issued.status_code == 200, issued.text
        access_token = issued.json()["access_token"]

        async def introspect(headers):
            return await client_app.post(
                "/oauth/introspect",
                data={"token": access_token},
                headers={
                    "Authorization": "Basic " + base64.b64encode(b"client1:s3cret").decode(),
                    **headers,
                },
            )

        missing = await introspect({})
        assert missing.status_code == 200, missing.text
        assert missing.json()["active"] is False

        mismatch = await introspect(_cert_headers(OTHER_THUMBPRINT))
        assert mismatch.status_code == 200, mismatch.text
        assert mismatch.json()["active"] is False

        match = await introspect(_cert_headers())
        assert match.status_code == 200, match.text
        body = match.json()
        assert body["active"] is True
        assert body["cnf"] == {"x5t#S256": CERT_THUMBPRINT}


async def test_unbound_token_introspection_unaffected():
    async with _trusting_app() as client_app:
        issued = await post_token(client_app, CLIENT_CREDENTIALS, basic_auth=("client1", "s3cret"))
        assert issued.status_code == 200, issued.text
        resp = await client_app.post(
            "/oauth/introspect",
            data={"token": issued.json()["access_token"]},
            headers={"Authorization": "Basic " + base64.b64encode(b"client1:s3cret").decode()},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["active"] is True
        # The response is dumped with `exclude_none`, so an unbound token
        # omits `cnf` entirely.
        assert "cnf" not in resp.json()


async def test_introspection_of_non_ascii_cert_binding_is_inactive_not_500():
    """A non-ASCII thumbprint must not escape the oracle-free path.

    Starlette decodes headers as latin-1, so a proxy header carrying any
    byte >= 0x80 binds fine at the token endpoint. `hmac.compare_digest`
    raises TypeError on a non-ASCII `str` rather than returning False, so
    comparing the raw strings would turn the `{"active": false}` mismatch
    path into a distinguishable 500 — an oracle for "this token IS
    certificate-bound". The comparison is done on UTF-8 bytes instead.
    """
    # httpx will not ASCII-encode a `str` header value, but a real proxy
    # emits raw bytes on the wire — send those, exactly as Starlette would
    # receive them, and it latin-1-decodes them back to `non_ascii`.
    non_ascii = "abcé"
    raw = {"X-Client-Cert-Thumbprint": non_ascii.encode("latin-1")}
    async with _trusting_app() as client_app:
        issued = await post_token(
            client_app,
            CLIENT_CREDENTIALS,
            basic_auth=("client1", "s3cret"),
            headers=raw,
        )
        assert issued.status_code == 200, issued.text
        access_token = issued.json()["access_token"]
        assert _unverified_cnf(access_token) == {"x5t#S256": non_ascii}

        basic = "Basic " + base64.b64encode(b"client1:s3cret").decode()

        mismatch = await client_app.post(
            "/oauth/introspect",
            data={"token": access_token},
            headers={"Authorization": basic, **_cert_headers()},
        )
        assert mismatch.status_code == 200, mismatch.text
        assert mismatch.json()["active"] is False

        # A non-ASCII *presented* value against an ASCII binding is the
        # mirror image of the same hazard.
        other = await post_token(
            client_app,
            CLIENT_CREDENTIALS,
            basic_auth=("client1", "s3cret"),
            headers=_cert_headers(),
        )
        reversed_mismatch = await client_app.post(
            "/oauth/introspect",
            data={"token": other.json()["access_token"]},
            headers={"Authorization": basic, **raw},
        )
        assert reversed_mismatch.status_code == 200, reversed_mismatch.text
        assert reversed_mismatch.json()["active"] is False

        # And the matching case still works end to end.
        match = await client_app.post(
            "/oauth/introspect",
            data={"token": access_token},
            headers={"Authorization": basic, **raw},
        )
        assert match.status_code == 200, match.text
        assert match.json()["active"] is True
        assert match.json()["cnf"] == {"x5t#S256": non_ascii}
