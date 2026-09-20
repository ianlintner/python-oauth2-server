"""OIDC `response_mode` parity: query / fragment / form_post delivery.

Covers the mode-aware authorize response builder
(`oauth2_server.services.authorize_response`) and its wiring into
`GET /oauth/authorize`: default resolution, rejection of unsupported
modes, the exact `form_post` auto-submit HTML shape, and the security
headers every authorize response carries in every mode.
"""

import re
from urllib.parse import parse_qs, urlsplit

import pytest

from oauth2_server.errors import OAuthError
from oauth2_server.services.authorize_response import resolve_response_mode
from tests.helpers import login_session, reseed_client

_SECURITY_HEADERS = {
    "cache-control": "no-store",
    "pragma": "no-cache",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "content-security-policy": "frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
}


def _assert_security_headers(resp):
    for header, expected in _SECURITY_HEADERS.items():
        assert resp.headers[header] == expected, header


def _authorize_params(**overrides):
    params = {
        "response_type": "code",
        "client_id": "client1",
        "redirect_uri": "https://a.example/cb",
        "scope": "read",
    }
    params.update(overrides)
    return params


# --- resolve_response_mode unit tests -----------------------------------------


def test_resolve_response_mode_defaults_to_query():
    assert resolve_response_mode(None, hybrid=False) == "query"


def test_resolve_response_mode_defaults_to_fragment_for_hybrid():
    assert resolve_response_mode(None, hybrid=True) == "fragment"


@pytest.mark.parametrize("mode", ["query", "form_post", "fragment"])
def test_resolve_response_mode_passes_through_supported_modes(mode):
    assert resolve_response_mode(mode, hybrid=False) == mode


@pytest.mark.parametrize("mode", ["form_post", "fragment"])
def test_resolve_response_mode_passes_through_hybrid_safe_modes(mode):
    # Divergence 46: `query` is the one mode hybrid may not request; see
    # `test_resolve_response_mode_rejects_query_for_hybrid` in
    # tests/test_hybrid_flow.py.
    assert resolve_response_mode(mode, hybrid=True) == mode


def test_resolve_response_mode_rejects_unsupported():
    with pytest.raises(OAuthError) as excinfo:
        resolve_response_mode("token", hybrid=False)
    assert excinfo.value.error == "invalid_request"
    assert excinfo.value.status == 400
    assert excinfo.value.description == (
        "Unsupported response_mode; supported values: query, form_post, fragment"
    )


# --- end-to-end delivery ------------------------------------------------------


async def test_wave5_response_mode_fragment_delivers_code_in_fragment(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize", params=_authorize_params(state="xyz", response_mode="fragment")
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "#" in location
    split = urlsplit(location)
    frag = parse_qs(split.fragment)
    assert "code" in frag
    assert frag["iss"] == ["https://auth.example.com"]
    assert frag["state"] == ["xyz"]
    assert "code" not in parse_qs(split.query)
    _assert_security_headers(resp)


async def test_wave5_unsupported_response_mode_is_rejected(app_with_session):
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize", params=_authorize_params(response_mode="token")
    )
    assert resp.status_code == 400
    assert "location" not in resp.headers
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == (
        "Unsupported response_mode; supported values: query, form_post, fragment"
    )


async def test_form_post_success_shape(app_with_session):
    await login_session(app_with_session)
    state = "a&b\"c'd<e>"
    resp = await app_with_session.get(
        "/oauth/authorize", params=_authorize_params(state=state, response_mode="form_post")
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/html; charset=utf-8"
    _assert_security_headers(resp)

    body = resp.text
    match = re.search(r'name="code" value="([^"]+)"', body)
    assert match is not None, body
    code = match.group(1)
    assert body == (
        "<!DOCTYPE html>\n"
        '<html><body onload="document.forms[0].submit()">\n'
        '<form method="post" action="https://a.example/cb">\n'
        f'<input type="hidden" name="code" value="{code}"/>\n'
        '<input type="hidden" name="iss" value="https://auth.example.com"/>\n'
        '<input type="hidden" name="state" '
        'value="a&amp;b&quot;c&#x27;d&lt;e&gt;"/>\n'
        "</form></body></html>"
    )


async def test_form_post_error_carries_no_store(app_with_session):
    # Divergence 37: a redirect-channel error honors response_mode too, and
    # the resulting 200 form_post page carries the full security header set.
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params=_authorize_params(response_type="token", state="xyz", response_mode="form_post"),
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/html; charset=utf-8"
    _assert_security_headers(resp)
    assert '<input type="hidden" name="error" value="unsupported_response_type"/>' in resp.text
    assert '<input type="hidden" name="state" value="xyz"/>' in resp.text


async def test_prompt_none_login_required_honors_fragment(app_with_session):
    # Divergence 37: prompt=none's login_required is delivered in the
    # requested response_mode, not always as a query redirect.
    resp = await app_with_session.get(
        "/oauth/authorize",
        params=_authorize_params(prompt="none", state="xyz", response_mode="fragment"),
    )
    assert resp.status_code == 302
    split = urlsplit(resp.headers["location"])
    assert split.query == ""
    frag = parse_qs(split.fragment)
    assert frag["error"] == ["login_required"]
    assert frag["state"] == ["xyz"]
    assert frag["iss"] == ["https://auth.example.com"]
    _assert_security_headers(resp)


async def test_query_mode_preserves_existing_query_string(app_with_session):
    await reseed_client(app_with_session, redirect_uris='["https://a.example/cb?foo=bar"]')
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize",
        params=_authorize_params(redirect_uri="https://a.example/cb?foo=bar", state="xyz"),
    )
    assert resp.status_code == 302
    q = parse_qs(urlsplit(resp.headers["location"]).query)
    assert q["foo"] == ["bar"]
    assert "code" in q
    assert q["state"] == ["xyz"]
    assert q["iss"] == ["https://auth.example.com"]


async def test_query_mode_rejects_redirect_uri_with_fragment(app_with_session):
    await reseed_client(app_with_session, redirect_uris='["https://a.example/cb#frag"]')
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize", params=_authorize_params(redirect_uri="https://a.example/cb#frag")
    )
    assert resp.status_code == 400
    assert "location" not in resp.headers
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert body["error_description"] == "redirect_uri must not contain a fragment"


async def test_fragment_never_contains_plus(app_with_session):
    # Divergence 45: fragment params are percent-encoded (quote_via=quote),
    # so a space is %20 and a literal `+` never appears.
    await login_session(app_with_session)
    resp = await app_with_session.get(
        "/oauth/authorize", params=_authorize_params(state="a b", response_mode="fragment")
    )
    assert resp.status_code == 302
    fragment = urlsplit(resp.headers["location"]).fragment
    assert "+" not in fragment
    assert "state=a%20b" in fragment
    assert parse_qs(fragment)["state"] == ["a b"]
