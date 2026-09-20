"""RFC 8707 Resource Indicators — validation of the `resource` parameter.

Divergence 32 (deliberate, beyond Rust): the Rust server accepts any string as
a `resource` value and copies it verbatim into the access token's `aud` claim.
This port enforces RFC 8707 §2's requirement that the value be an absolute URI
without a fragment, rejecting anything else with `invalid_target` — a
malformed audience is a configuration bug that is far cheaper to surface at the
request than to debug at the resource server.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from oauth2_server.errors import OAuthError

_INVALID_TARGET_DESCRIPTION = "resource must be an absolute URI without a fragment"


def validate_resource(value: str | None) -> str | None:
    """Return `value` unchanged when it is a usable resource indicator.

    `None` (the parameter was absent) passes straight through — callers treat
    that as "no resource requested", leaving `aud` as `[client_id]`. Anything
    present but not an absolute, fragment-free URI raises `OAuthError`
    (`invalid_target`, RFC 8707 §2).
    """
    if value is None:
        return None
    split = urlsplit(value)
    if not split.scheme or not split.netloc or split.fragment:
        raise OAuthError("invalid_target", _INVALID_TARGET_DESCRIPTION, 400)
    return value
