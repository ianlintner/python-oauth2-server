"""The one place an OIDC id_token is built and signed (OIDC Core §2).

Two endpoints mint id_tokens and they must agree claim-for-claim:

- `POST /oauth/token` — the authorization_code, refresh_token and device_code
  grants, each with an access token to hash into `at_hash` (and, on the
  initial code exchange only, a `code` to hash into `c_hash` and a `nonce` to
  echo — OIDC Core §12.2 forbids echoing `nonce` on a refreshed id_token).
- `GET /oauth/authorize` — the hybrid `response_type=code id_token` branch,
  which has a `code` but no access token, so it sets `c_hash` and never
  `at_hash` (Rust parity: the front-channel id_token carries no `at_hash`
  because no token is delivered alongside it).

Divergence 40: the hybrid id_token shares this minter *and* its TTL — `exp =
iat + config.access_token_ttl_secs`, the same lifetime the token endpoint
uses, rather than a separate front-channel TTL.

`acr`/`amr`/`auth_time` are pass-through: the caller decides what the session
can attest to. They are omitted from the encoded JWT when `None`
(`IdTokenClaims` is dumped with `exclude_none=True`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from oauth2_server.keys import KeySet
from oauth2_server.models import Client, IdTokenClaims, User
from oauth2_server.services.claims_request import ClaimsSelection
from oauth2_server.security import encode_id_token, half_hash

if TYPE_CHECKING:
    from oauth2_server.config import Config


def mint_id_token(
    *,
    config: "Config",
    keyset: KeySet | None,
    client: Client,
    user_id: str,
    user: User | None,
    scope: str,
    nonce: str | None = None,
    access_token: str | None = None,
    code: str | None = None,
    acr: str | None = None,
    amr: list[str] | None = None,
    auth_time: int | None = None,
    claims_selection: ClaimsSelection | None = None,
) -> str:
    """Build and encode an id_token for `user_id` as `sub`.

    Callers must check `"openid" in scope` first; the id_token is minted
    unconditionally here. `user` is an optional best-effort lookup
    (`get_user_by_id`) — when the user row is missing (e.g. the user was
    deleted after the token was issued), `sub` is still set from `user_id`
    and the scope-gated `email`/`preferred_username` claims are simply
    omitted.

    `at_hash` is set only when `access_token` is given, `c_hash` only when
    `code` is given (both via `security.half_hash`). `keyset` (from
    `app.state.keyset`) lets RS256 id_tokens sign with the current rotated
    key instead of always the static env PEM — see `encode_id_token`. Raises
    `ValueError` (turned into a 500 `server_error` by every call site) when
    `config.id_token_alg == "RS256"` but neither the keyset nor
    `config.id_token_private_key_pem` can supply a signing key.

    `claims_selection` (divergence 59) is the OIDC Core §5.5 `claims` request
    distilled by `services/claims_request.py`. It only ever SUBTRACTS: a
    claim whose requested `value`/`values` the actual value does not satisfy
    is dropped. It cannot add a claim the scope did not already permit, which
    is why it is applied last, over the scope-gated assignments above.
    """
    scope_set = set(scope.split())
    now = int(datetime.now(timezone.utc).timestamp())
    claims = IdTokenClaims(
        iss=config.issuer,
        sub=user_id,
        aud=client.client_id,
        exp=now + config.access_token_ttl_secs,
        iat=now,
        nonce=nonce,
        acr=acr,
        amr=amr,
        auth_time=auth_time,
    )
    if access_token is not None:
        claims.at_hash = half_hash(access_token)
    if code is not None:
        claims.c_hash = half_hash(code)
    if user is not None:
        if "email" in scope_set:
            claims.email = user.email
        if "profile" in scope_set:
            claims.preferred_username = user.username
    if claims_selection is not None:
        for name in ("acr", "auth_time", "email", "preferred_username"):
            value = getattr(claims, name)
            if value is not None and not claims_selection.allows(name, value):
                setattr(claims, name, None)
    return encode_id_token(claims, config.jwt_secret, config=config, keyset=keyset)
