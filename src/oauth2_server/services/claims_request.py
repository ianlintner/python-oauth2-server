"""OIDC Core §5.5 `claims` request — id_token (divergence 59) and userinfo (63).

The `claims` request parameter is validated and stored on the authorization
code by `routes/authorize.py`; this module reads it back when the id_token is
minted at code redemption and turns it into a `ClaimsSelection` that
`services/id_token.py` applies.

The semantics are deliberately narrow, because the `claims` parameter is
attacker-reachable on every authorization request:

* **It can never widen a grant.** A claim is only "requested" here when the
  GRANTED scope already permits it (`email` needs the `email` scope,
  `preferred_username` needs `profile`), so a `claims` document asking for
  `email` on an `openid`-only grant leaves the id_token exactly as it would
  have been. `acr`/`auth_time` need no scope, but they need a session fact
  the token endpoint does not have — the minter simply has nothing to put
  there at redemption.
* **The only observable effect is omission.** A `value` / `values` constraint
  the real claim value does not satisfy drops the claim from the id_token;
  everything else is a no-op over the existing scope-gated behavior.
* **`essential` is a hint, not a requirement** (OIDC Core §5.5.1): an
  unsatisfiable essential claim is logged at DEBUG and the response still
  succeeds. Failing the whole flow would let any client turn a claim this
  deployment cannot assert into a hard authentication error.

The `userinfo` member is honored the same way at `/oauth/userinfo` (divergence
63); `claims_parameter_supported` is therefore advertised.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

__all__ = ["ClaimsSelection", "select_id_token_claims", "select_userinfo_claims"]

logger = logging.getLogger(__name__)

# The id_token claims this server can answer a `claims` request for, mapped to
# the scope that must ALREADY have been granted for them to appear at all.
# `None` = no scope gate (but still no value to report at the token endpoint).
_SUPPORTED: dict[str, str | None] = {
    "acr": None,
    "auth_time": None,
    "email": "email",
    "preferred_username": "profile",
}


@dataclass(frozen=True)
class ClaimsSelection:
    """Which supported id_token claims the request asked for, and how.

    `requested` holds the scope-permitted subset of `_SUPPORTED`;
    `constraints` maps a requested claim to the list of acceptable values
    from its `value`/`values` member (absent = unconstrained); `essential`
    holds the requested claims marked `essential: true`, used only for the
    DEBUG log when one cannot be satisfied.
    """

    requested: set[str] = field(default_factory=set)
    constraints: dict[str, list] = field(default_factory=dict)
    essential: set[str] = field(default_factory=set)

    def allows(self, name: str, value: object) -> bool:
        """Whether `value` satisfies this request's constraint on `name`.

        Unrequested and unconstrained claims always pass — the selection only
        ever REMOVES a claim the scope already permitted.
        """
        allowed = self.constraints.get(name)
        if allowed is None:
            return True
        if value in allowed:
            return True
        if name in self.essential:
            logger.debug(
                "essential claim %r could not be satisfied (value not among %d requested)",
                name,
                len(allowed),
            )
        return False


# The userinfo claims a `claims` request can constrain — the same scope gates
# as the id_token, minus `acr`/`auth_time` (userinfo never reports them).
_SUPPORTED_USERINFO: dict[str, str | None] = {
    "email": "email",
    "preferred_username": "profile",
}


def select_id_token_claims(claims_request: str | None, *, scope: str) -> ClaimsSelection:
    """Build the id_token `ClaimsSelection` for a stored `claims` parameter."""
    return _select(claims_request, scope, "id_token", _SUPPORTED)


def select_userinfo_claims(claims_request: str | None, *, scope: str) -> ClaimsSelection:
    """Build the userinfo `ClaimsSelection` for a stored `claims` parameter."""
    return _select(claims_request, scope, "userinfo", _SUPPORTED_USERINFO)


def _select(
    claims_request: str | None,
    scope: str,
    member: str,
    supported: dict[str, str | None],
) -> ClaimsSelection:
    """Build the `ClaimsSelection` for one member of a stored `claims` parameter.

    `claims_request` is the raw string stored on the authorization code. It
    was validated as a JSON object at `/oauth/authorize`, but this is the
    trust boundary for a value that has since round-tripped through storage,
    so anything unparseable or unexpected yields an EMPTY selection (which is
    a complete no-op) rather than an error.
    """
    if not claims_request:
        return ClaimsSelection()
    try:
        document = json.loads(claims_request)
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        logger.debug("stored claims request is not valid JSON; ignoring")
        return ClaimsSelection()
    if not isinstance(document, dict):
        return ClaimsSelection()
    members = document.get(member)
    if not isinstance(members, dict):
        return ClaimsSelection()

    scope_set = set(scope.split())
    selection = ClaimsSelection()
    for name, required_scope in supported.items():
        if name not in members:
            continue
        if required_scope is not None and required_scope not in scope_set:
            # Never widen: the claim was not granted, so it was not requested.
            logger.debug(
                "claims request for %r ignored: %r scope not granted", name, required_scope
            )
            continue
        selection.requested.add(name)
        spec = members[name]
        if not isinstance(spec, dict):
            # `null` (or anything else) = "requested, voluntary, unconstrained".
            continue
        if spec.get("essential") is True:
            selection.essential.add(name)
        if "value" in spec:
            selection.constraints[name] = [spec["value"]]
        elif isinstance(spec.get("values"), list):
            selection.constraints[name] = list(spec["values"])
    return selection
