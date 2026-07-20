"""RFC 9396 rich authorization requests — `authorization_details` validation.

Ported per `.superpowers/sdd/research-rar-token-exchange.md`: the Rust server
accepts `authorization_details` at `/oauth/authorize`, PAR, and `/oauth/token`
with essentially no validation — JSON-parse-only at the token endpoint, and
nothing at all at authorize/PAR — despite discovery hardcoding
`authorization_details_types_supported: ["openid"]` with nothing enforcing
it (research doc `gotchas`, "RAR type-specific validation" backlog gap #20).
This port FIXES that gap: RFC 9396 §2 requires `authorization_details` to be
a JSON array of objects, each carrying a `type` member, and this module
additionally enforces a configurable type allowlist
(`config.rar_types_supported`) that the Rust server advertises but never
checks.
"""

from __future__ import annotations

import json


class RarError(Exception):
    """Raised by `validate_authorization_details` to signal an RFC 9396
    `invalid_authorization_details` failure."""

    def __init__(self, description: str) -> None:
        self.error = "invalid_authorization_details"
        self.description = description
        super().__init__(description)


def validate_authorization_details(raw: str, allowed_types: list[str]) -> list[dict]:
    """Parse and validate a raw `authorization_details` JSON string.

    RFC 9396 §2: `authorization_details` MUST be a JSON array of objects,
    each carrying a `type` member identifying the authorization data type.
    Raises `RarError` (error="invalid_authorization_details") on:
      - malformed JSON -> "authorization_details is not valid JSON"
      - not a non-empty JSON array of objects ->
        "authorization_details must be a JSON array of objects"
      - an entry missing a (non-empty string) `type` ->
        "authorization_details entry is missing a type"
      - an entry's `type` not present in `allowed_types` ->
        "authorization_details type '<t>' is not supported"

    Returns the parsed list of dicts on success.
    """
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise RarError("authorization_details is not valid JSON") from None

    if (
        not isinstance(parsed, list)
        or not parsed
        or not all(isinstance(entry, dict) for entry in parsed)
    ):
        raise RarError("authorization_details must be a JSON array of objects")

    for entry in parsed:
        entry_type = entry.get("type")
        if not isinstance(entry_type, str) or not entry_type:
            raise RarError("authorization_details entry is missing a type")
        if entry_type not in allowed_types:
            raise RarError(f"authorization_details type '{entry_type}' is not supported")

    return parsed
