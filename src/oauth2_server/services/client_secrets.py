"""Turn a freshly minted plaintext client secret into its at-rest fields.

Every code path that creates or rotates a client secret (dynamic
registration, admin create/regenerate, conformance seeding) goes through
`protect_client_secret`, so no path can persist the plaintext. The plaintext
is returned to the caller's own response once and is never stored.
"""

from __future__ import annotations

import anyio.to_thread

from oauth2_server.services.credential_storage import derive_seal_key, seal, secret_verifier


def protect_client_secret_sync(plaintext: str, client_id: str, master: str) -> tuple[str, str]:
    """Return `(verifier, sealed_key)` for `plaintext`.

    `verifier` goes in `clients.client_secret` (nonrecoverable Argon2id);
    `sealed_key` goes in `clients.client_secret_key` (AES-256-GCM, bound to
    `client_id`) and exists only so the HMAC uses of the secret keep working.
    An empty secret (public client) yields `("", "")`.
    """
    if not plaintext:
        return "", ""
    return (
        secret_verifier(plaintext),
        seal(plaintext, derive_seal_key(master), client_id),
    )


async def protect_client_secret(plaintext: str, client_id: str, master: str) -> tuple[str, str]:
    """Async wrapper: Argon2 is CPU-bound, so keep it off the event loop."""
    return await anyio.to_thread.run_sync(protect_client_secret_sync, plaintext, client_id, master)
