"""Authorization-code minting and redirect-safety checks for the authorize/login flow.

Ported from `crates/oauth2-core/src/utils/redirect.rs` (`is_safe_redirect`) and the
authorization-code issuance path of `crates/oauth2-actix/src/handlers/oauth.rs`.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from oauth2_server.config import Config
from oauth2_server.models import AuthorizationCode, Client
from oauth2_server.storage.base import Storage
from oauth2_server import clock


def is_safe_redirect(url: str | None) -> bool:
    """True only for same-origin relative paths — never an absolute or protocol-relative URL."""
    if not url:
        return False
    url = url.strip()
    if not url.startswith("/"):
        return False
    if url.startswith("//"):
        return False
    if "\\" in url:  # noqa: SIM103 - guard-clause form reads clearer for a redirect safety check
        return False
    return True


# How long a pending `return_to` saved before a login stays valid. After this
# window a login no longer replays the stored redirect target.
RETURN_TO_MAX_AGE_SECS = 600


def fresh_return_to(session: dict, fallback: str, *, now: float) -> str:
    """Resolve a session's `return_to` only if it is safe and recently stamped.

    Shared by password and social login so both enforce the same replay
    window against stale redirect targets.
    """
    target = session.get("return_to")
    stamped = session.get("return_to_ts")
    fresh = isinstance(stamped, int) and now - stamped <= RETURN_TO_MAX_AGE_SECS
    if not fresh or not isinstance(target, str) or not is_safe_redirect(target):
        return fallback
    return target


def scope_is_subset(requested: str, allowed: str) -> bool:
    return set(requested.split()).issubset(set(allowed.split()))


class AuthorizeService:
    def __init__(self, storage: Storage, config: Config):
        self._storage = storage
        self._config = config

    async def issue_code(
        self,
        client: Client,
        user_id: str,
        redirect_uri: str,
        scope: str,
        *,
        code_challenge: str | None,
        code_challenge_method: str | None,
        nonce: str | None,
        authorization_details: str | None = None,
        resource: str | None = None,
        claims_request: str | None = None,
        dpop_jkt: str | None = None,
    ) -> AuthorizationCode:
        now = clock.now()
        auth_code = AuthorizationCode(
            id=uuid.uuid4().hex,
            code=secrets.token_urlsafe(32),
            client_id=client.client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            expires_at=now + timedelta(seconds=self._config.authorization_code_ttl_secs),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            resource=resource,
            authorization_details=authorization_details,
            claims_request=claims_request,
            token_family=uuid.uuid4().hex,
            dpop_jkt=dpop_jkt,
        )
        await self._storage.save_authorization_code(auth_code)
        return auth_code
