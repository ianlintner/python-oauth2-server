"""Authorization-code minting and redirect-safety checks for the authorize/login flow.

Ported from `crates/oauth2-core/src/utils/redirect.rs` (`is_safe_redirect`) and the
authorization-code issuance path of `crates/oauth2-actix/src/handlers/oauth.rs`.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from oauth2_server.config import Config
from oauth2_server.models import AuthorizationCode, Client
from oauth2_server.storage.base import Storage


def is_safe_redirect(url: str | None) -> bool:
    """True only for same-origin relative paths — never an absolute or protocol-relative URL."""
    if not url:
        return False
    url = url.strip()
    if not url.startswith("/"):
        return False
    if url.startswith("//"):
        return False
    if "\\" in url:
        return False
    return True


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
    ) -> AuthorizationCode:
        now = datetime.now(timezone.utc)
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
            authorization_details=authorization_details,
            token_family=uuid.uuid4().hex,
        )
        await self._storage.save_authorization_code(auth_code)
        return auth_code
