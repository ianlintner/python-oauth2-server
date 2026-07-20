"""Token issuance — RFC 6749 §5.1 / RFC 9068 JWT access tokens."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from oauth2_server.config import Config
from oauth2_server.keys import KeySet
from oauth2_server.models import Claims, Client, Token, TokenResponse
from oauth2_server.security import encode_access_token
from oauth2_server.storage.base import Storage


class TokenService:
    def __init__(self, storage: Storage, config: Config, keyset: KeySet | None = None):
        self._storage = storage
        self._config = config
        self._keyset = keyset

    async def issue(
        self,
        client: Client,
        user_id: str | None,
        scope: str,
        *,
        with_refresh: bool,
        token_family: str | None = None,
    ) -> TokenResponse:
        config = self._config
        subject = user_id or client.client_id

        if config.access_tokens_opaque:
            access_token = secrets.token_urlsafe(32)
        else:
            claims = Claims.new(
                subject, client.client_id, scope, config.access_token_ttl_secs, config.issuer
            )
            # Prefer the current RS256 key so access+refresh tokens follow
            # RS256 rotation automatically whenever one is configured; fall
            # back to the current HS256 key, then (no keyset at all) the
            # legacy kid-less HS256(jwt_secret) path in encode_access_token.
            signing_key = None
            if self._keyset is not None:
                signing_key = self._keyset.current_for_alg("RS256") or self._keyset.current_for_alg(
                    "HS256"
                )
            if signing_key is not None:
                access_token = encode_access_token(claims, config.jwt_secret, key=signing_key)
            else:
                access_token = encode_access_token(claims, config.jwt_secret)

        refresh_token = secrets.token_urlsafe(32) if with_refresh else None
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=config.access_token_ttl_secs)

        token = Token(
            id=uuid.uuid4().hex,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=config.access_token_ttl_secs,
            scope=scope,
            client_id=client.client_id,
            user_id=user_id,
            expires_at=expires_at,
            token_family=token_family,
        )
        await self._storage.save_token(token)

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=config.access_token_ttl_secs,
            scope=scope,
        )
