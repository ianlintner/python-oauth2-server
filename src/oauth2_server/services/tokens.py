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
        cnf: dict | None = None,
        authorization_details: list[dict] | None = None,
        act: dict | None = None,
        resource: str | None = None,
    ) -> TokenResponse:
        """Issue an access (+ optional refresh) token.

        `cnf` is the confirmation claim to bind onto the access token —
        either RFC 9449 §6.1 DPoP (`{"jkt": ...}`) or RFC 8705 §3.1
        certificate binding (`{"x5t#S256": ...}`) — see `routes/token.py`
        for which grants pass a real value. **Opaque mode drops it silently**: an opaque
        access token is a bare random string with nowhere to carry a `cnf`
        claim, so `cnf` here only ever reaches the issued token when
        `config.access_tokens_opaque` is False (Rust parity: the Rust server
        has no opaque-token mode at all, so this divergence is Python-only).
        The stored `Token` row's `token_type` always stays the model default
        "Bearer" regardless of `cnf` — only the `TokenResponse` returned here
        says "DPoP" (research-dpop.md `key_behaviors`: "the persisted Token
        row keeps token_type 'Bearer'"), and only for a `jkt` binding: a
        certificate-bound (`x5t#S256`) token is still a Bearer token.

        `authorization_details` (RFC 9396) follows the same opaque-mode
        drop rule as `cnf` — an opaque token has nowhere to carry it as a
        JWT claim, so it is silently omitted from both the issued token and
        the returned `TokenResponse` (parity with the Rust server, which has
        no opaque mode but likewise drops `authorization_details` on every
        path except the JWT claim — see research-rar-token-exchange.md).
        Callers pass `None` here for grants that drop RAR details entirely
        (refresh_token, device_code — Rust parity).

        `act` (RFC 8693 §4.1 delegation claim) follows the same opaque-mode
        drop rule as `cnf`/`authorization_details` — see routes/token.py's
        token-exchange branch for the only caller that passes a value and
        `models.Claims.act`'s docstring for the JWT-vs-response-body split.

        `resource` (RFC 8707) overrides the access token's `aud` claim, and
        is therefore ignored in opaque mode for the same reason as the
        claims above: an opaque token is a bare random string with no `aud`
        to bind. The stored `Token` row is unaffected either way — the
        audience lives only in the JWT.
        """
        config = self._config
        subject = user_id or client.client_id
        bound_cnf = cnf if not config.access_tokens_opaque else None
        bound_details = authorization_details if not config.access_tokens_opaque else None
        bound_act = act if not config.access_tokens_opaque else None

        if config.access_tokens_opaque:
            access_token = secrets.token_urlsafe(32)
        else:
            claims = Claims.new(
                subject,
                client.client_id,
                scope,
                config.access_token_ttl_secs,
                config.issuer,
                cnf=bound_cnf,
                authorization_details=bound_details,
                act=bound_act,
                resource=resource,
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
            # RFC 9449 §5: only a DPoP (`jkt`) binding makes this a "DPoP"
            # token. A certificate binding (RFC 8705 `x5t#S256`) stays
            # "Bearer" — the token is still presented with the `Bearer`
            # scheme, the certificate is the second factor.
            token_type="DPoP" if bound_cnf and bound_cnf.get("jkt") else "Bearer",
            expires_in=config.access_token_ttl_secs,
            scope=scope,
            authorization_details=bound_details,
        )
