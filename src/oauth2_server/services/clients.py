"""Client authentication — RFC 6749 §2.3, ported from oauth2-actix client auth."""

from __future__ import annotations

import base64
import binascii
import secrets
from urllib.parse import unquote_plus

from oauth2_server.errors import OAuthError
from oauth2_server.models import Client
from oauth2_server.storage.base import Storage


class ClientService:
    def __init__(self, storage: Storage):
        self._storage = storage

    async def authenticate(self, request_form: dict, authorization_header: str | None) -> Client:
        basic = _parse_basic_auth(authorization_header)
        if basic is not None:
            client_id, client_secret = basic
        else:
            client_id = request_form.get("client_id")
            client_secret = request_form.get("client_secret")

        if not client_id:
            raise OAuthError("invalid_client", "missing client_id")

        client = await self._storage.get_client(client_id)
        if client is None or not client.enabled:
            raise OAuthError("invalid_client", "unknown or disabled client")

        if client.is_public():
            if client_secret:
                raise OAuthError("invalid_client", "public client must not present a secret")
            return client

        if not client_secret or not secrets.compare_digest(client_secret, client.client_secret):
            raise OAuthError("invalid_client", "invalid client secret")
        return client


def _parse_basic_auth(authorization_header: str | None) -> tuple[str, str] | None:
    if not authorization_header or not authorization_header.lower().startswith("basic "):
        return None
    encoded = authorization_header[len("Basic ") :].strip()
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise OAuthError("invalid_client", "malformed Basic auth header") from exc
    if ":" not in decoded:
        raise OAuthError("invalid_client", "malformed Basic auth header")
    raw_client_id, raw_client_secret = decoded.split(":", 1)
    # RFC 6749 §2.3.1: both components are application/x-www-form-urlencoded.
    return unquote_plus(raw_client_id), unquote_plus(raw_client_secret)
