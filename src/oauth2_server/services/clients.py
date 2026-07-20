"""Client authentication — RFC 6749 §2.3, ported from oauth2-actix client auth."""

from __future__ import annotations

import base64
import binascii
import logging
import secrets
from urllib.parse import unquote_plus

from oauth2_server.errors import OAuthError
from oauth2_server.middleware import check_subject_denylisted
from oauth2_server.models import Client
from oauth2_server.services.events_bus import EventBus, emit_event
from oauth2_server.storage.base import Storage

logger = logging.getLogger(__name__)

_UNKNOWN_OR_DISABLED_CLIENT_MESSAGE = "unknown or disabled client"


class ClientService:
    def __init__(self, storage: Storage, event_bus: EventBus | None = None):
        self._storage = storage
        self._event_bus = event_bus

    def _emit_client_validated(self, client_id: str, success: bool) -> None:
        # `client_validated` (research doc `key_behaviors` EVENT TYPES:
        # "emitted on BOTH secret match and mismatch") — scoped narrowly to
        # the actual secret-comparison outcome below, not every possible
        # `authenticate()` failure (missing client_id, unknown/disabled
        # client, denylisted client_id raise before ever reaching here).
        emit_event(
            self._event_bus,
            "client_validated",
            client_id=client_id,
            metadata={"success": "true" if success else "false"},
        )

    async def authenticate(self, request_form: dict, authorization_header: str | None) -> Client:
        basic = _parse_basic_auth(authorization_header)
        form_client_id = request_form.get("client_id")
        form_client_secret = request_form.get("client_secret")
        if basic is not None:
            client_id, client_secret = basic
            # RFC 6749 §2.3: reject duplicate credentials that disagree; allow
            # matching duplicates.
            if form_client_id and form_client_id != client_id:
                raise OAuthError("invalid_request", "client_id mismatch", 400)
            if form_client_secret and not secrets.compare_digest(form_client_secret, client_secret):
                raise OAuthError("invalid_client", "client_secret mismatch")
        else:
            client_id = form_client_id
            client_secret = form_client_secret

        if not client_id:
            raise OAuthError("invalid_client", "missing client_id")

        client = await self._storage.get_client(client_id)
        if client is None or not client.enabled:
            raise OAuthError("invalid_client", _UNKNOWN_OR_DISABLED_CLIENT_MESSAGE)

        # Subject-kind denylist (Phase 3a): a denylisted client_id is
        # rejected the same way as an unknown/disabled one — identical
        # error/description/status — so the response carries no oracle
        # distinguishing "denylisted" from "never registered".
        denylist_reason = await check_subject_denylisted(
            self._storage, "client_id", client.client_id
        )
        if denylist_reason is not None:
            logger.warning(
                "client auth blocked: client_id is denylisted (reason=%s)", denylist_reason
            )
            raise OAuthError("invalid_client", _UNKNOWN_OR_DISABLED_CLIENT_MESSAGE)

        if client.is_public():
            if client_secret:
                self._emit_client_validated(client.client_id, success=False)
                raise OAuthError("invalid_client", "public client must not present a secret")
            self._emit_client_validated(client.client_id, success=True)
            return client

        if not client_secret or not secrets.compare_digest(client_secret, client.client_secret):
            self._emit_client_validated(client.client_id, success=False)
            raise OAuthError("invalid_client", "invalid client secret")
        self._emit_client_validated(client.client_id, success=True)
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
