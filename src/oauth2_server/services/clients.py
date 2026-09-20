"""Client authentication — RFC 6749 §2.3, ported from oauth2-actix client auth."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
import secrets
import socket
from urllib.parse import unquote_plus, urlparse

from oauth2_server.errors import OAuthError
from oauth2_server.middleware import check_subject_denylisted
from oauth2_server.models import Client
from oauth2_server.services.client_assertion import (
    JWT_BEARER_ASSERTION_TYPE,
    JtiReplayGuard,
    unverified_assertion_subject,
    validate_client_assertion,
)
from oauth2_server.services.events_bus import EventBus, emit_event
from oauth2_server.services.jwks_cache import JwksCache, resolve_client_jwks
from oauth2_server.storage.base import Storage

logger = logging.getLogger(__name__)

_UNKNOWN_OR_DISABLED_CLIENT_MESSAGE = "unknown or disabled client"

# RFC 7523 §3 auth methods, dispatched on the client's REGISTERED
# `token_endpoint_auth_method` — never on what the request happens to
# present, so a JWT client cannot fall back to `client_secret_basic`.
_JWT_AUTH_METHODS = frozenset({"client_secret_jwt", "private_key_jwt"})

# Every `token_endpoint_auth_method` this server accepts at registration. It
# lives here rather than in `routes/register.py` because BOTH intake paths —
# RFC 7591 dynamic registration and the admin JSON API
# (`routes/admin/clients.py`) — must validate against exactly the same set,
# and a route module is an awkward thing for another route module to import.
VALID_AUTH_METHODS = frozenset(
    {
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "none",
    }
)

JWKS_URI_ERROR = "jwks_uri must be an absolute https URL"


def is_valid_jwks_uri(uri: str) -> bool:
    """Whether `uri` is safe for this server to dereference as a client's
    JWKS endpoint.

    `jwks_uri` is the only client-supplied URL the server fetches itself
    (`services/jwks_cache.py`), so an unvalidated value is a server-side
    request forgery primitive: a registrant could aim it at an internal
    service or walk it across ports. The rule is an https-only variant of
    `routes/register.py::_is_valid_redirect_uri` — absolute, `https`, a real
    netloc, no fragment — plus a rejection of hosts that resolve to the
    server's own machine or its link-local metadata range:

    * `localhost` (and any `*.localhost` name, which RFC 6761 §6.3 reserves
      for the loopback interface),
    * loopback literals (`127.0.0.0/8`, `::1`),
    * link-local literals (`169.254.0.0/16`, `fe80::/10`), and
    * the unspecified addresses (`0.0.0.0`, `::`).

    This is a registration-time guard, not a complete SSRF defense: a
    hostname that only resolves to a private address at fetch time still
    passes. It removes the trivially-exploitable cases; DNS-rebinding-proof
    egress filtering belongs at the network layer.
    """
    parsed = urlparse(uri)
    if parsed.scheme != "https" or not parsed.netloc:
        return False
    if parsed.fragment or uri.endswith("#"):
        return False

    # `.hostname` lowercases and strips the brackets off an IPv6 literal. It
    # does not raise on CPython (only `.port` parses an int); the guard is
    # defensive against a stricter urllib.
    try:
        host = parsed.hostname
    except ValueError:
        return False
    if not host:
        return False

    if host == "localhost" or host.endswith(".localhost"):
        return False

    # Belt and braces: an all-numeric-label host cannot be a legitimate
    # registered name, so refuse it whether or not it parses as an address
    # (e.g. an out-of-range integer that no normalizer below accepts).
    if host.replace(".", "").isdigit():
        return False

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = _loose_ipv4(host)
        if address is None:
            # A registered name, not an IP literal in any spelling — nothing
            # more to check here.
            return True
    # Unwrap IPv4-mapped IPv6 (`::ffff:127.0.0.1`) explicitly: `is_loopback`
    # on the mapped form only became True in CPython 3.12.4+/3.13, so older
    # 3.12 patch releases (as on CI) would let it through.
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return not (address.is_loopback or address.is_link_local or address.is_unspecified)


def _loose_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Parse the legacy IPv4 spellings `ipaddress` refuses but resolvers
    accept, so the blocked-range check above sees the real address. Returns
    `None` for anything that is not an IPv4 address in some spelling.

    `ipaddress.ip_address` takes only dotted-quad decimal, so
    `https://2130706433/`, `https://0177.0.0.1/` and `https://127.1/` all
    slipped through as "registered names" while `getaddrinfo` (and every
    HTTP client on top of it) resolves each of them to 127.0.0.1 — a
    loopback-guard bypass. `inet_aton` implements exactly the historical
    grammar those clients use (decimal/octal/hex, 1-to-4 parts), so it is
    the right normalizer here.
    """
    try:
        return ipaddress.IPv4Address(socket.inet_ntoa(socket.inet_aton(host)))
    except OSError:
        return None


def _secrets_equal(a: str, b: str) -> bool:
    """Constant-time compare, safe for non-ASCII client secrets.

    ``secrets.compare_digest``/``hmac.compare_digest`` raise ``TypeError``
    when either ``str`` operand contains a non-ASCII character instead of
    returning ``False``. Both operands here can legitimately contain
    non-ASCII text — the Basic-auth password is UTF-8-decoded in
    ``_parse_basic_auth`` below with no ASCII restriction, and form bodies
    decode the same way — so a client sending a non-ASCII secret would
    otherwise turn a routine credential mismatch into an unhandled 500
    instead of the documented ``invalid_client`` error. Compare on the
    UTF-8 byte representation instead, which has no such restriction.
    """
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class ClientService:
    def __init__(
        self,
        storage: Storage,
        event_bus: EventBus | None = None,
        *,
        issuer: str | None = None,
        jwks_cache: JwksCache | None = None,
        jti_guard: JtiReplayGuard | None = None,
    ):
        self._storage = storage
        self._event_bus = event_bus
        self._issuer = issuer
        self._jwks_cache = jwks_cache
        self._jti_guard = jti_guard

    @classmethod
    def from_app(cls, state) -> ClientService:
        """Build a fully-wired service from `request.app.state`.

        Every route that authenticates a client goes through this so the
        RFC 7523 pieces (issuer, shared `JwksCache`, shared
        `JtiReplayGuard`) are never accidentally left unwired — a service
        built with the plain two-argument constructor still works for
        secret-based auth but rejects JWT methods outright (see
        `_authenticate_jwt`).
        """
        return cls(
            state.storage,
            state.event_bus,
            issuer=state.config.issuer,
            jwks_cache=state.jwks_cache,
            jti_guard=state.jti_guard,
        )

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
            if form_client_secret and not _secrets_equal(form_client_secret, client_secret):
                raise OAuthError("invalid_client", "client_secret mismatch")
        else:
            client_id = form_client_id
            client_secret = form_client_secret

        if not client_id:
            # Divergence 36 (deliberate): a form carrying `client_assertion`
            # but no `client_id` resolves the client from the assertion's
            # UNVERIFIED `sub`. That only picks which client row to load —
            # `validate_client_assertion` still re-checks the verified
            # `iss`/`sub` against that row's `client_id` before the request
            # is authenticated.
            client_id = unverified_assertion_subject(request_form.get("client_assertion") or "")

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

        if client.token_endpoint_auth_method in _JWT_AUTH_METHODS:
            await self._authenticate_jwt(client, request_form)
            return client

        if not client_secret or not _secrets_equal(client_secret, client.client_secret):
            self._emit_client_validated(client.client_id, success=False)
            raise OAuthError("invalid_client", "invalid client secret")
        self._emit_client_validated(client.client_id, success=True)
        return client

    async def _authenticate_jwt(self, client: Client, request_form: dict) -> None:
        """RFC 7523 §3 client authentication for a client registered with
        `client_secret_jwt` or `private_key_jwt`.

        No `client_validated` event is emitted here: Rust raises that event
        only from the secret-comparison path (`client_actor.rs`
        `ValidateClient`), and `_emit_client_validated`'s contract is
        deliberately scoped to that same outcome.
        """
        if self._issuer is None or self._jti_guard is None:
            raise OAuthError("invalid_client", "Client is not configured for JWT authentication")

        assertion_type = request_form.get("client_assertion_type")
        if not assertion_type:
            raise OAuthError("invalid_client", "Missing client_assertion_type")
        if assertion_type != JWT_BEARER_ASSERTION_TYPE:
            raise OAuthError("invalid_client", "Unsupported client_assertion_type")

        assertion = request_form.get("client_assertion")
        if not assertion:
            raise OAuthError("invalid_client", "Missing client_assertion")

        jwks = await resolve_client_jwks(client, self._jwks_cache)
        validate_client_assertion(
            client,
            assertion,
            # RFC 7523 §3 / Rust parity: the expected `aud` is the TOKEN
            # endpoint URL at EVERY endpoint that authenticates a client
            # this way (introspect, revoke, PAR, device authorization
            # included), not the URL of the endpoint being called.
            self._issuer.rstrip("/") + "/oauth/token",
            jwks=jwks,
            guard=self._jti_guard,
        )


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
