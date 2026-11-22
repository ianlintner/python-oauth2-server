"""POST /connect/register — RFC 7591 dynamic client registration."""

from __future__ import annotations

import json
import secrets
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import ORJSONResponse
from pydantic import ValidationError

from oauth2_server.models import Client, ClientRegistration, ClientRegistrationResponse
from oauth2_server.services.clients import (
    JWKS_URI_ERROR,
    KNOWN_GRANT_TYPES,
    RESERVED_REGISTRATION_SCOPES,
    SELF_REGISTRABLE_GRANT_TYPES,
    SELF_SIGNED_REQUIRES_JWKS_ERROR,
    SUPPORTED_RESPONSE_TYPES,
    VALID_AUTH_METHODS,
    _secrets_equal,
    is_valid_jwks_uri,
    is_valid_redirect_uri,
    validate_subject_dn,
)
from oauth2_server.services.client_secrets import protect_client_secret
from oauth2_server.services.events_bus import emit_event
from oauth2_server import clock

router = APIRouter()


def _registration_error(description: str) -> ORJSONResponse:
    return ORJSONResponse(
        {"error": "invalid_client_metadata", "error_description": description},
        status_code=400,
        headers={"Cache-Control": "no-store"},
    )


# Moved to `services/clients.py` so the admin client API can share it; the
# module-local name stays as the call sites (and tests) already spell it.
_is_valid_redirect_uri = is_valid_redirect_uri


def _presented_bearer(request: Request) -> str | None:
    header = request.headers.get("authorization") or ""
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _policy_error(reg: ClientRegistration, config, *, trusted: bool) -> str | None:
    """Metadata policy (RFC 7591 §2): every unsupported or non-self-service
    value is rejected, never dropped. Returns the error description or None."""
    for grant in reg.grant_types:
        if grant not in KNOWN_GRANT_TYPES:
            return f"unsupported grant_type: {grant!r}"
        if grant not in SELF_REGISTRABLE_GRANT_TYPES and not trusted:
            return f"grant_type {grant!r} requires an initial access token"
    for response_type in reg.response_types:
        if response_type not in SUPPORTED_RESPONSE_TYPES:
            return f"unsupported response_type: {response_type!r}"
    allowed = {s.strip() for s in config.self_registration_scopes if s.strip()}
    for scope in reg.scope.split():
        if scope in RESERVED_REGISTRATION_SCOPES or scope not in allowed:
            return f"scope {scope!r} is not available for registration"
    return None


@router.post("/register")
async def register_client(request: Request) -> ORJSONResponse:
    config = request.app.state.config
    if not config.dynamic_registration_enabled:
        return ORJSONResponse(
            {
                "error": "access_denied",
                "error_description": "dynamic client registration is disabled",
            },
            status_code=403,
            headers={"Cache-Control": "no-store"},
        )

    # Intake authentication (RFC 7591 §3): a configured initial access token
    # is always required; with none configured, anonymous registration must
    # have been enabled explicitly.
    initial_token = config.dynamic_registration_initial_access_token or ""
    trusted = False
    if initial_token:
        presented = _presented_bearer(request)
        if presented is None or not _secrets_equal(presented, initial_token):
            return ORJSONResponse(
                {
                    "error": "invalid_token",
                    "error_description": "a valid initial access token is required",
                },
                status_code=401,
                headers={"Cache-Control": "no-store", "WWW-Authenticate": "Bearer"},
            )
        trusted = True
    elif not config.dynamic_registration_anonymous:
        return ORJSONResponse(
            {
                "error": "access_denied",
                "error_description": "dynamic client registration is not open",
            },
            status_code=403,
            headers={"Cache-Control": "no-store"},
        )

    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        return _registration_error("invalid registration request")

    try:
        reg = ClientRegistration.model_validate(body)
    except ValidationError:
        return _registration_error("invalid registration request")

    policy_error = _policy_error(reg, config, trusted=trusted)
    if policy_error is not None:
        return _registration_error(policy_error)

    storage = request.app.state.storage

    if not reg.redirect_uris or not all(_is_valid_redirect_uri(u) for u in reg.redirect_uris):
        return _registration_error("redirect_uris must be a non-empty list of absolute URLs")

    if reg.backchannel_logout_uri and not _is_valid_redirect_uri(reg.backchannel_logout_uri):
        return _registration_error(
            "backchannel_logout_uri must be an absolute http(s) URL without fragment"
        )

    if reg.frontchannel_logout_uri and not _is_valid_redirect_uri(reg.frontchannel_logout_uri):
        return _registration_error(
            "frontchannel_logout_uri must be an absolute http(s) URL without fragment"
        )

    if reg.post_logout_redirect_uris and not all(
        _is_valid_redirect_uri(u) for u in reg.post_logout_redirect_uris
    ):
        return _registration_error(
            "post_logout_redirect_uris must be a list of absolute http(s) URLs without fragment"
        )

    if reg.token_endpoint_auth_method not in VALID_AUTH_METHODS:
        return _registration_error(
            f"token_endpoint_auth_method must be one of {sorted(VALID_AUTH_METHODS)}"
        )

    # RFC 7523 §3 / RFC 7591 §2: a private_key_jwt client's assertions can
    # only ever be verified against a registered key set.
    if (
        reg.token_endpoint_auth_method == "private_key_jwt"
        and reg.jwks is None
        and not reg.jwks_uri
    ):
        return _registration_error("private_key_jwt requires jwks or jwks_uri")

    # RFC 8705 §2.2 (divergence 48): a self-signed-certificate client is
    # authenticated by matching the certificate thumbprint against a
    # registered JWK's `x5t#S256`, so registering the method without any key
    # material would leave the client permanently unauthenticatable.
    if (
        reg.token_endpoint_auth_method == "self_signed_tls_client_auth"
        and reg.jwks is None
        and not reg.jwks_uri
    ):
        return _registration_error(SELF_SIGNED_REQUIRES_JWKS_ERROR)

    if reg.jwks is not None and reg.jwks_uri:
        return _registration_error("jwks and jwks_uri are mutually exclusive")

    # RFC 8705 §2.1: a `tls_client_auth` client is identified by its
    # registered Subject DN, so one must be supplied. Shape rules shared with
    # the admin API live in `services/clients.py::validate_subject_dn`.
    dn_error = validate_subject_dn(
        reg.token_endpoint_auth_method, reg.tls_client_certificate_subject_dn
    )
    if dn_error is not None:
        return _registration_error(dn_error)

    # `jwks_uri` is the one registrant-supplied URL this server dereferences
    # itself, so it gets a stricter rule than the redirect URIs above — see
    # `services/clients.py::is_valid_jwks_uri`.
    if reg.jwks_uri and not is_valid_jwks_uri(reg.jwks_uri):
        return _registration_error(JWKS_URI_ERROR)

    is_public = reg.token_endpoint_auth_method == "none"
    if is_public and "client_credentials" in reg.grant_types:
        return _registration_error(
            "public clients (token_endpoint_auth_method=none) cannot use the "
            "client_credentials grant"
        )

    now = clock.now()
    client_id = secrets.token_urlsafe(16)
    client_secret = "" if is_public else secrets.token_urlsafe(32)
    registration_access_token = secrets.token_urlsafe(32)
    # Persist only the verifier + sealed HMAC key; the plaintext secret and
    # registration access token go back in this response once and are never
    # stored (storage digests the registration access token on save).
    secret_verifier_value, sealed_secret_key = await protect_client_secret(
        client_secret, client_id, config.jwt_secret
    )

    client = Client(
        id=uuid.uuid4().hex,
        client_id=client_id,
        client_secret=secret_verifier_value,
        client_secret_key=sealed_secret_key,
        redirect_uris=json.dumps(reg.redirect_uris),
        grant_types=json.dumps(reg.grant_types),
        response_types=json.dumps(reg.response_types),
        scope=reg.scope,
        name=reg.client_name,
        created_at=now,
        updated_at=now,
        token_endpoint_auth_method=reg.token_endpoint_auth_method,
        registration_access_token=registration_access_token,
        contacts=json.dumps(reg.contacts),
        backchannel_logout_uri=reg.backchannel_logout_uri or "",
        backchannel_logout_session_required=reg.backchannel_logout_session_required,
        frontchannel_logout_uri=reg.frontchannel_logout_uri or "",
        frontchannel_logout_session_required=reg.frontchannel_logout_session_required,
        post_logout_redirect_uris=json.dumps(reg.post_logout_redirect_uris),
        jwks=json.dumps(reg.jwks) if reg.jwks else "",
        jwks_uri=reg.jwks_uri or "",
        tls_client_certificate_subject_dn=reg.tls_client_certificate_subject_dn or "",
        enabled=True,
    )
    await storage.save_client(client)
    emit_event(
        request.app.state.event_bus,
        "client_registered",
        client_id=client_id,
        metadata={"client_name": reg.client_name, "scope": reg.scope},
    )

    response_body = ClientRegistrationResponse(
        client_id=client_id,
        client_secret=None if is_public else client_secret,
        client_id_issued_at=int(now.timestamp()),
        client_secret_expires_at=None if is_public else 0,
        registration_access_token=registration_access_token,
        registration_client_uri=f"{config.issuer}/connect/register/{client_id}",
        redirect_uris=reg.redirect_uris,
        grant_types=reg.grant_types,
        response_types=reg.response_types,
        token_endpoint_auth_method=reg.token_endpoint_auth_method,
        client_name=reg.client_name,
        scope=reg.scope,
        jwks=reg.jwks,
        jwks_uri=reg.jwks_uri,
        tls_client_certificate_subject_dn=reg.tls_client_certificate_subject_dn,
        backchannel_logout_uri=reg.backchannel_logout_uri,
        backchannel_logout_session_required=reg.backchannel_logout_session_required,
        frontchannel_logout_uri=reg.frontchannel_logout_uri,
        frontchannel_logout_session_required=reg.frontchannel_logout_session_required,
        post_logout_redirect_uris=reg.post_logout_redirect_uris,
    )
    return ORJSONResponse(
        response_body.model_dump(exclude_none=True),
        status_code=201,
        headers={"Cache-Control": "no-store"},
    )
