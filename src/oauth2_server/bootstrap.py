"""Startup seeding — port of the Rust server's OAUTH2_SEED_* admin bootstrap."""

import logging
import uuid

from oauth2_server.config import Config
from oauth2_server.models import User
from oauth2_server.security import hash_password_async
from oauth2_server.storage.base import Storage

logger = logging.getLogger(__name__)

# Consistent with the admin API's password-reset floor
# (routes/admin/users.py::reset_user_password).
_MIN_SEED_PASSWORD_LEN = 8


async def seed_admin_user(storage: Storage, config: Config) -> bool:
    if not config.seed_password:
        return False
    if len(config.seed_password) < _MIN_SEED_PASSWORD_LEN:
        logger.warning(
            "seed admin user skipped: OAUTH2_SEED_PASSWORD is shorter than %d characters",
            _MIN_SEED_PASSWORD_LEN,
        )
        return False
    if await storage.get_user_by_username(config.seed_username) is not None:
        return False
    password_hash = await hash_password_async(config.seed_password)
    await storage.save_user(
        User(
            id=uuid.uuid4().hex,
            username=config.seed_username,
            password_hash=password_hash,
            email=config.seed_email,
            role="admin",
        )
    )
    return True


_TLS_CLIENT_AUTH_METHOD = "tls_client_auth"


async def warn_tls_clients_without_subject_dn(storage: Storage) -> list[str]:
    """Log one warning per `tls_client_auth` client with no registered Subject DN.

    Such a client can no longer authenticate (every attempt fails
    `invalid_client`); surfacing it at startup lets an operator set the DN via
    the admin API instead of discovering the lock-out on the first request.
    Returns the affected `client_id`s.
    """
    affected = [
        client.client_id
        for client in await storage.list_all_clients()
        if client.token_endpoint_auth_method == _TLS_CLIENT_AUTH_METHOD
        and not client.tls_client_certificate_subject_dn
    ]
    for client_id in affected:
        logger.warning(
            "client %r uses tls_client_auth but has no tls_client_certificate_subject_dn; "
            "it cannot authenticate until one is set (PUT /admin/api/clients/{id})",
            client_id,
        )
    return affected
