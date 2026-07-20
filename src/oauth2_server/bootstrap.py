"""Startup seeding — port of the Rust server's OAUTH2_SEED_* admin bootstrap."""

import uuid

from oauth2_server.config import Config
from oauth2_server.models import User
from oauth2_server.security import hash_password
from oauth2_server.storage.base import Storage


async def seed_admin_user(storage: Storage, config: Config) -> bool:
    if not config.seed_password:
        return False
    if await storage.get_user_by_username(config.seed_username) is not None:
        return False
    await storage.save_user(
        User(
            id=uuid.uuid4().hex,
            username=config.seed_username,
            # TODO(task-3): switch to hash_password_async once it lands.
            password_hash=hash_password(config.seed_password),
            email=config.seed_email,
            role="admin",
        )
    )
    return True
