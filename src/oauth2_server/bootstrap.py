"""Startup seeding — port of the Rust server's OAUTH2_SEED_* admin bootstrap."""

import uuid

from oauth2_server.config import Config
from oauth2_server.models import User
from oauth2_server.security import hash_password_async
from oauth2_server.storage.base import Storage


async def seed_admin_user(storage: Storage, config: Config) -> bool:
    if not config.seed_password:
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
