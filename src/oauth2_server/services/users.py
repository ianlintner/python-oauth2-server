"""Shared "is this account currently allowed to act" rule.

Every path that turns a stored subject into a session, a code or a token calls
`load_active_user`, so the rule lives in one place: the user must exist, be
enabled, and not be denylisted by username or email. A storage error
propagates (the request fails closed) rather than being treated as "allowed".
"""

from __future__ import annotations

from oauth2_server.middleware import check_subject_denylisted_strict
from oauth2_server.models import User


async def ensure_user_active(storage, user: User | None) -> User | None:
    if user is None or not user.enabled:
        return None
    if await check_subject_denylisted_strict(storage, "username", user.username) is not None:
        return None
    if await check_subject_denylisted_strict(storage, "email", user.email) is not None:
        return None
    return user


async def load_active_user(storage, user_id: str | None) -> User | None:
    """The stored user for `user_id`, or `None` when absent, disabled or denylisted."""
    if not user_id:
        return None
    return await ensure_user_active(storage, await storage.get_user_by_id(user_id))
