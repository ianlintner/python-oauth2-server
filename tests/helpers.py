from pathlib import Path

from oauth2_server.storage.sql import SqlStorage

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations" / "sql"


async def make_storage() -> SqlStorage:
    s = SqlStorage("sqlite+aiosqlite://", MIGRATIONS)
    await s.init()
    return s
