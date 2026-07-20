"""Storage backend dispatch, keyed off `Config.database_url`'s scheme.

`mongodb://`/`mongodb+srv://` URLs select the (Phase 3d) MongoStorage
backend; everything else falls through to the SQL backend (SQLite /
PostgreSQL via SQLAlchemy). MongoStorage is imported lazily, inside
`create_storage`, so the default SQLite deployment path never imports
`motor` — `motor` is an optional dependency (`pip install oauth2-server
[mongo]`), and importing it unconditionally at module load time would make
it a hard requirement for every install.
"""

from __future__ import annotations

from oauth2_server.config import Config
from oauth2_server.storage import MIGRATIONS_DIR
from oauth2_server.storage.base import Storage
from oauth2_server.storage.sql import SqlStorage

_MONGO_SCHEMES = ("mongodb://", "mongodb+srv://")


def create_storage(config: Config) -> Storage:
    """Construct the `Storage` backend selected by `config.database_url`."""
    if config.database_url.startswith(_MONGO_SCHEMES):
        try:
            from oauth2_server.storage.mongo import MongoStorage
        except ImportError as e:
            raise RuntimeError(
                "MongoDB backend requested but 'motor' is not installed "
                "(pip install oauth2-server[mongo])"
            ) from e
        return MongoStorage(config.database_url)

    return SqlStorage(config.database_url, MIGRATIONS_DIR, pool_size=config.max_connections)
