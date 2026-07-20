"""Tests for `storage/factory.py`'s `create_storage` backend dispatch.

Dispatches on `config.database_url`'s scheme: `mongodb://`/`mongodb+srv://` ->
MongoStorage (imported lazily so the default SQLite path never imports
`motor`); anything else -> SqlStorage. `motor` is in the dev dependency
group, so both mongo schemes construct a real `MongoStorage` here —
`MongoStorage.__init__` never connects (motor is lazy), so this is safe
without a live mongod.
"""

import pytest

from oauth2_server.config import Config
from oauth2_server.storage.factory import create_storage
from oauth2_server.storage.sql import SqlStorage

_JWT_SECRET = "unit-test-secret-not-for-production-0123456789abcdef"


def test_factory_returns_sqlstorage_for_sqlite():
    config = Config(jwt_secret=_JWT_SECRET)
    storage = create_storage(config)
    assert isinstance(storage, SqlStorage)


def test_factory_returns_sqlstorage_for_postgres_url():
    # SqlStorage.__init__ only builds an engine (no connection attempt), so
    # this is safe to construct without a live Postgres server.
    config = Config(
        jwt_secret=_JWT_SECRET,
        database_url="postgresql+asyncpg://user:pass@localhost/oauth2",
    )
    storage = create_storage(config)
    assert isinstance(storage, SqlStorage)


def test_factory_dispatches_mongo_scheme():
    try:
        from oauth2_server.storage.mongo import MongoStorage
    except ImportError:
        config = Config(jwt_secret=_JWT_SECRET, database_url="mongodb://localhost:27017/oauth2")
        with pytest.raises(RuntimeError, match="motor"):
            create_storage(config)
        return

    config = Config(jwt_secret=_JWT_SECRET, database_url="mongodb://localhost:27017/oauth2")
    storage = create_storage(config)
    assert isinstance(storage, MongoStorage)


def test_factory_mongo_srv_scheme_also_dispatches():
    try:
        from oauth2_server.storage.mongo import MongoStorage
    except ImportError:
        config = Config(
            jwt_secret=_JWT_SECRET,
            database_url="mongodb+srv://user:pass@cluster0.example.mongodb.net/oauth2",
        )
        with pytest.raises(RuntimeError, match="motor"):
            create_storage(config)
        return

    config = Config(
        jwt_secret=_JWT_SECRET,
        database_url="mongodb+srv://user:pass@cluster0.example.mongodb.net/oauth2",
    )
    storage = create_storage(config)
    assert isinstance(storage, MongoStorage)
