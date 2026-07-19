"""Entry point: `python -m oauth2_server`."""

import asyncio
from pathlib import Path

import uvicorn

from oauth2_server.app import create_app
from oauth2_server.config import Config
from oauth2_server.storage.sql import SqlStorage

MIGRATIONS = Path(__file__).resolve().parents[2] / "migrations" / "sql"


def main() -> None:
    config = Config()
    storage = SqlStorage(config.database_url, MIGRATIONS)
    asyncio.run(storage.init())
    app = create_app(config, storage)
    uvicorn.run(app, host=config.host, port=config.port, loop="uvloop")


if __name__ == "__main__":
    main()
