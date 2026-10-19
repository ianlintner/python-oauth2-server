"""Entry point: `python -m oauth2_server`.

Runs uvicorn with uvloop + httptools and one worker process per CPU (override
with `OAUTH2_WORKERS`). Because `workers` spawns independent processes, the
app must be passed as an import string with `factory=True` so each worker
builds (and migrates) its own `Config`/`SqlStorage` — see `oauth2_server.app.build`.
"""

import os

import uvicorn

from oauth2_server.config import Config
from oauth2_server.conformance import seed_from_env


def main() -> None:
    # Fail fast in the parent process on an insecure config before spawning workers.
    config = Config()
    config.validate_for_production()
    # Conformance test mode (off by default) also fails closed here, before any
    # worker is spawned: a production-looking environment or an invalid seed
    # aborts startup. Its store is process-local, so it runs a single worker.
    conformance = seed_from_env(os.environ, config) is not None

    workers = 1 if conformance else int(os.environ.get("OAUTH2_WORKERS", os.cpu_count() or 1))
    uvicorn.run(
        "oauth2_server.app:build",
        factory=True,
        host=config.host,
        port=config.port,
        loop="uvloop",
        http="httptools",
        workers=workers,
    )


if __name__ == "__main__":
    main()
