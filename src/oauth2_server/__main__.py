"""Entry point: `python -m oauth2_server`.

Runs uvicorn with uvloop + httptools and a single worker process. Replay
guards (client-assertion `jti`, DPoP), the PAR store, the device-poll tracker
and the rate limiters keep their state in process memory, so more than one
worker would give each worker its own independent copy. `OAUTH2_WORKERS`
values above 1 are therefore refused until that state can be shared.

The app is passed as an import string with `factory=True` so the worker
builds (and migrates) its own `Config`/`SqlStorage` — see `oauth2_server.app.build`.
"""

import os
from collections.abc import Mapping

import uvicorn

from oauth2_server.config import Config
from oauth2_server.conformance import seed_from_env


def resolve_worker_count(env: Mapping[str, str], conformance: bool = False) -> int:
    """Return the uvicorn worker count, refusing unsupported values.

    Defaults to 1. Raises `SystemExit` with an operator-readable message for a
    non-numeric or non-positive `OAUTH2_WORKERS`, and for any value above 1
    because replay and rate-limit state is per process.
    """
    if conformance:
        return 1
    raw = env.get("OAUTH2_WORKERS")
    if raw is None or raw.strip() == "":
        return 1
    try:
        workers = int(raw.strip())
    except ValueError:
        raise SystemExit(
            f"OAUTH2_WORKERS={raw!r} is invalid: expected a positive integer"
        ) from None
    if workers < 1:
        raise SystemExit(f"OAUTH2_WORKERS={raw!r} is invalid: expected a positive integer")
    if workers > 1:
        raise SystemExit(
            f"OAUTH2_WORKERS={workers} is not supported: replay and rate-limit state is "
            "per process; leave OAUTH2_WORKERS unset or set it to 1"
        )
    return workers


def main() -> None:
    # Fail fast in the parent process on an insecure config before spawning workers.
    config = Config()
    config.validate_for_production()
    # Conformance test mode (off by default) also fails closed here, before any
    # worker is spawned: a production-looking environment or an invalid seed
    # aborts startup. Its store is process-local, so it runs a single worker.
    conformance = seed_from_env(os.environ, config) is not None

    workers = resolve_worker_count(os.environ, conformance)
    uvicorn.run(
        "oauth2_server.app:build",
        factory=True,
        host=config.host,
        port=config.port,
        loop="uvloop",
        http="httptools",
        workers=workers,
        # Keep `scope["client"]` as the real TCP peer. Uvicorn would otherwise
        # rewrite it from `X-Forwarded-For` for loopback peers, and the mTLS
        # trusted-proxy check (`services/mtls.py`) must see the socket peer.
        # Forwarded addresses are derived explicitly in `client_address.py`.
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
