"""Storage backends for the OAuth2 server."""

from pathlib import Path

# Repo-root/migrations/sql, resolved relative to this package so it works
# both from a source checkout and an installed wheel with the same layout
# (src/oauth2_server/storage/__init__.py -> parents[3] == repo root). Shared
# by app.py's `build()` and storage/factory.py's `create_storage()` so the
# path logic lives in exactly one place.
MIGRATIONS_DIR = Path(__file__).resolve().parents[3] / "migrations" / "sql"
