"""Migration runner applying the shared repo-root `migrations/sql/V*.sql` files.

The migrations are written for Postgres (the Rust server's primary target). For
SQLite (used in tests / local dev), we rewrite Postgres-only syntax to SQLite
equivalents, and special-case the handful of files that use Postgres-only
constructs (PL/pgSQL `DO $$` blocks, `IF NOT EXISTS` on `ADD COLUMN`) that
cannot be handled by textual rewrite alone.
"""

import re
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

SQLITE_REWRITES = [
    ("TIMESTAMPTZ", "TEXT"),
    ("BYTEA", "BLOB"),
    ("NOW()", "CURRENT_TIMESTAMP"),
    ("ADD COLUMN IF NOT EXISTS", "ADD COLUMN"),
]

# V6 makes tokens.user_id nullable via a PL/pgSQL DO $$ block, which SQLite
# doesn't support. SQLite also can't ALTER COLUMN to drop NOT NULL, so we
# rebuild the table instead. This mirrors the schema as of V1-V5 (V6 runs
# right after them, before any later ALTER TABLE tokens statements).
_V6_SQLITE_OVERRIDE = [
    """
    CREATE TABLE tokens_new (
        id TEXT PRIMARY KEY,
        access_token TEXT NOT NULL UNIQUE,
        refresh_token TEXT,
        token_type TEXT NOT NULL,
        expires_in INTEGER NOT NULL,
        scope TEXT NOT NULL,
        client_id TEXT NOT NULL,
        user_id TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        FOREIGN KEY (client_id) REFERENCES clients(client_id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """,
    "INSERT INTO tokens_new SELECT * FROM tokens",
    "DROP TABLE tokens",
    "ALTER TABLE tokens_new RENAME TO tokens",
    "CREATE INDEX idx_tokens_access_token ON tokens(access_token)",
    "CREATE INDEX idx_tokens_refresh_token ON tokens(refresh_token)",
    "CREATE INDEX idx_tokens_client_id ON tokens(client_id)",
    "CREATE INDEX idx_tokens_user_id ON tokens(user_id)",
]

SQLITE_VERSION_OVERRIDES: dict[int, list[str]] = {
    6: _V6_SQLITE_OVERRIDE,
}

_VERSION_RE = re.compile(r"^V(\d+)__")


def _version_of(path: Path) -> int:
    m = _VERSION_RE.match(path.name)
    if not m:
        raise ValueError(f"unversioned migration file: {path.name}")
    return int(m.group(1))


async def run_migrations(engine: AsyncEngine, migrations_dir: Path) -> None:
    files = sorted(migrations_dir.glob("V*.sql"), key=_version_of)
    is_sqlite = engine.dialect.name == "sqlite"
    async with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            # Serialize concurrent migrators (multi-worker startup) for the
            # duration of this transaction; released automatically at commit.
            await conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": 961_748_927})
        await conn.execute(
            text("CREATE TABLE IF NOT EXISTS py_schema_version (version INTEGER PRIMARY KEY)")
        )
        applied = {
            row[0]
            for row in (await conn.execute(text("SELECT version FROM py_schema_version"))).all()
        }
        if not applied:
            # Existing DB migrated by the Rust server? Backfill instead of re-running.
            try:
                await conn.execute(text("SELECT 1 FROM clients LIMIT 1"))
                for f in files:
                    await conn.execute(
                        text("INSERT INTO py_schema_version (version) VALUES (:v)"),
                        {"v": _version_of(f)},
                    )
                return
            except Exception:
                pass  # fresh DB — run everything

        for f in files:
            v = _version_of(f)
            if v in applied:
                continue
            if is_sqlite and v in SQLITE_VERSION_OVERRIDES:
                for stmt in SQLITE_VERSION_OVERRIDES[v]:
                    await conn.execute(text(stmt))
            else:
                sql = f.read_text()
                if is_sqlite:
                    for old, new in SQLITE_REWRITES:
                        sql = sql.replace(old, new)
                for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
                    await conn.execute(text(stmt))
            await conn.execute(
                text("INSERT INTO py_schema_version (version) VALUES (:v)"), {"v": v}
            )
