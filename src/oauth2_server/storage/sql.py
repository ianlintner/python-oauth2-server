"""SQLAlchemy-based SQL storage backend (SQLite / PostgreSQL).

Query text is translated 1:1 from `crates/oauth2-storage-sqlx/src/sqlx.rs`.
SQLAlchemy's `text()` uses named `:param` placeholders for both dialects, so
(unlike the Rust sqlx code, which hand-writes `?` vs `$n` per branch) a single
query string works for both backends here.
"""

from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from oauth2_server.models import AuthorizationCode, Client, DeviceAuthorization, Token, User
from oauth2_server.storage.migrations import run_migrations

_CLIENT_COLS = ", ".join(Client.model_fields.keys())
_USER_COLS = ", ".join(User.model_fields.keys())
_TOKEN_COLS = ", ".join(Token.model_fields.keys())
_AUTH_CODE_COLS = ", ".join(AuthorizationCode.model_fields.keys())
_DEVICE_AUTH_COLS = ", ".join(DeviceAuthorization.model_fields.keys())

# Columns update_client is allowed to change — mirrors the Rust UPDATE query,
# which deliberately excludes id/client_id/created_at/require_state.
_CLIENT_UPDATE_COLS = [
    "client_secret",
    "redirect_uris",
    "grant_types",
    "scope",
    "name",
    "updated_at",
    "token_endpoint_auth_method",
    "registration_access_token",
    "response_types",
    "contacts",
    "logo_uri",
    "client_uri",
    "policy_uri",
    "tos_uri",
    "jwks",
    "jwks_uri",
    "backchannel_logout_uri",
    "backchannel_logout_session_required",
    "frontchannel_logout_uri",
    "frontchannel_logout_session_required",
    "post_logout_redirect_uris",
    "tls_client_certificate_subject_dn",
    "enabled",
    "dpop_nonce_required",
]


def _insert_stmt(table: str, cols: str) -> str:
    names = [c.strip() for c in cols.split(",")]
    params = ", ".join(f":{c}" for c in names)
    return f"INSERT INTO {table} ({cols}) VALUES ({params})"


class SqlStorage:
    def __init__(
        self,
        database_url: str,
        migrations_dir: Path,
        *,
        pool_size: int | None = None,
    ):
        engine_kwargs: dict = {}
        # Pool sizing only applies to real connection-pooled backends; SQLite's
        # async driver uses NullPool by default and rejects these kwargs.
        if not database_url.startswith("sqlite") and pool_size is not None:
            engine_kwargs["pool_size"] = pool_size
            engine_kwargs["pool_pre_ping"] = True
        self._engine: AsyncEngine = create_async_engine(database_url, **engine_kwargs)
        self._migrations_dir = migrations_dir

    def _dump(self, model) -> dict:
        # mode="json" turns datetimes into ISO strings, which SQLite's TEXT
        # columns want — but asyncpg's Postgres driver requires native
        # datetime objects for TIMESTAMPTZ columns and rejects strings, so on
        # Postgres we pass Python objects through unconverted instead.
        mode = "json" if self._engine.dialect.name == "sqlite" else "python"
        return model.model_dump(mode=mode)

    async def init(self) -> None:
        await run_migrations(self._engine, self._migrations_dir)

    async def table_exists(self, name: str) -> bool:
        q = (
            "SELECT name FROM sqlite_master WHERE type='table' AND name=:n"
            if self._engine.dialect.name == "sqlite"
            else "SELECT tablename FROM pg_tables WHERE tablename=:n"
        )
        async with self._engine.connect() as conn:
            return (await conn.execute(text(q), {"n": name})).first() is not None

    # --- Clients ---

    async def save_client(self, client: Client) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(text(_insert_stmt("clients", _CLIENT_COLS)), self._dump(client))

    async def get_client(self, client_id: str) -> Client | None:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(f"SELECT {_CLIENT_COLS} FROM clients WHERE client_id = :cid"),
                        {"cid": client_id},
                    )
                )
                .mappings()
                .first()
            )
        return Client(**row) if row else None

    async def update_client(self, client: Client) -> None:
        set_clause = ", ".join(f"{c} = :{c}" for c in _CLIENT_UPDATE_COLS)
        async with self._engine.begin() as conn:
            await conn.execute(
                text(f"UPDATE clients SET {set_clause} WHERE client_id = :client_id"),
                self._dump(client),
            )

    async def delete_client(self, client_id: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM clients WHERE client_id = :cid"), {"cid": client_id}
            )

    # --- Users ---

    async def save_user(self, user: User) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(text(_insert_stmt("users", _USER_COLS)), self._dump(user))

    async def get_user_by_username(self, username: str) -> User | None:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(f"SELECT {_USER_COLS} FROM users WHERE username = :u"),
                        {"u": username},
                    )
                )
                .mappings()
                .first()
            )
        return User(**row) if row else None

    async def get_user_by_id(self, user_id: str) -> User | None:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(f"SELECT {_USER_COLS} FROM users WHERE id = :id"), {"id": user_id}
                    )
                )
                .mappings()
                .first()
            )
        return User(**row) if row else None

    # --- Tokens ---

    async def save_token(self, token: Token) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(text(_insert_stmt("tokens", _TOKEN_COLS)), self._dump(token))

    async def get_token_by_access_token(self, access_token: str) -> Token | None:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(f"SELECT {_TOKEN_COLS} FROM tokens WHERE access_token = :t"),
                        {"t": access_token},
                    )
                )
                .mappings()
                .first()
            )
        return Token(**row) if row else None

    async def get_token_by_refresh_token(self, refresh_token: str) -> Token | None:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(f"SELECT {_TOKEN_COLS} FROM tokens WHERE refresh_token = :t"),
                        {"t": refresh_token},
                    )
                )
                .mappings()
                .first()
            )
        return Token(**row) if row else None

    async def revoke_token(self, token: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE tokens SET revoked = :r WHERE access_token = :t OR refresh_token = :t"
                ),
                {"r": True, "t": token},
            )

    async def set_token_family(self, access_token: str, family: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text("UPDATE tokens SET token_family = :f WHERE access_token = :t"),
                {"f": family, "t": access_token},
            )

    async def revoke_token_family(self, family: str) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                text("UPDATE tokens SET revoked = :r WHERE token_family = :f"),
                {"r": True, "f": family},
            )
        return result.rowcount

    # --- Authorization codes ---

    async def save_authorization_code(self, code: AuthorizationCode) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text(_insert_stmt("authorization_codes", _AUTH_CODE_COLS)),
                self._dump(code),
            )

    async def get_authorization_code(self, code: str) -> AuthorizationCode | None:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(f"SELECT {_AUTH_CODE_COLS} FROM authorization_codes WHERE code = :c"),
                        {"c": code},
                    )
                )
                .mappings()
                .first()
            )
        return AuthorizationCode(**row) if row else None

    async def mark_authorization_code_used(self, code: str) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                text("UPDATE authorization_codes SET used = :u WHERE code = :c AND used = :f"),
                {"u": True, "c": code, "f": False},
            )
        return result.rowcount

    # --- Device authorizations (RFC 8628) ---

    async def save_device_authorization(self, d: DeviceAuthorization) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text(_insert_stmt("device_authorizations", _DEVICE_AUTH_COLS)),
                self._dump(d),
            )

    async def get_device_authorization_by_device_code(
        self, device_code: str
    ) -> DeviceAuthorization | None:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(
                            f"SELECT {_DEVICE_AUTH_COLS} FROM device_authorizations "
                            "WHERE device_code = :dc"
                        ),
                        {"dc": device_code},
                    )
                )
                .mappings()
                .first()
            )
        return DeviceAuthorization(**row) if row else None

    async def get_device_authorization_by_user_code(
        self, user_code: str
    ) -> DeviceAuthorization | None:
        async with self._engine.connect() as conn:
            row = (
                (
                    await conn.execute(
                        text(
                            f"SELECT {_DEVICE_AUTH_COLS} FROM device_authorizations "
                            "WHERE user_code = :uc"
                        ),
                        {"uc": user_code},
                    )
                )
                .mappings()
                .first()
            )
        return DeviceAuthorization(**row) if row else None

    async def approve_device_authorization(self, user_code: str, user_id: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE device_authorizations SET approved = :a, denied = :d, "
                    "user_id = :uid WHERE user_code = :uc"
                ),
                {"a": True, "d": False, "uid": user_id, "uc": user_code},
            )

    async def deny_device_authorization(self, user_code: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text(
                    "UPDATE device_authorizations SET denied = :d, approved = :a "
                    "WHERE user_code = :uc"
                ),
                {"d": True, "a": False, "uc": user_code},
            )

    async def mark_device_authorization_used(self, device_code: str) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                text(
                    "UPDATE device_authorizations SET used = :u "
                    "WHERE device_code = :dc AND used = :f"
                ),
                {"u": True, "dc": device_code, "f": False},
            )
        return result.rowcount

    async def expire_device_authorization(self, device_code: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text("UPDATE device_authorizations SET expires_at = :e WHERE device_code = :dc"),
                {"e": "1970-01-01T00:00:00+00:00", "dc": device_code},
            )
