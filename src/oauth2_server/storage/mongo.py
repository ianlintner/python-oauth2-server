"""MongoDB storage backend — port of `crates/oauth2-storage-mongo/src/lib.rs`.

Documents are the JSON-mode serialization of the `oauth2_server.models`
Pydantic models, so field names match the SQL columns exactly (including the
JSON-array-as-string convention on `Client.redirect_uris` etc. — those stay
strings here too, never BSON arrays). Datetimes are stored as RFC 3339
strings (`model_dump(mode="json")` already renders them that way), not BSON
dates; `Model.MongoDateTime` (see `models.py`) tolerantly parses both on the
way back in, and `_normalize_legacy_timestamps` heals any real BSON dates
left over from older data in place (mirrors the Rust `init()` healer that
fixed a production `/auth/callback/github` 500 — PR #288 upstream).

Two intentional divergences from the Rust Mongo backend (both called out in
`.superpowers/sdd/research-mongo-backend.md`):

- `revoke_token_family` / `revoke_tokens_by_user_id` are actually
  implemented here (`update_many` + `modified_count`) instead of Rust's
  silently-no-op trait defaults (divergence 28) — the gap breaks RFC 9700
  §4.13.2 refresh-replay cascade revocation and OIDC-logout revocation on
  Mongo, and there's no reason to port a bug.
- `mark_authorization_code_used` / `mark_device_authorization_used` use an
  atomic `find_one_and_update` single-claim (divergence 30) instead of
  Rust's non-atomic `update_one` (no `find_one_and_update` call exists
  anywhere in the Rust repo) — this closes a double-spend race at the
  storage layer while keeping the same `int` (1 claimed / 0 already used)
  return contract as `SqlStorage`.

`mongodb+srv://` is accepted here (divergence 31) — Rust hard-rejects it to
dodge a hickory-proto DNS-resolver security advisory that doesn't apply to
this driver stack.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import motor.motor_asyncio
from pydantic import BaseModel
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from oauth2_server.errors import OAuthError
from oauth2_server.models import (
    AuthorizationCode,
    Client,
    DeviceAuthorization,
    Token,
    User,
)

logger = logging.getLogger(__name__)

_DEFAULT_DB_NAME = "oauth2"

# (collection name, natural key field, datetime fields) — drives both the
# `created_at` index list (clients/users/tokens only, per Rust's
# `ensure_indexes`) and the legacy-BSON-date healer (all five, per Rust's
# `normalize_legacy_timestamps`).
_TIMESTAMP_HEAL_SPECS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("clients", "client_id", ("created_at", "updated_at")),
    ("users", "id", ("created_at", "updated_at")),
    ("tokens", "access_token", ("created_at", "expires_at")),
    ("authorization_codes", "code", ("created_at", "expires_at")),
    ("device_authorizations", "device_code", ("created_at", "expires_at")),
)


def _db_name_from_url(url: str) -> str:
    path = urlsplit(url).path
    name = path.lstrip("/").split("/", 1)[0]
    return name or _DEFAULT_DB_NAME


def _to_doc(model: BaseModel, omit_when_none: tuple[str, ...] = ()) -> dict:
    """`model.model_dump(mode="json")`, minus the fields in `omit_when_none`
    that are currently `None`. NOT a blanket `exclude_none` — fields like
    `Token.user_id` / `DeviceAuthorization.user_id` must round-trip as an
    explicit `null` in the document, only the fields callers name (Token's
    `refresh_token`/`token_family`, AuthorizationCode's PKCE/RAR/token-
    exchange extras) are dropped entirely when absent, matching the Rust
    `serde skip_serializing_if` annotations this ports."""
    doc = model.model_dump(mode="json")
    for field in omit_when_none:
        if doc.get(field) is None:
            doc.pop(field, None)
    return doc


def _from_doc(model_cls: type, doc: dict | None):
    if doc is None:
        return None
    return model_cls(**{k: v for k, v in doc.items() if k != "_id"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MongoStorage:
    def __init__(self, url: str):
        # motor's AsyncIOMotorClient is lazy — no I/O happens until the
        # first operation, so constructing this never connects.
        self._client = motor.motor_asyncio.AsyncIOMotorClient(url)
        self._db = self._client[_db_name_from_url(url)]
        self.clients = self._db["clients"]
        self.users = self._db["users"]
        self.tokens = self._db["tokens"]
        self.authorization_codes = self._db["authorization_codes"]
        self.device_authorizations = self._db["device_authorizations"]
        self.denylist = self._db["denylist"]
        self.audit_log = self._db["audit_log"]

    async def _ensure_indexes(self) -> None:
        await self.clients.create_index("client_id", unique=True)
        await self.clients.create_index([("created_at", -1)])
        await self.users.create_index("username", unique=True)
        await self.users.create_index("email")
        await self.users.create_index([("created_at", -1)])
        await self.tokens.create_index("access_token", unique=True)
        # NON-unique on purpose: Azure Cosmos DB for MongoDB silently drops
        # the sparse flag on sparse+unique indexes, which would collide on
        # multiple tokens that omit refresh_token entirely. Uniqueness for
        # refresh tokens that *are* set is an application-level invariant
        # instead (the value is a high-entropy random token).
        await self.tokens.create_index("refresh_token")
        await self.tokens.create_index([("created_at", -1)])
        await self.authorization_codes.create_index("code", unique=True)
        await self.device_authorizations.create_index("device_code", unique=True)
        await self.device_authorizations.create_index("user_code", unique=True)
        await self.device_authorizations.create_index("client_id")
        await self.denylist.create_index([("kind", 1), ("value", 1)], unique=True)

    async def _normalize_legacy_timestamps(self) -> None:
        """Idempotent: rewrites any BSON-Date-typed datetime field back to
        an RFC 3339 string, per collection/field. Wrapped per-collection in
        try/except — some fixtures (mongomock-motor) don't support the
        `$type` operator, and that gap must not break real-mongod runs."""
        for coll_name, key_field, fields in _TIMESTAMP_HEAL_SPECS:
            coll = self._db[coll_name]
            for field in fields:
                try:
                    healed = 0
                    async for doc in coll.find({field: {"$type": "date"}}):
                        value = doc[field]
                        if isinstance(value, datetime):
                            if value.tzinfo is None:
                                value = value.replace(tzinfo=timezone.utc)
                            iso = value.isoformat()
                        else:  # pragma: no cover - defensive, shouldn't happen
                            continue
                        await coll.update_one({key_field: doc[key_field]}, {"$set": {field: iso}})
                        healed += 1
                    if healed:
                        logger.info(
                            "normalized legacy BSON Date timestamps",
                            extra={"collection": coll_name, "field": field, "count": healed},
                        )
                except Exception:
                    logger.debug(
                        "skipping legacy timestamp normalization for %s.%s "
                        "(backend doesn't support $type queries)",
                        coll_name,
                        field,
                        exc_info=True,
                    )

    async def init(self) -> None:
        await self._db.command({"ping": 1})
        await self._ensure_indexes()
        await self._normalize_legacy_timestamps()

    async def healthcheck(self) -> None:
        await self._db.command({"ping": 1})

    @staticmethod
    async def _insert(collection, doc: dict) -> None:
        try:
            await collection.insert_one(doc)
        except DuplicateKeyError as e:
            raise OAuthError("invalid_request", "duplicate key") from e

    # --- Clients ---

    async def save_client(self, client: Client) -> None:
        await self._insert(self.clients, _to_doc(client))

    async def get_client(self, client_id: str) -> Client | None:
        doc = await self.clients.find_one({"client_id": client_id})
        return _from_doc(Client, doc)

    async def update_client(self, client: Client) -> None:
        # Full document replace (not `$set`) — matches the Rust
        # `replace_one`. No upsert; a missing match is silently a no-op.
        await self.clients.replace_one({"client_id": client.client_id}, _to_doc(client))

    async def delete_client(self, client_id: str) -> None:
        await self.clients.delete_one({"client_id": client_id})

    async def set_client_enabled(self, client_id: str, enabled: bool) -> None:
        await self.clients.update_one(
            {"client_id": client_id}, {"$set": {"enabled": enabled, "updated_at": _now_iso()}}
        )

    async def set_client_secret(self, client_id: str, client_secret: str) -> None:
        await self.clients.update_one(
            {"client_id": client_id},
            {"$set": {"client_secret": client_secret, "updated_at": _now_iso()}},
        )

    # --- Users ---

    async def save_user(self, user: User) -> None:
        await self._insert(self.users, _to_doc(user))

    async def get_user_by_username(self, username: str) -> User | None:
        doc = await self.users.find_one({"username": username})
        return _from_doc(User, doc)

    async def get_user_by_id(self, user_id: str) -> User | None:
        doc = await self.users.find_one({"id": user_id})
        return _from_doc(User, doc)

    async def update_user(self, user: User) -> None:
        await self.users.update_one(
            {"id": user.id},
            {
                "$set": {
                    "username": user.username,
                    "email": user.email,
                    "enabled": user.enabled,
                    "role": user.role,
                    "password_hash": user.password_hash,
                    "updated_at": user.updated_at.isoformat(),
                }
            },
        )

    async def delete_user(self, user_id: str) -> None:
        # Rust's Mongo backend has no FK to a `users` row, so (unlike
        # SqlStorage) it never revokes/unlinks the user's tokens first —
        # ported verbatim per research-mongo-backend.md's storage_methods.
        await self.users.delete_one({"id": user_id})

    async def set_user_enabled(self, user_id: str, enabled: bool) -> None:
        await self.users.update_one(
            {"id": user_id}, {"$set": {"enabled": enabled, "updated_at": _now_iso()}}
        )

    async def set_user_role(self, user_id: str, role: str) -> None:
        await self.users.update_one(
            {"id": user_id}, {"$set": {"role": role, "updated_at": _now_iso()}}
        )

    async def set_user_password_hash(self, user_id: str, password_hash: str) -> None:
        await self.users.update_one(
            {"id": user_id},
            {"$set": {"password_hash": password_hash, "updated_at": _now_iso()}},
        )

    # --- Tokens ---

    async def save_token(self, token: Token) -> None:
        await self._insert(
            self.tokens, _to_doc(token, omit_when_none=("refresh_token", "token_family"))
        )

    async def get_token_by_access_token(self, access_token: str) -> Token | None:
        doc = await self.tokens.find_one({"access_token": access_token})
        return _from_doc(Token, doc)

    async def get_token_by_refresh_token(self, refresh_token: str) -> Token | None:
        doc = await self.tokens.find_one({"refresh_token": refresh_token})
        return _from_doc(Token, doc)

    async def get_token_by_id(self, token_id: str) -> Token | None:
        doc = await self.tokens.find_one({"id": token_id})
        return _from_doc(Token, doc)

    async def revoke_token(self, token: str) -> None:
        await self.tokens.update_many(
            {"$or": [{"access_token": token}, {"refresh_token": token}]},
            {"$set": {"revoked": True}},
        )

    async def revoke_token_family(self, family: str) -> int:
        result = await self.tokens.update_many(
            {"token_family": family}, {"$set": {"revoked": True}}
        )
        return result.modified_count

    async def revoke_tokens_by_user_id(self, user_id: str) -> int:
        result = await self.tokens.update_many(
            {"user_id": user_id, "revoked": False}, {"$set": {"revoked": True}}
        )
        return result.modified_count

    async def revoke_tokens_by_client_id(self, client_id: str) -> int:
        result = await self.tokens.update_many(
            {"client_id": client_id, "revoked": False}, {"$set": {"revoked": True}}
        )
        return result.modified_count

    # --- Authorization codes ---

    async def save_authorization_code(self, code: AuthorizationCode) -> None:
        await self._insert(
            self.authorization_codes,
            _to_doc(
                code,
                omit_when_none=(
                    "code_challenge",
                    "code_challenge_method",
                    "nonce",
                    "resource",
                    "authorization_details",
                    "claims_request",
                    "token_family",
                ),
            ),
        )

    async def get_authorization_code(self, code: str) -> AuthorizationCode | None:
        doc = await self.authorization_codes.find_one({"code": code})
        return _from_doc(AuthorizationCode, doc)

    async def mark_authorization_code_used(self, code: str) -> int:
        # Atomic single-claim (divergence 30) — Rust does a bare
        # `update_one({code}, {$set:{used:true}})` with no `used: false`
        # predicate anywhere in the repo, leaving a check-then-act race in
        # the handler. `find_one_and_update` here closes that race while
        # keeping the same 1-claimed/0-already-used `int` contract as
        # `SqlStorage.mark_authorization_code_used`'s `rowcount`.
        doc = await self.authorization_codes.find_one_and_update(
            {"code": code, "used": False},
            {"$set": {"used": True}},
            return_document=ReturnDocument.BEFORE,
        )
        return 1 if doc is not None else 0

    # --- Device authorizations (RFC 8628) ---

    async def save_device_authorization(self, d: DeviceAuthorization) -> None:
        await self._insert(self.device_authorizations, _to_doc(d))

    async def get_device_authorization_by_device_code(
        self, device_code: str
    ) -> DeviceAuthorization | None:
        doc = await self.device_authorizations.find_one({"device_code": device_code})
        return _from_doc(DeviceAuthorization, doc)

    async def get_device_authorization_by_user_code(
        self, user_code: str
    ) -> DeviceAuthorization | None:
        doc = await self.device_authorizations.find_one({"user_code": user_code})
        return _from_doc(DeviceAuthorization, doc)

    async def approve_device_authorization(self, user_code: str, user_id: str) -> None:
        await self.device_authorizations.update_one(
            {"user_code": user_code},
            {"$set": {"approved": True, "denied": False, "user_id": user_id}},
        )

    async def deny_device_authorization(self, user_code: str) -> None:
        await self.device_authorizations.update_one(
            {"user_code": user_code}, {"$set": {"denied": True, "approved": False}}
        )

    async def mark_device_authorization_used(self, device_code: str) -> int:
        # Same atomic single-claim treatment as mark_authorization_code_used.
        doc = await self.device_authorizations.find_one_and_update(
            {"device_code": device_code, "used": False},
            {"$set": {"used": True}},
            return_document=ReturnDocument.BEFORE,
        )
        return 1 if doc is not None else 0

    async def expire_device_authorization(self, device_code: str) -> None:
        # Deliberately an RFC 3339 STRING (not a BSON date) to match the
        # encoding `insert_one` used — mixing encodings on the same field is
        # what caused the upstream mixed-encoding deserialization bug.
        now_minus_1s = datetime.now(timezone.utc) - timedelta(seconds=1)
        await self.device_authorizations.update_one(
            {"device_code": device_code}, {"$set": {"expires_at": now_minus_1s.isoformat()}}
        )
