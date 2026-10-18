"""Conformance test mode: the SUT (system under test) interface of the
`ianlintner/oauth2-conformance` contract (v0.1, `contract/sut-interface.md`).

The mode is **off by default**. It is switched on only by
`OAUTH2_CONFORMANCE_MODE=1` together with `OAUTH2_CONFORMANCE_SEED=<file>`,
and every failure while it is on aborts startup (fail closed): an invalid
seed, an unsupported signing algorithm, or a configuration that looks like
production. There is no partial seed and no warn-and-continue path.

What the mode does:

* loads and validates the seed file (YAML or JSON; mirrors
  `schemas/seed.schema.json` including `additionalProperties: false`),
* checks the process is not in a production profile (`check_not_production`),
* seeds clients and users into the (process-local, in-memory) store, so the
  ordinary `/auth/login` form + `/oauth/authorize` drive the flow
  non-interactively,
* provisions the seeded signing key IDs, and
* lets `/ready` report that the seed was applied.

Nothing here changes protocol behavior: redirect validation, PKCE, `iss`,
and error handling are the normal code paths. This server grants consent to
every authenticated authorization request (there is no consent screen), so
`auto_approve_clients` is validated but needs no further handling.

Mirrors `rust-oauth2-server/crates/oauth2-server/src/conformance.rs`.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Hashable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from sqlalchemy.engine import make_url

from oauth2_server.config import Config
from oauth2_server.keys import KeySet, SigningKey, generate_signing_key
from oauth2_server.models import Client, User
from oauth2_server.security import hash_password_async
from oauth2_server.storage.base import Storage

MODE_ENV = "OAUTH2_CONFORMANCE_MODE"
SEED_ENV = "OAUTH2_CONFORMANCE_SEED"

# Environment-name variables inspected by the production guard.
PROFILE_ENV_VARS = (
    "OAUTH2_ENV",
    "OAUTH2_ENVIRONMENT",
    "OAUTH2_PROFILE",
    "APP_ENV",
    "ENVIRONMENT",
    "RUST_ENV",
)

# Environment names under which conformance mode may run. Any other value of
# a profile variable (production, staging, a typo, ...) aborts startup: the
# guard is an allowlist so an unknown name fails closed.
NON_PRODUCTION_ENV_NAMES = (
    "test",
    "testing",
    "conformance",
    "dev",
    "development",
    "local",
    "ci",
)

DEFAULT_CLIENT_SCOPE = "openid read"
DEFAULT_GRANT_TYPES = ("authorization_code",)
GRANT_TYPES = (
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
)
AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post")
# Algorithms this server can provision. Other well-formed schema values
# (ES256, PS256, ...) are refused rather than silently skipped.
SUPPORTED_SEED_ALGS = ("HS256", "RS256")


class ConformanceError(Exception):
    """Abort-worthy conformance-mode failure (fail closed).

    A startup error, never an HTTP response body, so deliberately outside the
    OAuth error hierarchy.
    """


# ── Seed model (schemas/seed.schema.json) ────────────────────────────────────


@dataclass
class SeedSigningKey:
    kid: str
    alg: str
    use: str = "sig"


@dataclass
class SeedClient:
    client_id: str
    redirect_uris: list[str]
    name: str | None = None
    client_secret: str | None = None
    token_endpoint_auth_method: str | None = None
    public: bool | None = None
    scopes: list[str] | None = None
    grant_types: list[str] | None = None

    def is_public(self) -> bool:
        return self.public is True or self.token_endpoint_auth_method == "none"


@dataclass
class SeedUser:
    username: str
    password: str
    email: str | None = None
    # Accepted for schema compatibility; not enforced by the v0.1 contract.
    scopes: list[str] | None = None
    auto_approve_clients: list[str] | None = None


@dataclass
class Seed:
    issuer: str
    clients: list[SeedClient]
    users: list[SeedUser]
    signing_keys: list[SeedSigningKey] = field(default_factory=list)

    def __repr__(self) -> str:
        # Lands in tracebacks: never leak seeded credentials.
        return (
            f"Seed(issuer={self.issuer!r}, "
            f"clients={[c.client_id for c in self.clients]!r}, "
            f"users={[u.username for u in self.users]!r}, "
            f"signing_keys={[k.kid for k in self.signing_keys]!r})"
        )

    @classmethod
    def load(cls, path: Path) -> Seed:
        """Read and parse the seed at `path`. Any failure is an error; there
        is no default seed."""
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConformanceError(f"cannot read seed file {path}: {exc}") from exc
        try:
            return cls.parse(text)
        except ConformanceError as exc:
            raise ConformanceError(f"{path}: {exc}") from exc

    @classmethod
    def parse(cls, text: str) -> Seed:
        """Parse and validate seed text (JSON first, then YAML)."""
        raw = _load_document(text)
        if not isinstance(raw, dict):
            raise ConformanceError("seed is not a mapping")
        seed = _build_seed(raw)
        _validate_seed(seed)
        return seed


# ── Parsing ───────────────────────────────────────────────────────────────────


class _StrictYamlLoader(yaml.SafeLoader):
    """`safe_load` that refuses what the seed schema cannot express:
    duplicate mapping keys (silent last-wins would make a seed ambiguous) and
    anchors/aliases."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ConformanceError("YAML aliases are not supported in a seed")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        seen: set[Hashable] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if isinstance(key, Hashable):
                if key in seen:
                    raise ConformanceError(f"duplicate key {key!r}")
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ConformanceError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _load_document(text: str) -> object:
    if not text.strip():
        raise ConformanceError("seed file is empty")
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError:
        pass
    try:
        doc = yaml.load(text, Loader=_StrictYamlLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise ConformanceError(f"seed is neither valid JSON nor YAML: {exc}") from exc
    if doc is None:
        raise ConformanceError("seed file is empty")
    return doc


def _mapping(obj: object, where: str) -> dict:
    if not isinstance(obj, dict):
        raise ConformanceError(f"{where}: expected a mapping, got {type(obj).__name__}")
    return obj


def _check_keys(obj: dict, allowed: set[str], required: set[str], where: str) -> None:
    unknown = sorted(str(k) for k in obj if k not in allowed)
    if unknown:
        raise ConformanceError(f"{where}: unknown field(s) {', '.join(unknown)}")
    for key in sorted(required):
        if key not in obj:
            raise ConformanceError(f"{where}: missing required key {key!r}")


def _string(obj: dict, key: str, where: str) -> str | None:
    value = obj.get(key)
    if value is not None and not isinstance(value, str):
        raise ConformanceError(f"{where}: {key} must be a string")
    return value


def _string_list(obj: dict, key: str, where: str) -> list[str] | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConformanceError(f"{where}: {key} must be a list of strings")
    return value


def _list_of_mappings(obj: dict, key: str) -> list[dict]:
    value = obj.get(key)
    if not isinstance(value, list):
        raise ConformanceError(f"seed: {key} must be a list")
    return [_mapping(item, f"{key}[]") for item in value]


def _build_seed(obj: dict) -> Seed:
    _check_keys(
        obj, {"issuer", "signingKeys", "clients", "users"}, {"issuer", "clients", "users"}, "seed"
    )
    issuer = _string(obj, "issuer", "seed")
    assert issuer is not None  # required key, checked above
    keys = _list_of_mappings(obj, "signingKeys") if obj.get("signingKeys") is not None else []
    return Seed(
        issuer=issuer,
        signing_keys=[_build_signing_key(k) for k in keys],
        clients=[_build_client(c) for c in _list_of_mappings(obj, "clients")],
        users=[_build_user(u) for u in _list_of_mappings(obj, "users")],
    )


def _build_signing_key(obj: dict) -> SeedSigningKey:
    where = "signingKeys[]"
    _check_keys(obj, {"kid", "alg", "use"}, {"kid", "alg"}, where)
    return SeedSigningKey(
        kid=_string(obj, "kid", where) or "",
        alg=_string(obj, "alg", where) or "",
        use=_string(obj, "use", where) or "sig",
    )


def _build_client(obj: dict) -> SeedClient:
    where = "clients[]"
    _check_keys(
        obj,
        {
            "client_id",
            "name",
            "client_secret",
            "token_endpoint_auth_method",
            "public",
            "redirect_uris",
            "scopes",
            "grant_types",
        },
        {"client_id", "redirect_uris"},
        where,
    )
    public = obj.get("public")
    if public is not None and not isinstance(public, bool):
        raise ConformanceError(f"{where}: public must be a boolean")
    return SeedClient(
        client_id=_string(obj, "client_id", where) or "",
        redirect_uris=_string_list(obj, "redirect_uris", where) or [],
        name=_string(obj, "name", where),
        client_secret=_string(obj, "client_secret", where),
        token_endpoint_auth_method=_string(obj, "token_endpoint_auth_method", where),
        public=public,
        scopes=_string_list(obj, "scopes", where),
        grant_types=_string_list(obj, "grant_types", where),
    )


def _build_user(obj: dict) -> SeedUser:
    where = "users[]"
    _check_keys(
        obj,
        {"username", "password", "email", "scopes", "auto_approve_clients"},
        {"username", "password"},
        where,
    )
    return SeedUser(
        username=_string(obj, "username", where) or "",
        password=_string(obj, "password", where) or "",
        email=_string(obj, "email", where),
        scopes=_string_list(obj, "scopes", where),
        auto_approve_clients=_string_list(obj, "auto_approve_clients", where),
    )


# ── Validation (the parts of the schema beyond shape) ─────────────────────────


def _nonempty(what: str, value: str) -> None:
    if not value:
        raise ConformanceError(f"{what} must not be empty")


def _well_formed_alg(alg: str) -> bool:
    return (
        len(alg) == 5
        and alg[:2] in ("RS", "ES", "PS", "HS")
        and alg[2:].isascii()
        and alg[2:].isdigit()
    )


def _validate_seed(seed: Seed) -> None:
    split = urlsplit(seed.issuer)
    if split.scheme not in ("http", "https"):
        raise ConformanceError(f"issuer {seed.issuer!r} must be an http(s) URL")
    if not split.netloc:
        raise ConformanceError(f"issuer {seed.issuer!r} must have a host")
    if seed.issuer.endswith("/"):
        # The server normalizes a trailing slash away; the contract forbids
        # that normalization, so an issuer it cannot honor verbatim is refused.
        raise ConformanceError("issuer must not end with '/'")
    if not seed.clients:
        raise ConformanceError("clients must contain at least one client")
    if not seed.users:
        raise ConformanceError("users must contain at least one user")

    kids: set[str] = set()
    for key in seed.signing_keys:
        _nonempty("signingKeys[].kid", key.kid)
        if key.kid in kids:
            raise ConformanceError(f"duplicate signing key kid {key.kid!r}")
        kids.add(key.kid)
        if key.use != "sig":
            raise ConformanceError(f'signing key {key.kid!r}: use must be "sig"')
        if not _well_formed_alg(key.alg):
            raise ConformanceError(
                f"signing key {key.kid!r}: alg {key.alg!r} is not RS/ES/PS/HS + 3 digits"
            )
        if key.alg not in SUPPORTED_SEED_ALGS:
            raise ConformanceError(
                f"signing key {key.kid!r}: alg {key.alg} is not supported by this server "
                f"({', '.join(SUPPORTED_SEED_ALGS)})"
            )

    client_ids: set[str] = set()
    for client in seed.clients:
        _nonempty("clients[].client_id", client.client_id)
        if client.client_id in client_ids:
            raise ConformanceError(f"duplicate client_id {client.client_id!r}")
        client_ids.add(client.client_id)
        _validate_client(client)

    usernames: set[str] = set()
    for user in seed.users:
        _nonempty("users[].username", user.username)
        _nonempty(f"user {user.username!r} password", user.password)
        if user.username in usernames:
            raise ConformanceError(f"duplicate username {user.username!r}")
        usernames.add(user.username)
        if user.email is not None and len(user.email) < 3:
            raise ConformanceError(f"user {user.username!r}: email is too short")
        # This server consents implicitly, so the list needs no handling, but
        # a dangling reference means the seed is wrong: refuse it.
        for approved in user.auto_approve_clients or []:
            if approved not in client_ids:
                raise ConformanceError(
                    f"user {user.username!r}: auto_approve_clients names unknown client {approved!r}"
                )


def _validate_redirect_uri(cid: str, uri: str) -> None:
    split = urlsplit(uri)
    # http(s), or an RFC 8252 private-use scheme such as `com.example.app:/cb`.
    has_scheme = bool(split.scheme)
    private_use = has_scheme and split.scheme not in ("http", "https") and bool(split.path)
    web = split.scheme in ("http", "https") and bool(split.netloc)
    if not (web or private_use):
        raise ConformanceError(f"client {cid!r}: redirect_uri {uri!r} is invalid")
    if split.fragment:
        raise ConformanceError(f"client {cid!r}: redirect_uri {uri!r} has a fragment")


def _validate_client(client: SeedClient) -> None:
    cid = client.client_id
    if client.name == "":
        raise ConformanceError(f"client {cid!r}: name must not be empty")
    method = client.token_endpoint_auth_method
    if method is not None and method not in AUTH_METHODS:
        raise ConformanceError(
            f"client {cid!r}: token_endpoint_auth_method {method!r} is not supported"
        )
    if client.client_secret == "":
        raise ConformanceError(f"client {cid!r}: client_secret must not be empty")

    if client.is_public():
        if client.client_secret is not None:
            raise ConformanceError(f"client {cid!r}: a public client must not carry a secret")
        if method is not None and method != "none":
            raise ConformanceError(f"client {cid!r}: a public client must use method none")
    elif client.client_secret is None:
        raise ConformanceError(
            f"client {cid!r}: a confidential client needs client_secret (or set public: true)"
        )

    if not client.redirect_uris:
        raise ConformanceError(f"client {cid!r}: redirect_uris must not be empty")
    for uri in client.redirect_uris:
        _validate_redirect_uri(cid, uri)
    for scope in client.scopes or []:
        if not scope or any(ch.isspace() for ch in scope):
            raise ConformanceError(f"client {cid!r}: invalid scope {scope!r}")
    for grant in client.grant_types or []:
        if grant not in GRANT_TYPES:
            raise ConformanceError(f"client {cid!r}: unsupported grant type {grant!r}")


# ── Mode switch and production guard ──────────────────────────────────────────


def mode_from_env(env: Mapping[str, str]) -> Path | None:
    """Decide whether conformance mode is on.

    Returns the seed path when on. An ambiguous `OAUTH2_CONFORMANCE_MODE`
    value or a missing seed path is an error (fail closed). A seed path
    without the mode switch is ignored: with the mode off nothing is exposed.
    """
    mode = env.get(MODE_ENV, "").strip().lower()
    if mode in ("", "0", "false"):
        return None
    if mode not in ("1", "true"):
        raise ConformanceError(
            f"{MODE_ENV}={mode!r} is not a recognized value; use 1 to enable or unset it"
        )
    path = env.get(SEED_ENV, "").strip()
    if not path:
        raise ConformanceError(f"{MODE_ENV}=1 requires {SEED_ENV} to point at a seed file")
    return Path(path)


def _is_in_memory_sqlite(database_url: str) -> bool:
    try:
        url = make_url(database_url)
    except Exception:
        return False
    return url.get_backend_name() == "sqlite" and (
        url.database in (None, "", ":memory:") or "mode=memory" in url.query
    )


def check_not_production(env: Mapping[str, str], config: Config) -> None:
    """Refuse to run conformance mode under a production-like configuration.

    Aborts when a profile variable (`OAUTH2_ENV`, `APP_ENV`, ...) names
    anything other than a known non-production environment, when the database
    is not process-local in-memory SQLite (seed data must never reach a shared
    or production store), or when a real signing key is configured.
    """
    for var in PROFILE_ENV_VARS:
        value = env.get(var)
        if value is None:
            continue
        name = value.strip().lower()
        if name and name not in NON_PRODUCTION_ENV_NAMES:
            raise ConformanceError(
                f"conformance mode refused: {var}={value!r} is not a known non-production "
                f"environment (allowed: {', '.join(NON_PRODUCTION_ENV_NAMES)})"
            )
    if not _is_in_memory_sqlite(config.database_url):
        raise ConformanceError(
            "conformance mode refused: it requires an in-memory database "
            "(OAUTH2_DATABASE_URL=sqlite+aiosqlite://) so seeded test credentials are "
            "never persisted to a shared or production store"
        )
    if config.id_token_private_key_pem:
        raise ConformanceError(
            "conformance mode refused: a real signing key is configured; the mode "
            "generates its own throwaway keys under the seeded kid"
        )


def seed_from_env(env: Mapping[str, str], config: Config) -> Seed | None:
    """The one entry point used at startup: `None` when the mode is off,
    otherwise the validated seed. Every failure is a `ConformanceError`."""
    path = mode_from_env(env)
    if path is None:
        return None
    check_not_production(env, config)
    return Seed.load(path)


# ── Applying the seed ─────────────────────────────────────────────────────────


@dataclass
class Applied:
    clients: int
    users: int
    signing_keys: list[SigningKey]

    def readiness(self) -> dict:
        """Public readiness detail: counts and key ids, never credentials or
        key material."""
        return {
            "seed_applied": True,
            "clients": self.clients,
            "users": self.users,
            "signing_key_ids": [k.kid for k in self.signing_keys],
        }


async def apply_seed(seed: Seed, storage: Storage, keyset: KeySet) -> Applied:
    """Apply `seed` to `storage` and provision its signing keys into `keyset`.

    The first failure raises `ConformanceError` (the caller must not start
    serving). Key material is generated here and never read from the seed.
    A client or user that already exists is a conflict, never a silent merge.
    """
    now = datetime.now(UTC)
    signing_keys = [generate_signing_key(spec.alg, spec.kid) for spec in seed.signing_keys]

    for seeded in seed.clients:
        public = seeded.is_public()
        if await storage.get_client(seeded.client_id) is not None:
            raise ConformanceError(f"seeding client {seeded.client_id!r} failed: already exists")
        client = Client(
            id=uuid.uuid4().hex,
            client_id=seeded.client_id,
            client_secret=seeded.client_secret or "",
            redirect_uris=json.dumps(seeded.redirect_uris),
            grant_types=json.dumps(seeded.grant_types or list(DEFAULT_GRANT_TYPES)),
            scope=" ".join(seeded.scopes) if seeded.scopes else DEFAULT_CLIENT_SCOPE,
            name=seeded.name or seeded.client_id,
            created_at=now,
            updated_at=now,
            token_endpoint_auth_method=(
                "none" if public else seeded.token_endpoint_auth_method or "client_secret_basic"
            ),
        )
        await storage.save_client(client)

    for seeded_user in seed.users:
        if await storage.get_user_by_username(seeded_user.username) is not None:
            raise ConformanceError(f"seeding user {seeded_user.username!r} failed: already exists")
        await storage.save_user(
            User(
                id=uuid.uuid4().hex,
                username=seeded_user.username,
                password_hash=await hash_password_async(seeded_user.password),
                email=seeded_user.email or f"{seeded_user.username}@conformance.invalid",
            )
        )

    # Each seeded key becomes the current key for its algorithm; the previous
    # current key stops being active immediately so the seeded kid is what is
    # published and used.
    for key in signing_keys:
        keyset.rotate(key, grace_secs=0)

    return Applied(clients=len(seed.clients), users=len(seed.users), signing_keys=signing_keys)
