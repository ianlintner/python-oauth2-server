"""Conformance test mode: the SUT interface of the `oauth2-conformance` contract
(v0.1, `contract/sut-interface.md`).

Covers the mode switch, the fail-closed production guard, seed validation
(mirroring `schemas/seed.schema.json`), seed application, and the end-to-end
non-interactive login -> authorize flow through the real `build()` factory.
"""

import re
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from httpx import ASGITransport, AsyncClient

from oauth2_server import conformance
from oauth2_server.app import build, create_app
from oauth2_server.config import Config
from oauth2_server.conformance import ConformanceError, Seed
from oauth2_server.keys import KeySet
from tests.helpers import PKCE_CHALLENGE, make_storage

VALID = """
issuer: http://localhost:8080
clients:
  - client_id: client-a
    client_secret: test-only-secret
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: [https://client.example/callback]
    grant_types: [authorization_code, refresh_token]
  - client_id: pub
    public: true
    token_endpoint_auth_method: none
    redirect_uris: [http://127.0.0.1/cb]
users:
  - username: alice
    password: test-only-password
    auto_approve_clients: [client-a]
"""

SECRET = "unit-test-secret-not-for-production-0123456789abcdef"


def _config(**overrides) -> Config:
    return Config(jwt_secret=SECRET, **overrides)


# -- mode switch ------------------------------------------------------------


def test_mode_is_off_by_default_and_for_explicit_zero():
    assert conformance.mode_from_env({}) is None
    for off in ("0", "false", "FALSE", "", "  "):
        assert conformance.mode_from_env({conformance.MODE_ENV: off}) is None


def test_seed_path_alone_never_turns_the_mode_on():
    assert conformance.mode_from_env({conformance.SEED_ENV: "/x.yaml"}) is None


def test_mode_on_requires_a_seed_path():
    env = {conformance.MODE_ENV: "1", conformance.SEED_ENV: "/s.yaml"}
    assert str(conformance.mode_from_env(env)) == "/s.yaml"
    assert conformance.mode_from_env({**env, conformance.MODE_ENV: "TRUE"}) is not None
    with pytest.raises(ConformanceError, match="requires"):
        conformance.mode_from_env({conformance.MODE_ENV: "1"})
    with pytest.raises(ConformanceError, match="requires"):
        conformance.mode_from_env({conformance.MODE_ENV: "1", conformance.SEED_ENV: "  "})


@pytest.mark.parametrize("value", ["yes", "on", "2", "enabled"])
def test_mode_rejects_ambiguous_values(value):
    env = {conformance.MODE_ENV: value, conformance.SEED_ENV: "/s.yaml"}
    with pytest.raises(ConformanceError, match="not a recognized value"):
        conformance.mode_from_env(env)


# -- production guard -------------------------------------------------------


@pytest.mark.parametrize("name", ["test", "CI", "conformance", " Dev ", "local", "development"])
def test_guard_allows_unset_and_known_test_environments(name):
    conformance.check_not_production({}, _config())
    for var in conformance.PROFILE_ENV_VARS:
        conformance.check_not_production({var: name}, _config())


@pytest.mark.parametrize("var", conformance.PROFILE_ENV_VARS)
@pytest.mark.parametrize("name", ["production", "prod", "staging", "live", "typo-env"])
def test_guard_rejects_production_and_unknown_environment_names(var, name):
    with pytest.raises(ConformanceError, match=var):
        conformance.check_not_production({var: name}, _config())


@pytest.mark.parametrize(
    "url",
    [
        "sqlite+aiosqlite:///var/lib/oauth2.db",
        "sqlite+aiosqlite:///oauth2.db",
        "postgresql+asyncpg://u:p@db/oauth2",
        "mongodb://localhost/oauth2",
        "mongodb+srv://u:p@cluster.example/oauth2",
        "",
        "not a url",
    ],
)
def test_guard_rejects_persistent_or_shared_databases(url):
    with pytest.raises(ConformanceError, match="in-memory"):
        conformance.check_not_production({}, _config(database_url=url))


@pytest.mark.parametrize(
    "url",
    ["sqlite+aiosqlite://", "sqlite+aiosqlite:///:memory:", "sqlite://", "sqlite:///:memory:"],
)
def test_guard_allows_process_local_in_memory_sqlite(url):
    conformance.check_not_production({}, _config(database_url=url))


@pytest.mark.parametrize(
    "var", ["NODE_ENV", "FLASK_ENV", "ASPNETCORE_ENVIRONMENT", "RAILS_ENV", "DEPLOY_ENV"]
)
def test_guard_covers_common_framework_environment_variables(var):
    assert var in conformance.PROFILE_ENV_VARS
    with pytest.raises(ConformanceError, match=var):
        conformance.check_not_production({var: "production"}, _config())


@pytest.mark.parametrize(
    "url",
    [
        "sqlite+aiosqlite:///file:x?mode=memory&cache=shared&uri=true",
        "sqlite+aiosqlite:///file:x?cache=shared&uri=true",
        "sqlite+aiosqlite:///conformance.db",
    ],
)
def test_guard_rejects_file_backed_and_shared_cache_sqlite(url):
    with pytest.raises(ConformanceError, match="in-memory"):
        conformance.check_not_production({}, _config(database_url=url))


def test_guard_rejects_a_configured_signing_key():
    # A real RS256 key means production-grade signing material is configured;
    # conformance mode generates its own throwaway keys instead.
    config = _config(id_token_private_key_pem="-----BEGIN PRIVATE KEY-----\nx\n", id_token_kid="k")
    with pytest.raises(ConformanceError, match="signing key"):
        conformance.check_not_production({}, config)


# -- seed parsing / validation ----------------------------------------------


def test_parses_the_contract_example_shape():
    seed = Seed.parse(VALID)
    assert seed.issuer == "http://localhost:8080"
    assert [c.client_id for c in seed.clients] == ["client-a", "pub"]
    assert seed.clients[1].is_public()
    assert not seed.clients[0].is_public()
    assert seed.users[0].username == "alice"


def test_parses_json_seeds():
    text = (
        '{"issuer":"http://localhost:8080","clients":[{"client_id":"c","client_secret":"s",'
        '"redirect_uris":["https://c.example/cb"]}],"users":[{"username":"u","password":"p"}]}'
    )
    assert Seed.parse(text).clients[0].client_id == "c"


def test_load_fails_for_missing_file(tmp_path):
    with pytest.raises(ConformanceError, match="cannot read seed file"):
        Seed.load(tmp_path / "nope.yaml")


def _rejects(text: str, needle: str) -> None:
    with pytest.raises(ConformanceError) as excinfo:
        Seed.parse(text)
    assert needle in str(excinfo.value), str(excinfo.value)


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("", "empty"),
        ("a: [", "neither valid JSON nor YAML"),
        ("- 1\n- 2\n", "mapping"),
        ("issuer: http://x\nclients: []\nusers: []\n", "clients"),
        (VALID + "extra: 1\n", "extra"),
        (VALID.replace("client_id: client-a", "client_id: client-a\n    bogus: 1"), "bogus"),
        ("clients: []\nusers: []\n", "issuer"),
        (VALID.replace("http://localhost:8080", "ftp://x"), "http(s)"),
        (VALID.replace("http://localhost:8080", "http://x/"), "end with '/'"),
        (VALID.replace("http://localhost:8080", "not a url"), "http(s)"),
        (VALID.replace("http://localhost:8080", "http://"), "host"),
        # duplicate mapping keys must not be silently last-wins
        (VALID + "issuer: http://other\n", "duplicate key"),
        # a YAML anchor/alias is not part of the seed schema
        ("issuer: &a http://x\nclients: *a\nusers: *a\n", "alias"),
    ],
)
def test_rejects_schema_violations(text, needle):
    _rejects(text, needle)


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        (
            "issuer: http://x\nclients:\n  - client_id: c\n    redirect_uris: [https://c/cb]\n"
            "users:\n  - {username: u, password: p}\n",
            "client_secret",
        ),
        (VALID.replace("public: true", "public: true\n    client_secret: nope"), "public"),
        (
            VALID.replace(
                "token_endpoint_auth_method: none", "token_endpoint_auth_method: client_secret_post"
            ),
            "method none",
        ),
        (VALID.replace("client_secret_basic", "private_key_jwt"), "token_endpoint_auth_method"),
        (
            VALID.replace(
                "grant_types: [authorization_code, refresh_token]", "grant_types: [implicit]"
            ),
            "unsupported grant type",
        ),
        (VALID.replace("https://client.example/callback", "https://c/cb#frag"), "fragment"),
        (VALID.replace("https://client.example/callback", "not-a-uri"), "redirect_uri"),
        (VALID.replace("https://client.example/callback", "javascript:alert(1)"), "redirect_uri"),
        (VALID.replace("https://client.example/callback", "data:text/html,x"), "redirect_uri"),
        (
            VALID.replace("redirect_uris: [https://client.example/callback]", "redirect_uris: []"),
            "redirect_uris",
        ),
        (VALID.replace("client_id: client-a", "client_id: ''"), "client_id"),
        (VALID.replace("client_secret: test-only-secret", "client_secret: ''"), "client_secret"),
        (VALID.replace("client_id: client-a", "client_id: client-a\n    name: ''"), "name"),
        (VALID.replace("client_id: client-a", "client_id: client-a\n    scopes: ['a b']"), "scope"),
    ],
)
def test_rejects_inconsistent_clients(text, needle):
    _rejects(text, needle)


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        (VALID.replace("client_id: pub", "client_id: client-a"), "duplicate client_id"),
        (VALID + "  - username: alice\n    password: x\n", "duplicate username"),
        (
            VALID.replace("auto_approve_clients: [client-a]", "auto_approve_clients: [ghost]"),
            "unknown client",
        ),
        (VALID.replace("password: test-only-password", "password: ''"), "password"),
        (VALID.replace("username: alice", "username: alice\n    email: ab"), "email"),
    ],
)
def test_rejects_duplicates_dangling_references_and_bad_users(text, needle):
    _rejects(text, needle)


def test_validates_signing_keys():
    def with_keys(keys: str) -> str:
        return f"{VALID}signingKeys:\n{keys}"

    assert Seed.parse(with_keys("  - {kid: k1, alg: RS256, use: sig}\n  - {kid: k2, alg: HS256}\n"))
    _rejects(with_keys("  - {kid: k1, alg: RS256}\n  - {kid: k1, alg: HS256}\n"), "duplicate")
    _rejects(with_keys("  - {kid: k1, alg: bogus}\n"), "alg")
    # well-formed per schema but not implemented here: refuse, never skip
    _rejects(with_keys("  - {kid: k1, alg: ES256}\n"), "not supported")
    _rejects(with_keys("  - {kid: k1, alg: RS256, use: enc}\n"), "use")
    _rejects(with_keys("  - {kid: '', alg: RS256}\n"), "kid")


def test_non_ascii_signing_alg_is_rejected():
    _rejects(f'{VALID}signingKeys:\n  - kid: k1\n    alg: "R\u00e9S2"\n', "alg")


# -- applying the seed -------------------------------------------------------


async def test_apply_seeds_clients_users_and_keys():
    storage = await make_storage()
    keyset = KeySet()
    seed = Seed.parse(
        f"{VALID}signingKeys:\n  - {{kid: seed-rs, alg: RS256}}\n  - {{kid: seed-hs, alg: HS256}}\n"
    )
    applied = await conformance.apply_seed(seed, storage, keyset)
    assert (applied.clients, applied.users) == (2, 1)

    confidential = await storage.get_client("client-a")
    assert confidential.client_secret == "test-only-secret"
    assert confidential.token_endpoint_auth_method == "client_secret_basic"
    assert confidential.scope == "openid read"
    assert confidential.grant_type_list() == ["authorization_code", "refresh_token"]
    assert confidential.redirect_uri_list() == ["https://client.example/callback"]
    public = await storage.get_client("pub")
    assert public.is_public()
    assert public.client_secret == ""
    assert public.grant_type_list() == ["authorization_code"]

    user = await storage.get_user_by_username("alice")
    assert user.password_hash != "test-only-password"
    assert user.password_hash.startswith("$argon2")
    assert user.email == "alice@conformance.invalid"
    assert user.role == "user"
    # Only seeded identities exist: no default admin.
    assert await storage.get_user_by_username("admin") is None

    assert [k.kid for k in applied.signing_keys] == ["seed-rs", "seed-hs"]
    assert keyset.current_for_alg("RS256").kid == "seed-rs"
    assert keyset.current_for_alg("HS256").kid == "seed-hs"
    assert applied.readiness() == {
        "seed_applied": True,
        "clients": 2,
        "users": 1,
        "signing_key_ids": ["seed-rs", "seed-hs"],
    }


async def test_apply_scopes_override_the_default_client_scope():
    storage = await make_storage()
    seed = Seed.parse(
        VALID.replace("client_id: client-a", "client_id: client-a\n    scopes: [read, profile]")
    )
    await conformance.apply_seed(seed, storage, KeySet())
    assert (await storage.get_client("client-a")).scope == "read profile"


async def test_apply_aborts_on_conflicting_existing_state():
    storage = await make_storage()
    seed = Seed.parse(VALID)
    await conformance.apply_seed(seed, storage, KeySet())
    # Re-applying onto a non-fresh store must fail, never merge silently.
    with pytest.raises(ConformanceError, match="already exists"):
        await conformance.apply_seed(seed, storage, KeySet())


async def test_apply_seeded_key_replaces_the_default_current_key():
    from oauth2_server.keys import seed_keyset

    keyset = seed_keyset(_config())
    assert keyset.current_for_alg("HS256").kid == "hs256-initial"
    seed = Seed.parse(f"{VALID}signingKeys:\n  - {{kid: seed-hs, alg: HS256}}\n")
    await conformance.apply_seed(seed, await make_storage(), keyset)
    assert keyset.current_for_alg("HS256").kid == "seed-hs"
    assert keyset.find("hs256-initial") is None


# -- startup wiring (the real `build()` factory) ------------------------------


@pytest.fixture
def seed_file(tmp_path):
    path = tmp_path / "seed.yaml"
    path.write_text(VALID + "signingKeys:\n  - {kid: seed-rs, alg: RS256}\n", encoding="utf-8")
    return path


@pytest.fixture
def conformance_env(monkeypatch, seed_file):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", SECRET)
    monkeypatch.setenv("OAUTH2_CONFORMANCE_MODE", "1")
    monkeypatch.setenv("OAUTH2_CONFORMANCE_SEED", str(seed_file))
    monkeypatch.setenv("OAUTH2_ENV", "test")
    monkeypatch.delenv("OAUTH2_DATABASE_URL", raising=False)
    return monkeypatch


async def _started_client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost:8080")


def _session_cookie(response) -> str:
    return response.headers["set-cookie"].split(";", 1)[0]


async def test_build_off_by_default_exposes_nothing(monkeypatch):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", SECRET)
    for var in ("OAUTH2_CONFORMANCE_MODE", "OAUTH2_CONFORMANCE_SEED", "OAUTH2_SEED_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    app = build()
    async with app.router.lifespan_context(app), await _started_client(app) as client:
        ready = await client.get("/ready")
        assert ready.status_code == 200
        assert "conformance" not in ready.json()
        assert not hasattr(app.state, "conformance")


async def test_seed_path_without_mode_is_ignored(monkeypatch, seed_file):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", SECRET)
    monkeypatch.delenv("OAUTH2_CONFORMANCE_MODE", raising=False)
    monkeypatch.setenv("OAUTH2_CONFORMANCE_SEED", str(seed_file))
    app = build()
    async with app.router.lifespan_context(app), await _started_client(app) as client:
        assert "conformance" not in (await client.get("/ready")).json()
        # Seeded credentials are never valid in a normal-mode start.
        resp = await client.post(
            "/auth/login", data={"username": "alice", "password": "test-only-password"}
        )
        assert resp.headers["location"] == "/auth/login?error=invalid_credentials"
        assert await app.state.storage.get_client("client-a") is None


async def test_build_in_conformance_mode_applies_the_seed_before_ready(conformance_env):
    app = build()
    assert app.state.config.issuer == "http://localhost:8080"
    async with app.router.lifespan_context(app), await _started_client(app) as client:
        assert (await client.get("/health")).status_code == 200
        ready = await client.get("/ready")
        assert ready.status_code == 200
        body = ready.json()
        assert body["status"] == "ready"
        assert body["conformance"] == {
            "seed_applied": True,
            "clients": 2,
            "users": 1,
            "signing_key_ids": ["seed-rs"],
        }
        # Counts and key ids only — never credentials or key material.
        assert "test-only" not in ready.text
        assert "PRIVATE" not in ready.text

        discovery = (await client.get("/.well-known/openid-configuration")).json()
        assert discovery["issuer"] == "http://localhost:8080"
        jwks = (await client.get("/.well-known/jwks.json")).json()
        assert [k["kid"] for k in jwks["keys"] if k.get("kty") == "RSA"] == ["seed-rs"]


async def test_non_interactive_login_then_authorize_issues_a_code(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), await _started_client(app) as client:
        params = {
            "response_type": "code",
            "client_id": "client-a",
            "redirect_uri": "https://client.example/callback",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "state": "xyz",
        }
        # 1. unauthenticated -> the SUT's own login step
        first = await client.get("/oauth/authorize", params=params)
        assert first.status_code == 302
        assert first.headers["location"] == "/auth/login"
        cookie = _session_cookie(first)
        # 2. seeded credentials, form-encoded, no browser
        login = await client.post(
            "/auth/login",
            data={"username": "alice", "password": "test-only-password"},
            headers={"cookie": cookie},
        )
        assert login.status_code == 303
        cookie = _session_cookie(login)
        # 3. consent is implicit for seeded clients: straight to the redirect_uri
        final = await client.get("/oauth/authorize", params=params, headers={"cookie": cookie})
        assert final.status_code == 302
        location = urlparse(final.headers["location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == (
            "https://client.example/callback"
        )
        query = parse_qs(location.query)
        assert query["state"] == ["xyz"]
        assert query["iss"] == ["http://localhost:8080"]
        assert "code" in query


async def test_http_seed_issuer_gets_a_cookie_the_runner_can_send_back(conformance_env):
    # The contract's example issuer is plain http://localhost:8080. A `Secure`
    # session cookie would never be returned by the runner over http, so the
    # test login could not work without an unrelated opt-in flag.
    app = build()
    async with app.router.lifespan_context(app), await _started_client(app) as client:
        login = await client.post(
            "/auth/login", data={"username": "alice", "password": "test-only-password"}
        )
        assert login.status_code == 303
        assert "secure" not in login.headers["set-cookie"].lower()


async def test_https_seed_issuer_keeps_the_secure_cookie(conformance_env, tmp_path):
    seed = tmp_path / "https-seed.yaml"
    seed.write_text(VALID.replace("http://localhost:8080", "https://sut.example"), encoding="utf-8")
    conformance_env.setenv("OAUTH2_CONFORMANCE_SEED", str(seed))
    app = build()
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://sut.example"
        ) as client:
            login = await client.post(
                "/auth/login", data={"username": "alice", "password": "test-only-password"}
            )
            assert "secure" in login.headers["set-cookie"].lower()


async def test_normal_mode_cookie_stays_secure_without_the_insecure_flag(monkeypatch):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", SECRET)
    monkeypatch.delenv("OAUTH2_CONFORMANCE_MODE", raising=False)
    monkeypatch.setenv("OAUTH2_SEED_PASSWORD", "admin-password-123")
    app = build()
    async with app.router.lifespan_context(app), await _started_client(app) as client:
        login = await client.post(
            "/auth/login", data={"username": "admin", "password": "admin-password-123"}
        )
        assert "secure" in login.headers["set-cookie"].lower()


async def test_protocol_errors_are_unchanged_by_the_test_login(conformance_env):
    app = build()
    async with app.router.lifespan_context(app), await _started_client(app) as client:
        login = await client.post(
            "/auth/login", data={"username": "alice", "password": "test-only-password"}
        )
        cookie = _session_cookie(login)
        # exact redirect_uri matching still applies: 400, never a redirect
        resp = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "client-a",
                "redirect_uri": "https://evil.example/callback",
                "code_challenge": PKCE_CHALLENGE,
                "code_challenge_method": "S256",
            },
            headers={"cookie": cookie},
        )
        assert resp.status_code == 400
        # PKCE is still mandatory
        resp = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "client-a",
                "redirect_uri": "https://client.example/callback",
            },
            headers={"cookie": cookie},
        )
        assert resp.status_code == 302
        assert parse_qs(urlparse(resp.headers["location"]).query)["error"] == ["invalid_request"]


async def test_only_seeded_users_can_log_in(conformance_env):
    conformance_env.setenv("OAUTH2_SEED_PASSWORD", "admin-password-123")
    app = build()
    async with app.router.lifespan_context(app), await _started_client(app) as client:
        for username, password in (
            ("admin", "admin-password-123"),  # the default admin seed is skipped
            ("mallory", "test-only-password"),
            ("alice", "wrong"),
        ):
            resp = await client.post(
                "/auth/login", data={"username": username, "password": password}
            )
            assert resp.headers["location"] == "/auth/login?error=invalid_credentials"
        assert await app.state.storage.get_user_by_username("admin") is None


async def test_seeded_rs256_key_signs_access_tokens_verifiable_via_jwks(conformance_env, tmp_path):
    seed = tmp_path / "cc-seed.yaml"
    seed.write_text(
        VALID.replace(
            "grant_types: [authorization_code, refresh_token]",
            "grant_types: [client_credentials]",
        )
        + "signingKeys:\n  - {kid: seed-rs, alg: RS256}\n",
        encoding="utf-8",
    )
    conformance_env.setenv("OAUTH2_CONFORMANCE_SEED", str(seed))
    app = build()
    async with app.router.lifespan_context(app), await _started_client(app) as client:
        # client-a is granted client_credentials in this seed, so the seeded
        # RS256 key is what actually signs the returned access token.
        resp = await client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "scope": "read"},
            auth=("client-a", "test-only-secret"),
        )
        assert resp.status_code == 200, resp.text
        token = resp.json()["access_token"]
        assert jwt.get_unverified_header(token)["kid"] == "seed-rs"

        # The public half published by JWKS verifies the token the SUT minted.
        jwks = (await client.get("/.well-known/jwks.json")).json()
        public = jwt.PyJWK(next(k for k in jwks["keys"] if k["kid"] == "seed-rs"))
        claims = jwt.decode(
            token,
            public.key,
            algorithms=["RS256"],
            issuer="http://localhost:8080",
            options={"verify_aud": False},
        )
        assert claims["iss"] == "http://localhost:8080"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda env, seed: env.setenv("OAUTH2_ENV", "production"),
        lambda env, seed: env.setenv("APP_ENV", "staging"),
        lambda env, seed: env.setenv("OAUTH2_DATABASE_URL", "sqlite+aiosqlite:///prod.db"),
        lambda env, seed: env.setenv("OAUTH2_DATABASE_URL", "postgresql+asyncpg://u:p@db/x"),
        lambda env, seed: env.setenv("OAUTH2_CONFORMANCE_MODE", "maybe"),
        lambda env, seed: env.delenv("OAUTH2_CONFORMANCE_SEED"),
        lambda env, seed: env.setenv("OAUTH2_CONFORMANCE_SEED", str(seed.parent / "missing.yaml")),
        lambda env, seed: seed.write_text("issuer: http://x\nclients: []\nusers: []\n"),
        lambda env, seed: seed.write_text(VALID + "bogus: 1\n"),
    ],
    ids=[
        "production-env",
        "staging-app-env",
        "persistent-sqlite",
        "postgres",
        "ambiguous-switch",
        "missing-seed-env",
        "missing-seed-file",
        "invalid-seed",
        "unknown-seed-key",
    ],
)
def test_build_fails_closed(conformance_env, seed_file, mutate):
    mutate(conformance_env, seed_file)
    with pytest.raises(ConformanceError):
        build()


async def test_an_unappliable_seed_never_becomes_ready(conformance_env):
    app = build()
    # Pre-existing state conflicts with the seed: the lifespan must abort.
    from tests.helpers import seed_client

    await app.state.storage.init()
    await seed_client(app.state.storage, client_id="client-a")
    with pytest.raises(ConformanceError, match="already exists"):
        async with app.router.lifespan_context(app):
            pytest.fail("server must not start serving with a partially applied seed")


# -- process entry point -------------------------------------------------------


def test_main_runs_a_single_worker_in_conformance_mode(conformance_env):
    from oauth2_server import __main__ as entry

    captured: dict = {}
    conformance_env.setattr(entry.uvicorn, "run", lambda *a, **kw: captured.update(kw))
    conformance_env.setenv("OAUTH2_WORKERS", "4")
    entry.main()
    # The store is process-local, so every worker would see a different one.
    assert captured["workers"] == 1


def test_main_fails_closed_before_spawning_workers(conformance_env):
    from oauth2_server import __main__ as entry

    conformance_env.setenv("OAUTH2_ENV", "production")
    ran = []
    conformance_env.setattr(entry.uvicorn, "run", lambda *a, **kw: ran.append(kw))
    with pytest.raises(ConformanceError):
        entry.main()
    assert ran == []


def test_main_keeps_configured_workers_when_the_mode_is_off(monkeypatch):
    from oauth2_server import __main__ as entry

    monkeypatch.setenv("OAUTH2_JWT_SECRET", SECRET)
    monkeypatch.delenv("OAUTH2_CONFORMANCE_MODE", raising=False)
    monkeypatch.setenv("OAUTH2_WORKERS", "3")
    captured: dict = {}
    monkeypatch.setattr(entry.uvicorn, "run", lambda *a, **kw: captured.update(kw))
    entry.main()
    assert captured["workers"] == 3


def test_create_app_alone_never_enables_the_mode():
    app = create_app(_config(), None)
    assert not hasattr(app.state, "conformance")


def test_seed_text_never_logs_credentials():
    # `Seed.__repr__` is what lands in tracebacks: secrets must be masked.
    seed = Seed.parse(VALID)
    assert not re.search(r"test-only", repr(seed))
