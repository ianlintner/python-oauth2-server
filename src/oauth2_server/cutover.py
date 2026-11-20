"""Operator-run credential-at-rest cutover: ``python -m oauth2_server.cutover``.

Converts a database written by a pre-cutover release (raw tokens, codes and
client secrets) to the at-rest format in `services/credential_storage.py`.
It is an OFFLINE, EXPLICIT step:

* never run by server startup (the V28 migration only adds columns);
* idempotent — already-converted rows are skipped, so a re-run after a partial
  Mongo pass is safe; on SQL the whole conversion is one transaction;
* never deletes rows. ``--revoke-issued`` additionally revokes every token
  and expires every outstanding code, which is the "credential rotation"
  half of a breaking cutover;
* records a version marker in ``cutover_state`` so ``status`` can tell
  whether a database has been converted.

After conversion no legacy value is accepted: lookups digest the presented
value, so a raw legacy value in a row matches nothing, and a legacy plaintext
``client_secret`` never verifies (`verify_client_secret`).

Commands::

    python -m oauth2_server.cutover status
    python -m oauth2_server.cutover convert [--revoke-issued] [--yes]
    python -m oauth2_server.cutover rollback-plan

Configuration comes from the same ``OAUTH2_*`` environment as the server
(``OAUTH2_DATABASE_URL``, ``OAUTH2_JWT_SECRET`` — the latter derives the
sealing key for HMAC client-secret key material).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import column, select, table, text, update

from oauth2_server.security import decode_unverified_claims
from oauth2_server.services.credential_storage import (
    derive_seal_key,
    digest,
    is_legacy,
    is_legacy_secret,
    seal,
    secret_verifier,
)

CUTOVER_VERSION = "credential-at-rest-v1"

ROLLBACK_PLAN = f"""\
Rollback plan for cutover {CUTOVER_VERSION}

A converted database CANNOT be turned back into the old format: the stored
digests and Argon2id verifiers are one-way, which is the point. Roll back by
RESTORING, not by reversing:

 1. Before running `convert`: take a full backup of the database (pg_dump, a
    snapshot, or a Mongo dump) and keep the previous release artifact.
 2. To roll back: stop all server instances, deploy the PREVIOUS release,
    restore the pre-cutover backup. The V28 columns are additive, so the old
    release ignores them.
 3. Anything issued after the cutover (new tokens, codes, clients, rotated
    secrets) exists only in the converted database and is lost by the restore.
 4. Do NOT run the old release against a converted database: it would read
    digests as if they were credentials and nothing would authenticate.
 5. Credentials revoked with `--revoke-issued` come back with the restore.
    Rotate them again if the cutover was meant to invalidate them.
"""


@dataclass
class Report:
    """Counts of rows by state; `legacy` is what `convert` would touch."""

    legacy: dict[str, int] = field(default_factory=dict)
    converted: dict[str, int] = field(default_factory=dict)
    marker: str | None = None

    @property
    def total_legacy(self) -> int:
        return sum(self.legacy.values())

    def lines(self) -> list[str]:
        out = [f"cutover marker: {self.marker or 'not applied'}"]
        for key in sorted(set(self.legacy) | set(self.converted)):
            out.append(
                f"  {key}: {self.legacy.get(key, 0)} legacy, {self.converted.get(key, 0)} converted"
            )
        return out


def _tally(report: Report, key: str, legacy: bool) -> None:
    bucket = report.legacy if legacy else report.converted
    bucket[key] = bucket.get(key, 0) + 1


# --- row classification (shared by SQL and Mongo) -------------------------------


def classify(
    clients: list[dict], tokens: list[dict], codes: list[dict], devices: list[dict]
) -> Report:
    report = Report()
    for c in clients:
        if c.get("client_secret"):
            _tally(report, "clients.client_secret", is_legacy_secret(c["client_secret"]))
        if c.get("registration_access_token"):
            _tally(
                report,
                "clients.registration_access_token",
                is_legacy(c["registration_access_token"], "rat"),
            )
    for t in tokens:
        _tally(report, "tokens.access_token", is_legacy(t["access_token"], "access"))
        if t.get("refresh_token"):
            _tally(report, "tokens.refresh_token", is_legacy(t["refresh_token"], "refresh"))
    for a in codes:
        _tally(report, "authorization_codes.code", is_legacy(a["code"], "authcode"))
    for d in devices:
        _tally(report, "device_authorizations.device_code", is_legacy(d["device_code"], "device"))
    return report


def _token_context(access_token: str) -> tuple[str, str]:
    """(cnf, audience) JSON for a legacy token, read while the plaintext is
    still available, so refresh continuity survives the cutover."""
    import json

    claims = decode_unverified_claims(access_token)
    cnf = claims.get("cnf")
    aud = claims.get("aud")
    if isinstance(aud, str):
        aud = [aud]
    ok_aud = isinstance(aud, list) and aud and all(isinstance(a, str) for a in aud)
    return (json.dumps(cnf) if isinstance(cnf, dict) else "", json.dumps(aud) if ok_aud else "")


# --- SQL ---------------------------------------------------------------------------

_STATE_DDL = (
    "CREATE TABLE IF NOT EXISTS cutover_state ("
    "version TEXT PRIMARY KEY, applied_at TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '')"
)


def _tbl(name: str, *cols: str):
    """Lightweight Core table so statements are built without raw SQL strings."""
    return table(name, *(column(c) for c in cols))


async def _sql_rows(conn, table: str, cols: str) -> list[dict]:
    tbl = _tbl(table, *(c.strip() for c in cols.split(",")))
    stmt = select(*tbl.c)
    return [dict(r) for r in (await conn.execute(stmt)).mappings()]


async def _sql_marker(conn) -> str | None:
    await conn.execute(text(_STATE_DDL))
    row = (
        await conn.execute(
            text("SELECT version FROM cutover_state WHERE version = :v"), {"v": CUTOVER_VERSION}
        )
    ).first()
    return row[0] if row else None


async def sql_status(storage) -> Report:
    async with storage._engine.begin() as conn:
        marker = await _sql_marker(conn)
        report = classify(
            await _sql_rows(conn, "clients", "client_secret, registration_access_token"),
            await _sql_rows(conn, "tokens", "access_token, refresh_token"),
            await _sql_rows(conn, "authorization_codes", "code"),
            await _sql_rows(conn, "device_authorizations", "device_code"),
        )
    report.marker = marker
    return report


async def sql_convert(storage, master: str, *, revoke_issued: bool) -> Report:
    """Convert every legacy SQL row in ONE transaction (all or nothing)."""
    key = derive_seal_key(master)
    async with storage._engine.begin() as conn:
        await _sql_marker(conn)
        before = classify(
            await _sql_rows(conn, "clients", "client_secret, registration_access_token"),
            await _sql_rows(conn, "tokens", "access_token, refresh_token"),
            await _sql_rows(conn, "authorization_codes", "code"),
            await _sql_rows(conn, "device_authorizations", "device_code"),
        )

        for c in await _sql_rows(
            conn, "clients", "client_id, client_secret, registration_access_token"
        ):
            sets: dict[str, str] = {}
            if is_legacy_secret(c["client_secret"]):
                sets["client_secret"] = secret_verifier(c["client_secret"])
                sets["client_secret_key"] = seal(c["client_secret"], key, c["client_id"])
            if is_legacy(c["registration_access_token"], "rat"):
                sets["registration_access_token"] = digest(c["registration_access_token"], "rat")
            if sets:
                tbl = _tbl("clients", "client_id", *sets)
                await conn.execute(
                    update(tbl).where(tbl.c.client_id == c["client_id"]).values(**sets)
                )

        for t in await _sql_rows(conn, "tokens", "id, access_token, refresh_token"):
            if not (
                is_legacy(t["access_token"], "access") or is_legacy(t["refresh_token"], "refresh")
            ):
                continue
            values: dict[str, str | None] = {
                "access_token": t["access_token"],
                "refresh_token": t["refresh_token"],
            }
            if is_legacy(t["access_token"], "access"):
                values["cnf"], values["audience"] = _token_context(t["access_token"])
                values["access_token"] = digest(t["access_token"], "access")
            if is_legacy(t["refresh_token"], "refresh"):
                values["refresh_token"] = digest(t["refresh_token"], "refresh")
            tbl = _tbl("tokens", "id", *values)
            await conn.execute(update(tbl).where(tbl.c.id == t["id"]).values(**values))

        for a in await _sql_rows(conn, "authorization_codes", "code"):
            if is_legacy(a["code"], "authcode"):
                await conn.execute(
                    text("UPDATE authorization_codes SET code = :n WHERE code = :o"),
                    {"n": digest(a["code"], "authcode"), "o": a["code"]},
                )
        for d in await _sql_rows(conn, "device_authorizations", "device_code"):
            if is_legacy(d["device_code"], "device"):
                await conn.execute(
                    text(
                        "UPDATE device_authorizations SET device_code = :n WHERE device_code = :o"
                    ),
                    {"n": digest(d["device_code"], "device"), "o": d["device_code"]},
                )

        detail = "revoke_issued" if revoke_issued else ""
        if revoke_issued:
            await conn.execute(text("UPDATE tokens SET revoked = :r"), {"r": True})
            await conn.execute(text("UPDATE authorization_codes SET used = :u"), {"u": True})
            await conn.execute(text("UPDATE device_authorizations SET used = :u"), {"u": True})
        await conn.execute(
            text(
                "INSERT INTO cutover_state (version, applied_at, detail) VALUES (:v, :t, :d) "
                "ON CONFLICT (version) DO UPDATE SET applied_at = :t, detail = :d"
            ),
            {"v": CUTOVER_VERSION, "t": datetime.now(UTC).isoformat(), "d": detail},
        )
    before.marker = CUTOVER_VERSION
    return before


# --- Mongo -------------------------------------------------------------------------


async def _mongo_docs(coll) -> list[dict]:
    return [d async for d in coll.find({})]


async def mongo_status(storage) -> Report:
    state = await storage._db["cutover_state"].find_one({"version": CUTOVER_VERSION})
    report = classify(
        await _mongo_docs(storage.clients),
        await _mongo_docs(storage.tokens),
        await _mongo_docs(storage.authorization_codes),
        await _mongo_docs(storage.device_authorizations),
    )
    report.marker = CUTOVER_VERSION if state else None
    return report


async def mongo_convert(storage, master: str, *, revoke_issued: bool) -> Report:
    """Per-document conversion. Not transactional (Cosmos-compatible); each
    document update is atomic and the pass is idempotent, so re-running after
    an interruption finishes the job."""
    key = derive_seal_key(master)
    before = await mongo_status(storage)

    async for c in storage.clients.find({}):
        sets: dict[str, str] = {}
        if is_legacy_secret(c.get("client_secret")):
            sets["client_secret"] = secret_verifier(c["client_secret"])
            sets["client_secret_key"] = seal(c["client_secret"], key, c["client_id"])
        if is_legacy(c.get("registration_access_token"), "rat"):
            sets["registration_access_token"] = digest(c["registration_access_token"], "rat")
        if sets:
            await storage.clients.update_one({"_id": c["_id"]}, {"$set": sets})

    async for t in storage.tokens.find({}):
        sets = {}
        if is_legacy(t.get("access_token"), "access"):
            sets["cnf"], sets["audience"] = _token_context(t["access_token"])
            sets["access_token"] = digest(t["access_token"], "access")
        if is_legacy(t.get("refresh_token"), "refresh"):
            sets["refresh_token"] = digest(t["refresh_token"], "refresh")
        if sets:
            await storage.tokens.update_one({"_id": t["_id"]}, {"$set": sets})

    async for a in storage.authorization_codes.find({}):
        if is_legacy(a.get("code"), "authcode"):
            await storage.authorization_codes.update_one(
                {"_id": a["_id"]}, {"$set": {"code": digest(a["code"], "authcode")}}
            )
    async for d in storage.device_authorizations.find({}):
        if is_legacy(d.get("device_code"), "device"):
            await storage.device_authorizations.update_one(
                {"_id": d["_id"]}, {"$set": {"device_code": digest(d["device_code"], "device")}}
            )

    if revoke_issued:
        await storage.tokens.update_many({}, {"$set": {"revoked": True}})
        await storage.authorization_codes.update_many({}, {"$set": {"used": True}})
        await storage.device_authorizations.update_many({}, {"$set": {"used": True}})
    await storage._db["cutover_state"].update_one(
        {"version": CUTOVER_VERSION},
        {
            "$set": {
                "applied_at": datetime.now(UTC).isoformat(),
                "detail": "revoke_issued" if revoke_issued else "",
            }
        },
        upsert=True,
    )
    before.marker = CUTOVER_VERSION
    return before


# --- dispatch + CLI ----------------------------------------------------------------


def _is_mongo(storage) -> bool:
    return hasattr(storage, "_db")


async def status(storage) -> Report:
    return await (mongo_status if _is_mongo(storage) else sql_status)(storage)


async def convert(storage, master: str, *, revoke_issued: bool = False) -> Report:
    """Convert `storage` in place; returns the pre-conversion report. Callers
    must have run the V28 migration (the server's `init()` does)."""
    fn = mongo_convert if _is_mongo(storage) else sql_convert
    return await fn(storage, master, revoke_issued=revoke_issued)


async def _run(args: argparse.Namespace) -> int:
    from oauth2_server.config import Config
    from oauth2_server.storage.factory import create_storage

    config = Config()
    storage = create_storage(config)
    await storage.init()
    try:
        if args.command == "status":
            for line in (await status(storage)).lines():
                print(line)
            return 0
        report = await status(storage)
        for line in report.lines():
            print(line)
        if not args.yes:
            print(
                f"\nThis converts {report.total_legacy} legacy value(s) in place"
                + (" and REVOKES all issued tokens/codes" if args.revoke_issued else "")
                + ". Back up the database first (see `rollback-plan`). Re-run with --yes."
            )
            return 2
        await convert(storage, config.jwt_secret, revoke_issued=args.revoke_issued)
        print("\nconverted. verify with `status` (expect 0 legacy).")
        return 0
    finally:
        close = getattr(storage, "close", None)
        if close is not None:
            await close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m oauth2_server.cutover", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="count legacy vs converted values (read-only)")
    c = sub.add_parser("convert", help="convert legacy rows in place (operator-initiated)")
    c.add_argument(
        "--revoke-issued", action="store_true", help="also revoke all issued tokens/codes"
    )
    c.add_argument("--yes", action="store_true", help="confirm; without it convert only previews")
    sub.add_parser("rollback-plan", help="print rollback guidance")
    args = p.parse_args(argv)
    if args.command == "rollback-plan":
        print(ROLLBACK_PLAN)
        return 0
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
