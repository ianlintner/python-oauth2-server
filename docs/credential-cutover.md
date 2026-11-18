# Credentials and tokens hashed at rest — operator cutover

This release stops storing raw bearer values in the database. It is a
**breaking, operator-initiated cutover**: deploying the release does not touch
existing data, and a database that has not been converted does not
authenticate anything.

## What is stored now

| Value | Stored as | Why |
|---|---|---|
| `tokens.access_token` | `sha256-access-v1$<b64url>` digest | lookup credential (server receives it, finds the row) |
| `tokens.refresh_token` | `sha256-refresh-v1$…` digest | lookup credential |
| `authorization_codes.code` | `sha256-authcode-v1$…` digest | lookup credential |
| `device_authorizations.device_code` | `sha256-device-v1$…` digest | lookup credential |
| `clients.registration_access_token` | `sha256-rat-v1$…` digest | lookup credential (RFC 7592) |
| `clients.client_secret` | `argon2id-v1$<Argon2id hash>` | comparison-only verifier for `client_secret_basic` / `client_secret_post` — nonrecoverable |
| `clients.client_secret_key` (new) | `aesgcm-v1$…` sealed key material | **only** for the HMAC uses of the secret (below) |
| `device_authorizations.user_code` | unchanged | short, human-typed, not a bearer credential; protected by the RFC 8628 polling limit |

* The high-entropy lookup values are 256-bit random (or JWTs), so a fast
  one-way SHA-256 is sufficient and keeps them usable as an indexed lookup key.
  Digests are domain-separated per kind: a refresh value never matches an
  access-token row.
* Lookups **always digest the presented value**, so a stored digest presented
  as a credential matches nothing, and a raw legacy value sitting in an
  unconverted row matches nothing either. There is no legacy fallback.
* Newly issued values behave as before: the plaintext is returned to the
  client once and never persisted.
* `tokens.cnf` / `tokens.audience` (new) keep the DPoP/mTLS confirmation claim
  and audience set so refresh keeps carrying them forward.

### Verifier vs. symmetric key material

`client_secret_jwt` (RFC 7523), HS256 JAR request objects and HS256 JWT
introspection responses use the client secret as an **HMAC key**, which a
nonrecoverable verifier cannot provide. That one value is therefore kept as
*sealed key material*: AES-256-GCM, key derived (HKDF-SHA256) from
`OAUTH2_JWT_SECRET`, bound to the `client_id` as associated data, in
`clients.client_secret_key`.

Security consequence, stated plainly: a copy of the database **alone** no
longer yields a usable client secret, but the database **plus**
`OAUTH2_JWT_SECRET` can recover the HMAC key of clients whose secret was
created by this release or converted. Clients that only use Basic/Post still
have only the nonrecoverable verifier in effect. If you do not need HMAC client
auth/JAR/HS256 introspection you can drop the sealed column's contents after
conversion (`UPDATE clients SET client_secret_key = ''`); those methods then
fail closed.

Rotating `OAUTH2_JWT_SECRET` makes existing sealed key material unopenable
(HMAC uses fail closed; Basic/Post keep working). Re-issue affected clients'
secrets after a rotation.

## Cutover procedure

1. **Back up** the database (this is the rollback — see below) and keep the
   previous release artifact.
2. Stop all server instances (the cutover is offline).
3. Deploy the new release's code to the operator shell and run the V24
   migration by starting the server once against a **restored copy**, or let
   your normal migration process run it. The migration only *adds* columns
   and never rewrites data.
4. Preview, then convert, with the same `OAUTH2_*` environment as the server:

   ```sh
   python -m oauth2_server.cutover status
   python -m oauth2_server.cutover convert            # preview: refuses without --yes
   python -m oauth2_server.cutover convert --yes      # convert in place
   python -m oauth2_server.cutover convert --yes --revoke-issued   # rotate: also revoke everything issued
   python -m oauth2_server.cutover status             # expect 0 legacy
   ```

   * SQL: the whole conversion is **one transaction** — all or nothing.
   * Mongo: per-document and idempotent (no multi-document transaction, for
     CosmosDB compatibility); re-run after an interruption.
   * Nothing is deleted. `--revoke-issued` marks every token revoked and every
     code used.
5. Start the new release.

`convert` without `--revoke-issued` keeps outstanding tokens working across
the conversion (their digests are computed from the presented value). Use
`--revoke-issued` for the breaking rotation: every access/refresh token,
authorization code and device code stops working and clients must obtain new
ones.

### Credential rotation and session resets

* **Client secrets**: conversion preserves each client's current secret as a
  verifier. To rotate, regenerate them through the admin API after cutover
  (`POST /admin/api/clients/{id}/regenerate-secret`) — the new secret is shown
  once.
* **Registration access tokens** are issued once at registration; conversion
  digests the current value. Re-register or rotate where required.
* **Browser sessions** are signed cookies held by the browser, not rows in the
  database. Rotating `OAUTH2_JWT_SECRET` (which also invalidates the HMAC key
  material above, see there) resets every session.

### Already-issued stateless tokens

JWT access tokens are self-contained. After cutover they remain
signature-valid until `exp` for any resource server that validates them
**without calling this server** (JWKS-only validation). Server-side endpoints
that consult storage — userinfo, introspection, refresh, admin — follow the
stored row: with `--revoke-issued` they reject the token immediately; without
it they keep honouring it until expiry. To cut off JWTs at resource servers
too, rotate the signing keys those servers trust (and `OAUTH2_JWT_SECRET` for
HS256-signed tokens) and keep access-token TTLs short.

## Rollback

A converted database **cannot be reversed**: digests and Argon2id verifiers
are one-way. Roll back by restoring:

1. Stop all instances.
2. Deploy the previous release.
3. Restore the pre-cutover backup (the V24 columns are additive, so the old
   release ignores them).
4. Anything issued after the cutover exists only in the converted database and
   is lost by the restore. Credentials revoked by `--revoke-issued` return
   with the restore.

Never run the previous release against a converted database. The same text is
available from `python -m oauth2_server.cutover rollback-plan`.

## Compatibility notes

* The Python server previously shared `migrations/sql` and a Postgres with the
  Rust server. After this cutover the two servers must not share one database
  unless the Rust server adopts the same format.
* Admin responses that echo `device_code` now show the stored digest; the
  admin expire endpoint accepts either form.
