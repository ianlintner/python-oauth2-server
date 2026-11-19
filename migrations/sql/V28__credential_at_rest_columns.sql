-- Credential-at-rest cutover (see docs/credential-cutover.md).
--
-- `clients.client_secret_key` holds sealed (AES-256-GCM) symmetric key
-- material for the HMAC uses of a client secret (client_secret_jwt, HS256 JAR,
-- HS256 introspection JWTs). `clients.client_secret` itself becomes a
-- nonrecoverable Argon2id verifier.
--
-- `tokens.cnf` / `tokens.audience` keep the confirmation claim and audience
-- set of the issued access token (JSON text, '' = none) so a refresh can carry
-- them forward now that the plaintext access token is no longer stored.
--
-- This migration only ADDS columns. It never rewrites, deletes or invalidates
-- existing rows: converting stored credentials is the explicit, operator-run
-- `python -m oauth2_server.cutover convert` step, never a side effect of
-- server startup.
ALTER TABLE clients ADD COLUMN client_secret_key TEXT NOT NULL DEFAULT '';
ALTER TABLE tokens ADD COLUMN cnf TEXT NOT NULL DEFAULT '';
ALTER TABLE tokens ADD COLUMN audience TEXT NOT NULL DEFAULT '';
