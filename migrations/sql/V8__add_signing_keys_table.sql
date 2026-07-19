-- Key storage for JWT key rotation.
-- key_material is encrypted at rest using AES-256-GCM with the JWT secret as KEK.
CREATE TABLE IF NOT EXISTS signing_keys (
    id TEXT PRIMARY KEY,
    kid TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL,
    key_material BYTEA NOT NULL,
    is_current BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_kid ON signing_keys(kid);
CREATE INDEX IF NOT EXISTS idx_signing_keys_algorithm_current ON signing_keys(algorithm, is_current);
