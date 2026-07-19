-- OAuth2 Device Authorization Grant (RFC 8628)
CREATE TABLE IF NOT EXISTS device_authorizations (
    id TEXT PRIMARY KEY,
    device_code TEXT NOT NULL UNIQUE,
    user_code TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    interval_seconds INTEGER NOT NULL,
    approved BOOLEAN NOT NULL DEFAULT FALSE,
    denied BOOLEAN NOT NULL DEFAULT FALSE,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    user_id TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_device_authorizations_device_code ON device_authorizations(device_code);
CREATE INDEX IF NOT EXISTS idx_device_authorizations_user_code ON device_authorizations(user_code);
CREATE INDEX IF NOT EXISTS idx_device_authorizations_client_id ON device_authorizations(client_id);
