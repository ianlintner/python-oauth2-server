-- User consent grants: the scopes a user has approved for a client.
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_grants_client_id ON grants(client_id);
