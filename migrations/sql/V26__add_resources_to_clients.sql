-- RFC 8707: optional per-client allow-list of resource indicators (a JSON array
-- stored as TEXT). An empty array means not configured, and existing rows need no backfill.
ALTER TABLE clients ADD COLUMN resources TEXT NOT NULL DEFAULT '[]';
