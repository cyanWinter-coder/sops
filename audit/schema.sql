-- Audit events for SOPS.
--
-- The table stores only safe metadata and redacted field summaries. Plaintext
-- and raw key fingerprints must never be inserted; see audit.Redactor.
CREATE TABLE IF NOT EXISTS audit_event (
  id SERIAL PRIMARY KEY,
  -- Idempotency key. Repeated delivery of the same event ID conflicts and is
  -- ignored, including retries after a short audit-database outage.
  event_id TEXT NOT NULL UNIQUE,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  action TEXT NOT NULL,
  username TEXT,
  file TEXT NOT NULL,
  -- Opaque stable key-group identifier/digest, not a raw key fingerprint.
  key_group_id TEXT,
  result TEXT NOT NULL DEFAULT 'unknown',
  -- Redacted diagnostic fields. Values are either safe scalars or
  -- {"length":N,"digest":"sha256-hex"} summaries.
  details JSONB,
  -- Six-month retention boundary. A daily job deletes rows once this is past.
  retention_until TIMESTAMPTZ GENERATED ALWAYS AS (timestamp + INTERVAL '180 days') STORED
);

-- Primary troubleshooting query: one file, optionally one operation type,
-- ordered by when events happened.
CREATE INDEX IF NOT EXISTS idx_audit_event_file_action_timestamp
  ON audit_event (file, action, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_event_action_timestamp
  ON audit_event (action, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_event_key_group
  ON audit_event (key_group_id);

-- Retention janitor query.
CREATE INDEX IF NOT EXISTS idx_audit_event_retention_until
  ON audit_event (retention_until);

-- Existing deployments created from the old schema can be migrated with:
--
-- ALTER TABLE audit_event
--   ADD COLUMN IF NOT EXISTS event_id TEXT,
--   ADD COLUMN IF NOT EXISTS key_group_id TEXT,
--   ADD COLUMN IF NOT EXISTS result TEXT NOT NULL DEFAULT 'unknown',
--   ADD COLUMN IF NOT EXISTS details JSONB,
--   ADD COLUMN IF NOT EXISTS retention_until TIMESTAMPTZ
--     GENERATED ALWAYS AS (timestamp + INTERVAL '180 days') STORED;
-- UPDATE audit_event SET event_id = id::text WHERE event_id IS NULL;
-- ALTER TABLE audit_event ALTER COLUMN event_id SET NOT NULL;
-- CREATE UNIQUE INDEX IF NOT EXISTS audit_event_event_id_key ON audit_event(event_id);

CREATE ROLE sops WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN PASSWORD 'sops';

GRANT INSERT, SELECT ON audit_event TO sops;
GRANT USAGE ON audit_event_id_seq TO sops;
-- Retention jobs that run as the application role also need DELETE. Prefer a
-- separate least-privilege retention role in production if cleanup is external.
GRANT DELETE ON audit_event TO sops;
