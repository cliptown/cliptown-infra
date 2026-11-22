-- Server-owned monotonic per-account cloud receipt position.
-- Survives cache eviction. Not a sync-v1 authoritative cursor.
CREATE TABLE IF NOT EXISTS cloud_cache_account_sequences (
  account_id TEXT PRIMARY KEY NOT NULL CHECK(length(account_id) BETWEEN 1 AND 128),
  last_sequence INTEGER NOT NULL CHECK(last_sequence BETWEEN 1 AND 9007199254740990)
);
