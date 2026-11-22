-- One-use signed device request nonce retention, independent from clipboard cache.
-- This is per-account/device control-plane state, not eligible for clip pruning.
-- Nonces are opaque random identifiers, never plaintext clipboard data.
CREATE TABLE IF NOT EXISTS cloud_cache_request_nonces (
  account_id TEXT NOT NULL CHECK(length(account_id) BETWEEN 1 AND 128),
  device_id TEXT NOT NULL CHECK(length(device_id) BETWEEN 1 AND 128),
  nonce TEXT NOT NULL CHECK(length(nonce) BETWEEN 22 AND 86),
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
  PRIMARY KEY(account_id, device_id, nonce)
);
CREATE INDEX IF NOT EXISTS cloud_cache_nonce_expiry
  ON cloud_cache_request_nonces(account_id, expires_at_ms);
