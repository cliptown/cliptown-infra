-- Persistent per-device replay watermark, independent of 2,000-clip eviction.
-- A device must sign a strictly increasing sequence for each encrypted upload.
-- Never prune this table with cached ciphertext. Device de-registration requires
-- a separate revocation epoch/retirement protocol to prevent re-enrollment replay.
CREATE TABLE IF NOT EXISTS cloud_cache_device_watermarks (
  account_id TEXT NOT NULL CHECK(length(account_id) BETWEEN 1 AND 128),
  device_id TEXT NOT NULL CHECK(length(device_id) BETWEEN 1 AND 128),
  last_device_sequence INTEGER NOT NULL
    CHECK(last_device_sequence BETWEEN 1 AND 9007199254740990),
  PRIMARY KEY(account_id, device_id)
);
CREATE TRIGGER IF NOT EXISTS cloud_cache_reject_device_replay
BEFORE UPDATE OF last_device_sequence ON cloud_cache_device_watermarks
WHEN NEW.last_device_sequence <= OLD.last_device_sequence
BEGIN
  SELECT RAISE(ABORT, 'device_sequence_replay');
END;

-- Existing foundation has not been deployed. The default supports upgrading a
-- dry-run/test D1 database without falsely marking old records authenticated.
ALTER TABLE encrypted_text_envelopes ADD COLUMN device_sequence INTEGER NOT NULL
  DEFAULT 0 CHECK(device_sequence BETWEEN 0 AND 9007199254740990);
