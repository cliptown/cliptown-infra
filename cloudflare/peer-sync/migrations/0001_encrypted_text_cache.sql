-- Contract-only Cloudflare D1 desired state; deploy only after auth/ownership admission.
-- Never insert plaintext, local paths, plaintext vectors, tokens, or device keys.
-- Exactly one authenticated account owns each opaque envelope ID.
CREATE TABLE IF NOT EXISTS encrypted_text_envelopes (
  account_id TEXT NOT NULL CHECK (length(account_id) BETWEEN 1 AND 128),
  envelope_id TEXT NOT NULL CHECK (length(envelope_id) BETWEEN 1 AND 128),
  server_sequence INTEGER NOT NULL CHECK (server_sequence > 0),
  kind TEXT NOT NULL DEFAULT 'text' CHECK (kind = 'text'),
  ciphertext BLOB NOT NULL CHECK (length(ciphertext) > 0),
  ciphertext_digest TEXT NOT NULL CHECK (length(ciphertext_digest) = 64),
  ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes = length(ciphertext)),
  stored_bytes INTEGER NOT NULL CHECK (
    stored_bytes = ciphertext_bytes + 512 AND stored_bytes <= 5242880
  ),
  received_ms INTEGER NOT NULL CHECK (received_ms > 0),
  device_id TEXT NOT NULL CHECK (length(device_id) BETWEEN 1 AND 128),
  PRIMARY KEY (account_id, envelope_id)
);
CREATE INDEX IF NOT EXISTS encrypted_text_envelopes_newest
  ON encrypted_text_envelopes(account_id, server_sequence DESC, envelope_id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS encrypted_text_envelopes_sequence
  ON encrypted_text_envelopes(account_id, server_sequence);

-- Tombstone/checkpoint and revocation state is a DIFFERENT bounded control-plane
-- dataset, not subject to clip eviction. Its own retention/anti-resurrection
-- requirements must be admitted before production activation.
