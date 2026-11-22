// Bounded, parameterized D1 SQL; no dynamic identifiers or account-id interpolation.
// The append batch atomically advances the durable per-account receipt position,
// inserts one server-measured ciphertext, prunes, and reads its receipt.
export const ALLOCATE_SEQUENCE_SQL =
  "INSERT INTO cloud_cache_account_sequences(account_id,last_sequence) VALUES (?,1) " +
  "ON CONFLICT(account_id) DO UPDATE SET last_sequence=last_sequence+1";

// Atomic UPSERT+trigger: an equal or regressing signed device sequence raises
// SQLITE_CONSTRAINT and rolls back the entire D1 batch. A plain SELECT-based
// preflight is insufficient when two requests race.
export const ADVANCE_DEVICE_WATERMARK_SQL =
  "INSERT INTO cloud_cache_device_watermarks " +
  "(account_id,device_id,last_device_sequence) VALUES (?,?,?) " +
  "ON CONFLICT(account_id,device_id) DO UPDATE " +
  "SET last_device_sequence=excluded.last_device_sequence";

export const READ_DEVICE_WATERMARK_SQL =
  "SELECT last_device_sequence FROM cloud_cache_device_watermarks " +
  "WHERE account_id=? AND device_id=? LIMIT 1";

export const APPEND_TEXT_SQL =
  "INSERT INTO encrypted_text_envelopes " +
  "(account_id,envelope_id,server_sequence,kind,ciphertext,ciphertext_digest," +
  "ciphertext_bytes,stored_bytes,received_ms,device_id,device_sequence) " +
  "SELECT ?,?,last_sequence,'text',?,?,?,?,?,?,? " +
  "FROM cloud_cache_account_sequences WHERE account_id=?";

export const PRUNE_ACCOUNT_SQL = [
  "WITH ranked AS (",
  " SELECT envelope_id,",
  " ROW_NUMBER() OVER (ORDER BY server_sequence DESC, envelope_id DESC) AS position,",
  " SUM(stored_bytes) OVER (ORDER BY server_sequence DESC, envelope_id DESC",
  " ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cumulative_bytes",
  " FROM encrypted_text_envelopes WHERE account_id = ?",
  ")",
  "DELETE FROM encrypted_text_envelopes",
  "WHERE account_id = ?",
  "AND envelope_id IN (SELECT envelope_id FROM ranked",
  "WHERE position > 2000 OR cumulative_bytes > 5242880)",
].join("\n");

export const LOOKUP_RECEIPT_SQL =
  "SELECT envelope_id,server_sequence,ciphertext_digest,ciphertext_bytes,device_id,device_sequence " +
  "FROM encrypted_text_envelopes WHERE account_id=? AND envelope_id=? LIMIT 1";

export const READ_CACHE_PAGE_SQL =
  "SELECT envelope_id,server_sequence,ciphertext,ciphertext_digest,ciphertext_bytes,device_id " +
  "FROM encrypted_text_envelopes " +
  "WHERE account_id=? AND (? IS NULL OR server_sequence<?) " +
  "ORDER BY server_sequence DESC, envelope_id DESC LIMIT ?";
