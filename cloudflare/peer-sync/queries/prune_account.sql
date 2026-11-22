-- Execute atomically in the same D1 batch as the authenticated insertion.
-- Do not run this alone after a separately committed insertion: that briefly
-- permits over-quota state and can leave it behind on failure.
-- Bind the same authenticated account_id to both placeholders.
WITH ranked AS (
  SELECT envelope_id,
         ROW_NUMBER() OVER (
           ORDER BY server_sequence DESC, envelope_id DESC
         ) AS position,
         SUM(stored_bytes) OVER (
           ORDER BY server_sequence DESC, envelope_id DESC
           ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
         ) AS cumulative_bytes
  FROM encrypted_text_envelopes WHERE account_id = ?
)
DELETE FROM encrypted_text_envelopes
WHERE account_id = ?
  AND envelope_id IN (
    SELECT envelope_id FROM ranked
    WHERE position > 2000 OR cumulative_bytes > 5242880
  );
