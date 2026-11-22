// Contract-only quota engine. Never accept client-reported byte charges.
export const MAX_TEXT_ITEMS = 2000;
export const MAX_LOGICAL_BYTES = 5 * 1024 * 1024;
export const PER_ITEM_METADATA_RESERVE_BYTES = 512;

// Reserve space for metadata and indexes when accounting against the advertised
// logical per-account cap. Physical D1 usage can be higher.
export function measuredCharge(ciphertextByteLength) {
  if (!Number.isSafeInteger(ciphertextByteLength) || ciphertextByteLength < 1) {
    throw new TypeError("ciphertextByteLength must be a positive safe integer");
  }
  const charge = ciphertextByteLength + PER_ITEM_METADATA_RESERVE_BYTES;
  if (!Number.isSafeInteger(charge) || charge > MAX_LOGICAL_BYTES) {
    throw new RangeError("encrypted text envelope exceeds the cloud quota");
  }
  return charge;
}

// Input is server-measured metadata, not untrusted data supplied by a client.
// Ordering MUST match the D1 prune query: newest sequence, then binary ID DESC.
export function planRetention(envelopes) {
  if (!Array.isArray(envelopes)) throw new TypeError("envelopes must be an array");
  const ids = new Set();
  const rows = envelopes.map((row) => {
    if (!row || row.kind !== "text" ||
      typeof row.envelope_id !== "string" ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(row.envelope_id) ||
      !Number.isSafeInteger(row.server_sequence) || row.server_sequence <= 0) {
      throw new TypeError("invalid encrypted text envelope metadata");
    }
    if (ids.has(row.envelope_id)) throw new TypeError("duplicate envelope_id");
    ids.add(row.envelope_id);
    return {...row, stored_bytes: measuredCharge(row.ciphertext_bytes)};
  });
  rows.sort((a, b) => b.server_sequence - a.server_sequence ||
    (a.envelope_id < b.envelope_id ? 1 : a.envelope_id > b.envelope_id ? -1 : 0));
  const retained = [], evicted = [];
  let cumulative = 0;
  let retainedBytes = 0;
  rows.forEach((row, index) => {
    cumulative += row.stored_bytes;
    if (index < MAX_TEXT_ITEMS && cumulative <= MAX_LOGICAL_BYTES) {
      retained.push(row.envelope_id);
      retainedBytes = cumulative;
    } else {
      evicted.push(row.envelope_id);
    }
  });
  return {retained, evicted, retained_count: retained.length, logical_bytes: retainedBytes};
}
