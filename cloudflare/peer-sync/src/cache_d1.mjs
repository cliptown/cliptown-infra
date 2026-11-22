// Internal Cloudflare D1 adapter. NOT a public HTTP route. All entry points
// require the official Shared Auth + signed device-envelope verification callback.
// The public Worker remains HTTP 503 until that implementation is reviewed.
import { measuredCharge } from "./quota.mjs";
import {
  ALLOCATE_SEQUENCE_SQL, APPEND_TEXT_SQL, PRUNE_ACCOUNT_SQL,
  LOOKUP_RECEIPT_SQL, READ_CACHE_PAGE_SQL,
} from "./cache_sql.mjs";

const ID = /^[A-Za-z0-9:_-]{1,128}$/;
const ENVELOPE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_PAGE = 100;
const MAX_ATTESTATION_AGE_MS = 30_000;

export class CacheAccessError extends Error {
  constructor(code = "cache_access_denied") {
    super(code);
    this.name = "CacheAccessError";
    this.code = code;
  }
}

function policy(condition, code) {
  if (!condition) throw new CacheAccessError(code);
}

function ownCiphertext(input) {
  policy(input && typeof input === "object" && !Array.isArray(input),
    "invalid_envelope");
  policy(Object.keys(input).length === 3 &&
    ["kind", "envelope_id", "ciphertext"].every((key) =>
      Object.prototype.hasOwnProperty.call(input, key)), "invalid_envelope");
  policy(input.kind === "text" && ENVELOPE_ID.test(input.envelope_id),
    "invalid_envelope");
  policy(input.ciphertext instanceof Uint8Array,
    "invalid_ciphertext");
  // A mutable or shared source view must never be retained across await.
  policy(!(typeof SharedArrayBuffer !== "undefined" &&
    input.ciphertext.buffer instanceof SharedArrayBuffer), "invalid_ciphertext");
  measuredCharge(input.ciphertext.byteLength);
  return {
    envelope_id: input.envelope_id,
    ciphertext: new Uint8Array(input.ciphertext), // owned async boundary
  };
}

async function digestHex(bytes) {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash),
    (value) => value.toString(16).padStart(2, "0")).join("");
}

function checkedIdentity(proof, purpose, envelope) {
  const now = Date.now();
  policy(proof && typeof proof === "object" &&
    proof.authenticated === true && proof.active_device === true &&
    proof.revocation_checked === true && proof.purpose === purpose &&
    ID.test(proof.account_id) && ID.test(proof.device_id) &&
    Number.isSafeInteger(proof.key_epoch) && proof.key_epoch > 0 &&
    Number.isSafeInteger(proof.verified_at_ms) &&
    proof.verified_at_ms <= now + 5_000 &&
    proof.verified_at_ms >= now - MAX_ATTESTATION_AGE_MS,
  "cache_authority_unavailable");

  if (purpose === "text_cache.write") {
    policy(proof.signature_verified === true &&
      proof.verified_envelope_id === envelope.envelope_id &&
      proof.verified_ciphertext_digest === envelope.digest,
    "cache_envelope_signature_required");
  }
  return {account_id: proof.account_id, device_id: proof.device_id};
}

function sameReceipt(receipt, identity, digest, bytes) {
  return receipt !== null && receipt !== undefined &&
    receipt.device_id === identity.device_id &&
    receipt.ciphertext_digest === digest &&
    receipt.ciphertext_bytes === bytes &&
    Number.isSafeInteger(receipt.server_sequence) && receipt.server_sequence > 0;
}

function mustBatchSucceed(results) {
  policy(Array.isArray(results) && results.length === 4 &&
    results.every((item) => item && item.success === true),
  "cache_commit_unavailable");
  const receipt = results[3]?.results?.[0];
  policy(receipt && Number.isSafeInteger(receipt.server_sequence) &&
    receipt.server_sequence > 0, "cache_receipt_unavailable");
  return receipt;
}

function copyPageRecord(row) {
  policy(row && typeof row.envelope_id === "string" &&
    Number.isSafeInteger(row.server_sequence) && row.server_sequence > 0 &&
    Array.isArray(row.ciphertext) &&
    row.ciphertext.every((value) => Number.isInteger(value) && value >= 0 && value <= 255) &&
    row.ciphertext.length === row.ciphertext_bytes,
  "cache_corrupt_record");
  const owned = Uint8Array.from(row.ciphertext);
  return {
    envelope_id: row.envelope_id,
    server_sequence: row.server_sequence,
    ciphertext: owned,
    ciphertext_digest: row.ciphertext_digest,
    device_id: row.device_id,
  };
}

/**
 * This adapter has no default or fallback verifier. Only a separately reviewed
 * Shared Auth + device proof verifier may be supplied to production code.
 * The verifier MUST NOT accept an asserted account/device from HTTP JSON or
 * an unsigned WebSocket claim. Reads and writes both recheck revocation.
 *
 * No member of this adapter is wired into the public fail-closed Worker.
 */
export function createEncryptedTextCache(db, verifyDeviceRequest) {
  policy(db && typeof db.prepare === "function" &&
    typeof db.batch === "function", "cache_database_unavailable");
  policy(typeof verifyDeviceRequest === "function", "cache_authority_unavailable");

  async function receipt(account, id) {
    return db.prepare(LOOKUP_RECEIPT_SQL).bind(account, id).first();
  }

  return Object.freeze({
    async append(request, input) {
      // Synchronous snapshot: the caller cannot mutate this queued payload
      // through the original Uint8Array after any asynchronous operation.
      const source = ownCiphertext(input);
      const digest = await digestHex(source.ciphertext);
      const proof = await verifyDeviceRequest(request, {
        purpose: "text_cache.write",
        envelope_id: source.envelope_id,
        digest,
      });
      const identity = checkedIdentity(proof, "text_cache.write",
        {envelope_id: source.envelope_id, digest});
      const previous = await receipt(identity.account_id, source.envelope_id);
      if (previous) {
        policy(sameReceipt(previous, identity, digest, source.ciphertext.byteLength),
          "cache_immutable_conflict");
        return {server_sequence: previous.server_sequence, duplicate: true};
      }

      const charge = measuredCharge(source.ciphertext.byteLength);
      const now = Date.now();
      const statements = [
        db.prepare(ALLOCATE_SEQUENCE_SQL).bind(identity.account_id),
        db.prepare(APPEND_TEXT_SQL).bind(
          identity.account_id, source.envelope_id, source.ciphertext,
          digest, source.ciphertext.byteLength, charge, now,
          identity.device_id, identity.account_id),
        db.prepare(PRUNE_ACCOUNT_SQL).bind(identity.account_id, identity.account_id),
        db.prepare(LOOKUP_RECEIPT_SQL).bind(identity.account_id, source.envelope_id),
      ];

      try {
        // D1 executes these four statements as one atomic transaction.
        const committed = mustBatchSucceed(await db.batch(statements));
        return {server_sequence: committed.server_sequence, duplicate: false};
      } catch (_error) {
        // Ambiguous response loss or concurrent duplicate request:
        // only identical, already-committed payload may be acknowledged.
        // Provider errors and mismatched digests must never fake success.
        const after = await receipt(identity.account_id, source.envelope_id);
        if (sameReceipt(after, identity, digest, source.ciphertext.byteLength)) {
          return {server_sequence: after.server_sequence, duplicate: true};
        }
        throw new CacheAccessError("cache_commit_unavailable");
      }
    },

    async readPage(request, {before_sequence = null, limit = 50} = {}) {
      policy(before_sequence === null ||
        (Number.isSafeInteger(before_sequence) && before_sequence > 0),
      "invalid_cache_cursor");
      policy(Number.isInteger(limit) && limit >= 1 && limit <= MAX_PAGE,
        "invalid_cache_limit");
      const proof = await verifyDeviceRequest(request, {
        purpose: "text_cache.read",
      });
      const identity = checkedIdentity(proof, "text_cache.read", null);
      const result = await db.prepare(READ_CACHE_PAGE_SQL).bind(
        identity.account_id, before_sequence, before_sequence, limit + 1).all();
      policy(result?.success === true && Array.isArray(result.results),
        "cache_read_unavailable");
      const has_more = result.results.length > limit;
      const records = result.results.slice(0, limit).map(copyPageRecord);
      const last = records.at(-1);
      return {
        records,
        has_more,
        next_before_sequence: last ? last.server_sequence : before_sequence,
        partial_backup: true,
      };
    },
  });
}
