// D1-backed, account-scoped one-use nonce consumption for signed device
// requests. Account/device identity MUST come from the trusted Shared Auth
// verifier + enrolled-device registry, never from an unverified request.
const ID = /^[A-Za-z0-9:_-]{1,128}$/;
const NONCE = /^[A-Za-z0-9_-]{22,86}$/;
export const MAX_ACTIVE_NONCES_PER_ACCOUNT = 1024;

export const DELETE_EXPIRED_NONCES_SQL =
  "DELETE FROM cloud_cache_request_nonces " +
  "WHERE account_id=? AND expires_at_ms<=?";

export const CONSUME_DEVICE_NONCE_SQL =
  "INSERT INTO cloud_cache_request_nonces " +
  "(account_id,device_id,nonce,expires_at_ms) " +
  "SELECT ?,?,?,? WHERE (SELECT COUNT(*) FROM cloud_cache_request_nonces " +
  "WHERE account_id=? AND expires_at_ms>?)<1024 " +
  "ON CONFLICT(account_id,device_id,nonce) DO NOTHING";

/**
 * D1 batch serializes the account-local expiry prune and bounded INSERT.
 * A nonce is consumed ONLY when D1 reports exactly one inserted row.
 * Duplicate, at-cap, missing metadata, and provider error all fail closed.
 * This store is for cache HTTP requests. A Durable Object signaling room
 * needs its own independently available nonce store for D1-outage P2P.
 */
export function createD1NonceStore(db) {
  if (!db || typeof db.prepare !== "function" ||
      typeof db.batch !== "function") {
    throw new TypeError("D1 nonce store is not configured");
  }
  return async function consumeNonce({account_id,device_id,nonce,expires_at_ms}) {
    const now=Date.now();
    if (!ID.test(account_id) || !ID.test(device_id) ||
        !NONCE.test(nonce) ||
        !Number.isSafeInteger(expires_at_ms) ||
        expires_at_ms <= now || expires_at_ms > now+125_000) {
      return false;
    }
    try {
      const statements = [
        db.prepare(DELETE_EXPIRED_NONCES_SQL).bind(account_id,now),
        db.prepare(CONSUME_DEVICE_NONCE_SQL).bind(
          account_id,device_id,nonce,expires_at_ms,account_id,now),
      ];
      const result = await db.batch(statements);
      return Array.isArray(result) && result.length === 2 &&
        result.every((item)=>item?.success === true) &&
        result[1]?.meta?.changes === 1;
    } catch (_error) {
      return false;
    }
  };
}
