// Internal Cloudflare Realtime TURN credential issuer. Never expose the
// long-lived TURN token, and never call this from an unauthenticated route.
// Public Worker remains fail-closed. Production requires metered usage limits
// and a reviewed Shared Auth + enrolled device verifier.
const TURN_TTL_SECONDS = 900;
const KEY_ID = /^[A-Za-z0-9_-]{1,128}$/;
const CREDENTIAL_TEXT = /^[A-Za-z0-9._~+-]{1,512}$/;
const TURN_URL = /^(?:stun:stun\.cloudflare\.com:3478|turn:turn\.cloudflare\.com:(?:3478|443|80)\?transport=(?:udp|tcp)|turns:turn\.cloudflare\.com:(?:5349|443)\?transport=tcp)$/;

export class TurnGrantError extends Error {
  constructor(code = "turn_unavailable") {
    super(code);
    this.name = "TurnGrantError";
    this.code = code;
  }
}

function requireCondition(value, code = "turn_unavailable") {
  if (!value) throw new TurnGrantError(code);
}

function authorizedIdentity(proof) {
  const now = Date.now();
  requireCondition(proof && proof.authenticated === true &&
    proof.active_device === true &&
    proof.revocation_checked === true &&
    proof.purpose === "peer_turn.issue" &&
    Number.isSafeInteger(proof.key_epoch) && proof.key_epoch > 0 &&
    Number.isSafeInteger(proof.verified_at_ms) &&
    proof.verified_at_ms <= now + 5_000 &&
    proof.verified_at_ms >= now - 30_000,
  "turn_authority_unavailable");
}

function sanitizedIceServers(value) {
  requireCondition(value && Array.isArray(value.iceServers) &&
    value.iceServers.length >= 1 && value.iceServers.length <= 4);
  let turns = 0;
  const iceServers = value.iceServers.map((entry) => {
    requireCondition(entry && Array.isArray(entry.urls) &&
      entry.urls.length >= 1 && entry.urls.length <= 8);
    const urls = entry.urls.map((url) => {
      requireCondition(typeof url === "string" && TURN_URL.test(url));
      return url;
    });
    const isTurn = urls.some((url) => url.startsWith("turn"));
    if (isTurn) {
      turns += 1;
      requireCondition(typeof entry.username === "string" &&
        CREDENTIAL_TEXT.test(entry.username) &&
        typeof entry.credential === "string" &&
        CREDENTIAL_TEXT.test(entry.credential));
      return {urls, username: entry.username, credential: entry.credential};
    }
    requireCondition(entry.username == null && entry.credential == null);
    return {urls};
  });
  requireCondition(turns >= 1); // STUN alone is not a TURN credential grant.
  return iceServers;
}

/**
 * turnKeyId and turnApiToken come ONLY from Cloudflare Worker secrets.
 * verifyDeviceRequest must use a reviewed auth/device/revocation gate;
 * it must not trust client JSON claiming active device or token validity.
 * request data is never embedded in the Cloudflare TURN API URL.
 */
export function createTurnIssuer({
  turnKeyId, turnApiToken, verifyDeviceRequest, fetchImpl = fetch,
} = {}) {
  requireCondition(typeof turnKeyId === "string" && KEY_ID.test(turnKeyId) &&
    typeof turnApiToken === "string" && turnApiToken.length >= 32 &&
    !turnApiToken.startsWith("REPLACE_") &&
    typeof verifyDeviceRequest === "function" &&
    typeof fetchImpl === "function", "turn_not_configured");

  const endpoint = "https://rtc.live.cloudflare.com/v1/turn/keys/" +
    turnKeyId + "/credentials/generate-ice-servers";

  return Object.freeze({
    async issue(request) {
      const proof = await verifyDeviceRequest(request, {
        purpose: "peer_turn.issue",
      });
      authorizedIdentity(proof);

      let response;
      try {
        response = await fetchImpl(endpoint, {
          method: "POST",
          headers: {
            "Authorization": "Bearer " + turnApiToken,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ttl: TURN_TTL_SECONDS}),
        });
        requireCondition(response && response.status === 201);
        const payload = await response.json();
        return Object.freeze({
          iceServers: sanitizedIceServers(payload),
          ttl_seconds: TURN_TTL_SECONDS,
          cache_control: "no-store",
        });
      } catch (_error) {
        // Fail closed; never leak secret token, issued credentials or
        // upstream error body into logs or API responses.
        throw new TurnGrantError("turn_unavailable");
      }
    },
  });
}
