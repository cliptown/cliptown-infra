// Internal proof verifier for protected Cloudflare cache routes.
// The canonical Shared Auth SDK MUST perform introspection using its own
// server-only service credential (introspect(token, audience, scopes)).
// Never parse an unverified JWT locally or trust an account_id from JSON.
// This module is not connected to the public Worker.

const ID = /^[A-Za-z0-9:_-]{1,128}$/;
const NONCE = /^[A-Za-z0-9_-]{22,86}$/;
const HEX_DIGEST = /^[a-f0-9]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const PURPOSES = Object.freeze({
  "text_cache.write": "cliptown:sync:text:write",
  "text_cache.read": "cliptown:sync:text:read",
});
const MAX_CLOCK_SKEW_MS = 5_000;
const MAX_PROOF_LIFETIME_MS = 120_000;
const MAX_PROOF_HEADER_CHARS = 4_096;
const MAX_SEQUENCE = 9_007_199_254_740_990;
const PROOF_FIELDS = Object.freeze([
  "protocol", "purpose", "device_id", "envelope_id", "ciphertext_digest",
  "media_kind", "device_sequence", "key_epoch", "revocation_epoch",
  "issued_at_ms", "expires_at_ms", "nonce", "signature",
]);

export class DeviceAuthError extends Error {
  constructor() {
    super("device_authorization_denied");
    this.name = "DeviceAuthError";
    // No account IDs, token strings, signatures, decrypted data, or key IDs.
  }
}

const deny = () => { throw new DeviceAuthError(); };
const ok = (condition) => { if (!condition) deny(); };

function toBytes(encoded) {
  ok(typeof encoded === "string" && BASE64URL.test(encoded) &&
    encoded.length > 0 && encoded.length <= MAX_PROOF_HEADER_CHARS);
  let bytes;
  try {
    const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
    bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
  } catch (_error) {
    deny();
  }
  // Reject non-canonical base64url to eliminate signature/parser ambiguity.
  const canonical = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  ok(encoded === canonical);
  return bytes;
}

function signedProofFromRequest(request) {
  ok(request instanceof Request);
  const encoded = request.headers.get("x-cliptown-device-proof");
  ok(encoded && encoded.length <= MAX_PROOF_HEADER_CHARS);
  const bytes = toBytes(encoded);
  let parsed;
  try { parsed = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes)); }
  catch (_error) { deny(); }
  ok(parsed && typeof parsed === "object" && !Array.isArray(parsed));
  ok(Object.keys(parsed).length === PROOF_FIELDS.length &&
    PROOF_FIELDS.every((key) => Object.prototype.hasOwnProperty.call(parsed, key)));
  return parsed;
}

function canonicalMessage(proof, account, tenant, application) {
  // JSON array with fixed field order. No unbounded object stringification,
  // alternate ordering, locale encoding or punctuation ambiguity.
  return new TextEncoder().encode(JSON.stringify([
    "cliptown.device_auth.v1", account, tenant, application,
    proof.purpose, proof.device_id, proof.envelope_id,
    proof.ciphertext_digest, proof.media_kind, proof.device_sequence,
    proof.key_epoch, proof.revocation_epoch, proof.issued_at_ms,
    proof.expires_at_ms, proof.nonce,
  ]));
}

async function verifyEd25519(proof, record, account, tenant, application) {
  const jwk = record.public_key_jwk;
  ok(jwk && typeof jwk === "object" && jwk.kty === "OKP" &&
    jwk.crv === "Ed25519" && typeof jwk.x === "string" &&
    !Object.prototype.hasOwnProperty.call(jwk, "d"));
  ok(typeof proof.signature === "string" &&
    /^[A-Za-z0-9_-]{86}$/.test(proof.signature));
  const signature = toBytes(proof.signature);
  ok(signature.length === 64);
  try {
    const key = await crypto.subtle.importKey(
      "jwk", {kty:"OKP", crv:"Ed25519", x:jwk.x, ext:true},
      {name:"Ed25519"}, false, ["verify"],
    );
    return await crypto.subtle.verify(
      {name:"Ed25519"}, key, signature,
      canonicalMessage(proof, account, tenant, application),
    );
  } catch (_error) {
    return false;
  }
}

/**
 * The two mandatory SDK/registry dependencies are *trusted internal services*:
 *  - sharedAuthClient is a pinned official SharedAuthClient with a
 *    server-only service credential, NOT a client-controlled HTTP implementation.
 *  - resolveEnrolledDevice reads the reviewed account-scoped device registry,
 *    including current revocation + key epoch (no client-supplied JWK).
 *  - consumeNonce atomically inserts unique account/device/nonce into D1 or
 *    Durable Object storage; an in-memory Set is TEST-ONLY.
 *
 * No route may call this without a configured, durable nonce implementation.
 */
export function createDeviceAuthorization({
  sharedAuthClient, resolveEnrolledDevice, consumeNonce,
  audience, issuer, tenantId, applicationId,
} = {}) {
  ok(sharedAuthClient && typeof sharedAuthClient.introspect === "function" &&
    typeof resolveEnrolledDevice === "function" &&
    typeof consumeNonce === "function" &&
    typeof audience === "string" && ID.test(audience) &&
    typeof issuer === "string" && issuer.length > 0 &&
    typeof tenantId === "string" && ID.test(tenantId) &&
    typeof applicationId === "string" && ID.test(applicationId));

  return async function verifyDeviceRequest(request, expected) {
    ok(expected && Object.prototype.hasOwnProperty.call(PURPOSES, expected.purpose));
    const rawAuthorization = request?.headers?.get?.("authorization");
    ok(typeof rawAuthorization === "string" &&
      /^Bearer [A-Za-z0-9._~+-]{16,8192}$/.test(rawAuthorization));
    const proof = signedProofFromRequest(request);
    const now = Date.now();
    const write = expected.purpose === "text_cache.write";

    ok(proof.protocol === "cliptown.device_auth.v1" &&
      proof.purpose === expected.purpose &&
      ID.test(proof.device_id) &&
      NONCE.test(proof.nonce) &&
      Number.isSafeInteger(proof.key_epoch) && proof.key_epoch > 0 &&
      Number.isSafeInteger(proof.revocation_epoch) && proof.revocation_epoch >= 0 &&
      Number.isSafeInteger(proof.issued_at_ms) &&
      Number.isSafeInteger(proof.expires_at_ms) &&
      proof.issued_at_ms <= now + MAX_CLOCK_SKEW_MS &&
      proof.issued_at_ms >= now - MAX_PROOF_LIFETIME_MS &&
      proof.expires_at_ms > now &&
      proof.expires_at_ms > proof.issued_at_ms &&
      proof.expires_at_ms - proof.issued_at_ms <= MAX_PROOF_LIFETIME_MS);

    ok(write
      ? proof.media_kind === "text" && ID.test(proof.envelope_id) &&
        HEX_DIGEST.test(proof.ciphertext_digest) &&
        Number.isSafeInteger(proof.device_sequence) &&
        proof.device_sequence > 0 && proof.device_sequence <= MAX_SEQUENCE &&
        proof.envelope_id === expected.envelope_id &&
        proof.ciphertext_digest === expected.digest
      : proof.media_kind === "none" && proof.envelope_id === "" &&
        proof.ciphertext_digest === "" && proof.device_sequence === 0);

    let identity;
    try {
      // Official server SDK introspects with an independent service credential.
      identity = await sharedAuthClient.introspect(
        rawAuthorization.slice(7), audience, [PURPOSES[expected.purpose]],
      );
    } catch (_error) { deny(); }

    const scopes = typeof identity?.scope === "string"
      ? identity.scope.split(" ").filter(Boolean) : [];
    ok(identity?.active === true &&
      identity.sub && ID.test(identity.sub) &&
      identity.iss === issuer && identity.aud === audience &&
      identity.tenant_id === tenantId &&
      identity.application_id === applicationId &&
      identity.actor_kind === "user" && identity.parent_jti == null &&
      Number.isSafeInteger(identity.exp) &&
      identity.exp * 1000 > now &&
      scopes.includes(PURPOSES[expected.purpose]));

    let device;
    try {
      device = await resolveEnrolledDevice({
        account_id: identity.sub, device_id: proof.device_id,
        tenant_id: tenantId, application_id: applicationId,
      });
    } catch (_error) { deny(); }
    ok(device && device.active === true && device.revoked !== true &&
      device.account_id === identity.sub &&
      device.device_id === proof.device_id &&
      device.key_epoch === proof.key_epoch &&
      device.revocation_epoch === proof.revocation_epoch &&
      device.enrollment_verified === true);

    ok(await verifyEd25519(
      proof, device, identity.sub, tenantId, applicationId,
    ));

    // Nonce must be durable and atomic. Failure, replay or unavailability DENY.
    let consumed = false;
    try {
      consumed = await consumeNonce({
        account_id: identity.sub, device_id: proof.device_id,
        nonce: proof.nonce, expires_at_ms: proof.expires_at_ms,
      });
    } catch (_error) { deny(); }
    ok(consumed === true);

    return Object.freeze({
      purpose: expected.purpose, authenticated: true, active_device: true,
      revocation_checked: true, account_id: identity.sub,
      device_id: proof.device_id, key_epoch: proof.key_epoch,
      revocation_epoch: proof.revocation_epoch, verified_at_ms: Date.now(),
      signature_verified: true, verified_envelope_id: proof.envelope_id,
      verified_ciphertext_digest: proof.ciphertext_digest,
      verified_clip_kind: proof.media_kind,
      verified_device_sequence: proof.device_sequence,
      verified_key_epoch: proof.key_epoch,
    });
  };
}
