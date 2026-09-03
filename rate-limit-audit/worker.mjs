const DEFAULT_LIMIT = 100;
const DEFAULT_WINDOW_MS = 60_000;
const HARD_MAX_IDENTITIES = 10_000;
const STRICT_CLASSES = new Set([
  "auth-attempt",
  "auth-recovery",
  "mutation",
  "payment-write",
  "job-admission",
]);

function positiveInteger(value, fallback, maximum) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, maximum);
}

function classify(request) {
  const method = request.method.toUpperCase();
  const path = new URL(request.url).pathname.toLowerCase();
  if (/\/(login|token|session)(\/|$)/.test(path)) return "auth-attempt";
  if (/\/(recover|recovery|reset-password)(\/|$)/.test(path)) return "auth-recovery";
  if (/\/(payment|payments|ledger)(\/|$)/.test(path) && method !== "GET") return "payment-write";
  if (/\/(jobs|queue|admit)(\/|$)/.test(path) && method !== "GET") return "job-admission";
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) return "mutation";
  return "public-read";
}

function encodeComponents(components) {
  const encoder = new TextEncoder();
  const encoded = components.map((component) => encoder.encode(component));
  const size = encoded.reduce((total, value) => total + 8 + value.byteLength, 0);
  const output = new Uint8Array(size);
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const value of encoded) {
    view.setBigUint64(offset, BigInt(value.byteLength), false);
    offset += 8;
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

async function opaquePrincipal(secret, components) {
  const encodedSecret = new TextEncoder().encode(secret);
  if (encodedSecret.byteLength < 32) return null;
  const key = await crypto.subtle.importKey(
    "raw",
    encodedSecret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, encodeComponents(components)),
  );
  return Array.from(signature, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function coordinatorObservation(binding, observation) {
  if (!binding || typeof binding.fetch !== "function") return null;
  const response = await binding.fetch("https://rate-limit.internal/v1/audit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(observation),
  });
  if (!response.ok) throw new Error("coordinator-unavailable");
  const value = await response.json();
  return value && value.allowed === false;
}

export function createAuditLimiter(options = {}) {
  const now = options.now ?? (() => Date.now());
  const maximum = positiveInteger(
    options.maxIdentities,
    HARD_MAX_IDENTITIES,
    HARD_MAX_IDENTITIES,
  );
  const buckets = new Map();

  function observeLocal(key, limit, windowMs) {
    const timestamp = now();
    let bucket = buckets.get(key);
    if (!bucket || timestamp - bucket.startedAt >= windowMs) {
      bucket = { count: 0, startedAt: timestamp };
    }
    bucket.count += 1;

    if (buckets.has(key)) buckets.delete(key);
    while (buckets.size >= maximum) {
      const oldest = buckets.keys().next().value;
      if (oldest === undefined) break;
      buckets.delete(oldest);
    }
    buckets.set(key, bucket);
    return bucket.count > limit;
  }

  return Object.freeze({
    size: () => buckets.size,
    async evaluate(request, env = {}) {
      const operationClass = classify(request);
      const ip = request.headers.get("cf-connecting-ip");
      const secret = env.RATE_LIMIT_HMAC_KEY;
      if (!ip || typeof secret !== "string") {
        return Object.freeze({
          auditOnly: true,
          enforced: false,
          wouldDeny: false,
          operationClass,
          source: "skipped",
          reason: !ip ? "missing-cloudflare-client-ip" : "missing-hmac-key",
        });
      }

      const url = new URL(request.url);
      const namespace = String(env.RATE_LIMIT_NAMESPACE ?? "edge");
      const principal = await opaquePrincipal(secret, [
        "ores.rl.edge.v1",
        namespace,
        operationClass,
        ip,
        request.method.toUpperCase(),
        url.pathname,
      ]);
      if (!principal) {
        return Object.freeze({
          auditOnly: true,
          enforced: false,
          wouldDeny: false,
          operationClass,
          source: "skipped",
          reason: "hmac-key-too-short",
        });
      }

      const limit = positiveInteger(env.RATE_LIMIT_AUDIT_LIMIT, DEFAULT_LIMIT, 1_000_000);
      const windowMs = positiveInteger(
        env.RATE_LIMIT_AUDIT_WINDOW_MS,
        DEFAULT_WINDOW_MS,
        31 * 24 * 60 * 60 * 1_000,
      );
      let wouldDeny = observeLocal(principal, limit, windowMs);
      let source = "isolate";
      let reason = wouldDeny ? "local-audit-threshold" : "within-audit-threshold";

      if (STRICT_CLASSES.has(operationClass)) {
        try {
          const coordinatorWouldDeny = await coordinatorObservation(
            env.RATE_LIMIT_COORDINATOR,
            {
              contractVersion: "ores.rate-limit.edge-audit.v1",
              auditOnly: true,
              namespace,
              operationClass,
              principal,
              cost: 1,
            },
          );
          if (coordinatorWouldDeny !== null) {
            wouldDeny ||= coordinatorWouldDeny;
            source = "coordinator";
            reason = coordinatorWouldDeny ? "coordinator-would-deny" : reason;
          }
        } catch {
          source = "coordinator-error";
          reason = "coordinator-observation-failed";
        }
      }

      return Object.freeze({
        auditOnly: true,
        enforced: false,
        wouldDeny,
        operationClass,
        source,
        reason,
      });
    },
  });
}

const limiter = createAuditLimiter();

export default {
  async fetch(request, env) {
    const decision = await limiter.evaluate(request, env);
    const originResponse =
      env.ORIGIN && typeof env.ORIGIN.fetch === "function"
        ? await env.ORIGIN.fetch(request)
        : await fetch(request);
    const response = new Response(originResponse.body, originResponse);
    response.headers.set("x-ores-rate-limit-mode", "audit");
    response.headers.set(
      "x-ores-rate-limit-would-deny",
      decision.wouldDeny ? "1" : "0",
    );
    response.headers.set("x-ores-rate-limit-source", decision.source);
    return response;
  },
};
