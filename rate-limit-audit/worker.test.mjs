import assert from "node:assert/strict";
import test from "node:test";

import { createAuditLimiter } from "./worker.mjs";

const secret = "0123456789abcdef0123456789abcdef";
function request(ip, path = "/v1/items", method = "GET") {
  return new Request(`https://example.test${path}`, {
    method,
    headers: ip ? { "cf-connecting-ip": ip } : {},
  });
}

test("audit mode records threshold crossings but never enforces", async () => {
  const limiter = createAuditLimiter({ now: () => 1_000 });
  const env = {
    RATE_LIMIT_HMAC_KEY: secret,
    RATE_LIMIT_AUDIT_LIMIT: "1",
    RATE_LIMIT_AUDIT_WINDOW_MS: "60000",
  };
  const first = await limiter.evaluate(request("203.0.113.10"), env);
  const second = await limiter.evaluate(request("203.0.113.10"), env);
  assert.equal(first.wouldDeny, false);
  assert.equal(second.wouldDeny, true);
  assert.equal(second.auditOnly, true);
  assert.equal(second.enforced, false);
});

test("per-isolate identity state is bounded", async () => {
  const limiter = createAuditLimiter({ now: () => 1_000, maxIdentities: 2 });
  const env = { RATE_LIMIT_HMAC_KEY: secret };
  await limiter.evaluate(request("203.0.113.1"), env);
  await limiter.evaluate(request("203.0.113.2"), env);
  await limiter.evaluate(request("203.0.113.3"), env);
  assert.equal(limiter.size(), 2);
});

test("strict coordinator receives only an opaque principal", async () => {
  let body;
  const limiter = createAuditLimiter({ now: () => 1_000 });
  const env = {
    RATE_LIMIT_HMAC_KEY: secret,
    RATE_LIMIT_COORDINATOR: {
      async fetch(_url, init) {
        body = JSON.parse(init.body);
        return Response.json({ allowed: false });
      },
    },
  };
  const decision = await limiter.evaluate(
    request("198.51.100.7", "/v1/login", "POST"),
    env,
  );
  assert.equal(decision.operationClass, "auth-attempt");
  assert.equal(decision.source, "coordinator");
  assert.equal(decision.wouldDeny, true);
  assert.match(body.principal, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(body).includes("198.51.100.7"), false);
  assert.equal(body.auditOnly, true);
});

test("coordinator outages cannot deny in audit mode", async () => {
  const limiter = createAuditLimiter({ now: () => 1_000 });
  const decision = await limiter.evaluate(
    request("198.51.100.8", "/v1/recovery", "POST"),
    {
      RATE_LIMIT_HMAC_KEY: secret,
      RATE_LIMIT_COORDINATOR: {
        async fetch() {
          throw new Error("offline");
        },
      },
    },
  );
  assert.equal(decision.source, "coordinator-error");
  assert.equal(decision.enforced, false);
});

test("missing trusted identity or HMAC key skips observation safely", async () => {
  const limiter = createAuditLimiter();
  const missingIp = await limiter.evaluate(request(null), {
    RATE_LIMIT_HMAC_KEY: secret,
  });
  const missingKey = await limiter.evaluate(request("203.0.113.9"), {});
  assert.equal(missingIp.source, "skipped");
  assert.equal(missingKey.source, "skipped");
  assert.equal(missingIp.enforced, false);
  assert.equal(missingKey.enforced, false);
});
