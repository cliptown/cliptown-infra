import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("proxy examples are shadow-only", async () => {
  const [nginx, envoy, haproxy, worker] = await Promise.all([
    readFile(new URL("./proxy/nginx.conf", import.meta.url), "utf8"),
    readFile(new URL("./proxy/envoy.yaml", import.meta.url), "utf8"),
    readFile(new URL("./proxy/haproxy.cfg", import.meta.url), "utf8"),
    readFile(new URL("./worker.mjs", import.meta.url), "utf8"),
  ]);

  assert.match(nginx, /limit_req_dry_run\s+on;/);
  assert.doesNotMatch(nginx, /return\s+429/);
  assert.match(envoy, /filter_enforced:/);
  assert.match(envoy, /numerator:\s*0/);
  assert.match(envoy, /failure_mode_deny:\s*false/);
  assert.doesNotMatch(haproxy, /http-request\s+deny/i);
  assert.match(worker, /auditOnly:\s*true/);
  assert.match(worker, /enforced:\s*false/);
  assert.doesNotMatch(worker, /console\.(log|info|warn|error)/);
});
