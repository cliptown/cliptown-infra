# Audit-only edge and proxy rate limiting

This directory is a non-enforcing pilot for the shared ORES rate-limit contract. Nothing here is referenced by a production deployment.

## Invariants

- The Cloudflare Worker derives a 64-hex opaque principal with Web Crypto HMAC-SHA-256 over length-prefixed components.
- Raw IP addresses are used only transiently at the trusted edge. They are not stored as map keys, sent to the coordinator, logged, traced, or emitted as metric labels.
- Per-isolate state is capped at 10,000 identities and is an advisory signal, never a global atomic counter.
- Authentication, recovery, mutation, payment-write, and job-admission classes may consult a coordinator Service Binding. Coordinator failure still cannot deny while this pilot is in audit mode.
- NGINX uses `limit_req_dry_run on`; Envoy enables observation but fixes `filter_enforced` at 0%; HAProxy tracks request rate without a deny rule.
- The application setting `ORES_MIDDLEWARE_RATE_LIMIT_ENABLED` must remain `false` until a separate reviewed activation change supplies validated trusted-proxy CIDRs, a stable external HMAC key, route budgets, coordinator capacity, reconnect behavior, and low-cardinality telemetry.

Cloudflare Cache API must not be treated as an atomic global counter. A future activation may use it only as a short-lived coordinator-issued denial fast path.

Run the self-contained checks with:

```sh
node --check rate-limit-audit/worker.mjs
node --test rate-limit-audit/*.test.mjs
```
