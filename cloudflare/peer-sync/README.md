# ClipTown peer-first synchronization on Cloudflare

Status: **foundation only; fail-closed; not a deployed or production-enabled sync service**.
Decision date: 2026-11-22. Scope: user-authorized encrypted TEXT clipboard history only.

## Decision

Each Flutter or native Rust device owns an independent, encrypted local SQLite
history and replay-safe operation log. No shared SQLite file, plaintext cloud
search, or upload of plaintext clip content is allowed.

Use only Cloudflare services for new ClipTown-hosted sync infrastructure:

| Purpose | Service |
| --- | --- |
| User-facing HTTPS API / authorization enforcement | Workers |
| Per-account encrypted text pivot/cache | D1 |
| Per-account presence, WebRTC signaling, backpressure | Durable Objects with hibernating WebSockets |
| ICE NAT traversal / relay fallback | Cloudflare Realtime STUN and time-limited TURN |
| Optional future encrypted image/file objects | R2; explicitly out of text-sync activation |
| Operational metrics | Workers/Cloudflare analytics; metadata only |

The existing Shared Auth issuer and official device-enrollment/revocation trust
contracts remain authoritative at initial integration. Hosting all new ClipTown
sync services on Cloudflare does not authorize replacing identity controls,
accepting client-asserted account IDs, or embedding a Shared Auth service secret
in a client. The edge must use the reviewed protected verification/SDK path and
check both session and device revocation.

## Cache quotas and data semantics

- Strictly text envelopes: reject image bytes, file blobs, local file paths,
  plaintext vectors, auth tokens, and 3FA/app-vault records.
- Per account: retain the newest contiguous prefix of at most **2,000**
  immutable encrypted text envelopes and at most **5 * 1024 * 1024 logical
  charged bytes**, whichever limit is reached first.
- Each item is charged the actual **server-measured ciphertext byte length +
  512 reserved metadata bytes**. Client-reported sizes are ignored. This is a
  logical account quota, **not a promise of <=5 MiB physical D1 disk use**;
  database indexes, SQLite pages, keys, and WAL add overhead.
- Server-issued monotonic sequence, then bytewise envelope ID DESC is the
  deterministic ordering. Oldest overflow envelopes are evicted from the **D1
  cache only**. Eviction MUST NOT propagate as a clipboard delete to devices.
- A single authoritative per-account sequencer must assign sequence and commit
  the insert and retention SQL in one **D1 batch transaction**. A missed/failed
  prune must cause the whole write to fail; an independent asynchronous prune
  or best-effort cloud eviction is not sufficient. Read/modify/write from
  separate Workers without account serialization is forbidden.
- The current SQL table is a proposed encrypted-cache desired state; the
  checked-in parameterized prune query is runtime SQL, not a D1 migration.
- The cache is not an authoritative global operation log and cannot by itself
  prove a device is fully up to date. Cross-device convergence uses the
  existing cliptown-interfaces sync-protocol-v1 contract and cliptown-sync
  replay/conflict engine, including immutable operation identities and
  monotonic cursors.
- Tombstones, per-device acknowledgments, revocation epochs, and anti-replay
  checkpoints need separately budgeted, bounded control-plane retention;
  dropping all tombstones after 2,000 clips can resurrect deleted content.
- If no peer holds the desired older history, a cloud restore can recover only
  the retained subset. Do not call this a full backup.

## Peer connectivity

- Same LAN: authenticated local discovery and direct peer channel; no
  dependence on Cloudflare for already paired devices.
- Nearby: reuse signed/encrypted Bluetooth LE proximity transport and its
  existing explicit-consent rules.
- Internet: authenticate with the **same enrolled device identity**, then
  connect to an account-scoped Durable Object for ephemeral presence and
  WebRTC offer/answer/ICE signaling. Use direct data channels when available.
  Cloudflare Realtime TURN is a metered fallback and its credentials must be
  short-lived, minted only by a protected Worker using a server-only token.
- Signaling contains no clipboard ciphertext or keys. TURN may relay the
  end-to-end encrypted data channel; a relay is not a trust authority.
- After Durable Object hibernation/restart, membership is derived only from
  existing authenticated socket attachments; never rely on volatile in-memory
  membership for device authorization. Bound connections, message rates,
  payload bytes, session lifetime, and peer fanout per account.
- Bind offer/answer/ICE, session ID, sender, recipient, encryption epoch, and
  expiry to authenticated identities. Require signature and replay checks for
  the sync envelope, including when switching LAN/BLE/WebRTC transports.
- iOS background restrictions mean an offline phone is not an always-on
  backup node. Allow a desktop/NAS as a user-selected full-history peer.

## Outage contract

1. D1 down, Worker/DO + Realtime available: existing peers can signal and
   connect; cache read/write reports unavailable without clearing local queues.
2. Signaling down: established peer links can continue; LAN/BLE remain usable.
   New remote WebRTC setup may fail unless an existing, independent path exists.
3. Full Cloudflare outage: do not claim new remote internet sessions can be
   established. Existing direct connections, LAN and BLE may continue.
4. Every other device offline: the D1 cache is the only hosted fallback, with
   at most the stated clipped quota; show a partial-restore warning.
5. Revoked device: block new signaling, cache and TURN grants; already
   established peer sessions must receive authenticated revocation and close.
   Test race windows across revocation, offline operation and key rotation.

## Security/release admission

This foundation intentionally exposes only a non-ready /healthz and returns
503 for all sync routes and Durable Object requests. No secrets, actual Cloudflare
database IDs, auth bypass or synthetic 200 success may be committed.

Before activation, require all of the following:
1. Freeze additive peer signal/cache contracts in cliptown-interfaces, with
   Rust/Dart/TypeScript fixtures and no incompatible changes to sync v1.
2. Integrate official protected Shared Auth verification, authenticated account
   and device ownership, fresh revocation state, monotonic signed requests,
   nonce/replay windows, E2EE envelope validation and key rotation.
3. Implement account-serialized D1 transactional push/pull with strict
   read/write ownership, bounded pagination, cursor-gap detection,
   deletion lifecycle and quota enforcement. Adversarially test multi-account
   isolation and simultaneous pushes.
4. Implement per-account hibernating Durable Object signaling, then generate
   Realtime TURN ICE credentials using a Worker secret; test rate limits,
   WebSocket expiry, reconnect and stale/revoked sessions.
5. Connect both independent desktop products and all supported Flutter
   targets through the same signed/encrypted cliptown-sync operation envelope,
   with LAN/BLE/WebRTC transport switching and offline durable queues.
6. Test real device-to-device transfers, mobile foreground/background lifecycle,
   hostile NATs, Cloudflare/D1 outages and cross-client restore; use production
   provider canaries only with operator approval. Mocked CI is not real-radio
   or real-TURN evidence.
7. Validate exact PR Git tree SHA, actual guest/client integration tests,
   cost/abuse limits, security redaction and deploy rollback. Do not mark
   unexecuted, skipped or pending gates as PASS.

Cloudflare's 5 GB D1 free-tier allocation is account-wide across users; it is
not 5 GB per ClipTown customer. TURN relay has usage-based outbound costs.
Cost controls and measured traffic are release blockers, not optional polish.

## Foundation verification

From the repository root:

    node --check cloudflare/peer-sync/src/index.mjs
    node --test cloudflare/peer-sync/test/quota.test.mjs
    python3 -B cloudflare/peer-sync/test/check_d1_contract.py

Do not copy wrangler.example.jsonc into a deployable config until real D1
identifiers, migration ownership, provider secrets and authentication gates
have been reviewed and tested.

## Current implementation slice: internal adapters, not live APIs

The optional Cloudflare provider adapters now exist as internal ES modules:

- src/cache_d1.mjs prepares D1 encrypted-text insert, server-issued account
  receipt allocation, retention pruning and receipt return as one db.batch
  transaction. A separately reviewed verifier must establish account/device
  ownership, revocation, ciphertext signature and exact digest binding.
  Input clip data cannot supply the account_id used for D1 access.
- src/cache_sql.mjs contains parameterized write and bounded page queries;
  migration 0002_account_sequences.sql preserves cloud receipt positions
  across cache eviction.
- Async JavaScript ciphertext is cloned before the first await. Unlike Rust
  borrowed slices, a Uint8Array may be modified by its owner. Regression
  tests mutate the source buffer immediately and ensure the database sees
  the original owned snapshot.
- src/turn_grants.mjs creates fixed 900-second Cloudflare Realtime TURN
  credentials using a server-only token and enrolled device authorization.
  Unsupported relay URLs, revoked credentials and upstream errors fail closed.
  The long-term TURN token is never sent to any client.
- The Worker and Durable Object still return HTTP 503 for all sync and TURN
  requests. No provider adapter is called from a public route. There is no
  live ingestion, active WebSocket signaling or actual TURN credential grant.
- This PR does not provision a D1 database, Durable Object, provider
  credentials or any Cloudflare production deployment.

### Remaining hard gates

1. Supply the actual reviewed Shared Auth and enrolled-device cryptographic
   verifier. Tests with injected verifiers prove guard decisions but are not
   real cryptographic or external identity-provider evidence.
2. Add a compact durable mutation-receipt/high-watermark control plane.
   An old immutable envelope retried *after D1 cache eviction* must not
   reappear as a new clip. Same-record duplicate replay and immutable digest
   conflicts are tested, but long-expired replay remains a release blocker.
3. Verify a signed text media-kind and exact ciphertext digest together.
   Opaque ciphertext alone cannot prove the concealed media type.
4. Build authorized hibernating Durable Object signaling with replay/rate
   limits and approved device revocation checks.
5. Enforce Cloudflare TURN issue rate limits and spending budgets, then
   execute live TURN/D1 canary and outage tests before activation.
6. Implement encrypted sync client adapters on both Flutter and native Rust
   desktops, with tombstone, offline and partial-restore validation.

Local checks:

    node --test cloudflare/peer-sync/test/*.test.mjs
    python3 -B cloudflare/peer-sync/test/check_d1_contract.py
    python3 -B cloudflare/peer-sync/test/check_d1_batch.py

These are offline tests and neither access user data nor create provider
resources.
