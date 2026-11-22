import test from "node:test";
import assert from "node:assert/strict";
import {createEncryptedTextCache, CacheAccessError} from "../src/cache_d1.mjs";
import {ALLOCATE_SEQUENCE_SQL, APPEND_TEXT_SQL, PRUNE_ACCOUNT_SQL,
  LOOKUP_RECEIPT_SQL, READ_CACHE_PAGE_SQL,
  ADVANCE_DEVICE_WATERMARK_SQL, READ_DEVICE_WATERMARK_SQL} from "../src/cache_sql.mjs";

class StubD1 {
  constructor() {
    this.prepared = []; this.batches = []; this.existing = null;
    this.page = []; this.watermark = null;
  }
  prepare(sql) {
    const db = this;
    return {
      bind(...params) {
        const statement = {sql, params};
        db.prepared.push(statement);
        return {
          ...statement,
          async first() {
            return sql === READ_DEVICE_WATERMARK_SQL ? db.watermark : db.existing;
          },
          async all() { return {success: true, results: db.page}; },
        };
      },
    };
  }
  async batch(statements) {
    this.batches.push(statements);
    if (this.fail) throw new Error("injected D1 transaction failure");
    return [
      {success: true, results: []}, {success: true, results: []},
      {success: true, results: []}, {success: true, results: []},
      {success: true, results: [{
        envelope_id: "clip_1", server_sequence: 9,
      }]},
    ];
  }
}

function verified(args, overrides = {}) {
  return {
    authenticated: true, active_device: true, revocation_checked: true,
    purpose: args.purpose, account_id: "account_a", device_id: "device_a",
    key_epoch: 3, revocation_epoch: 4, verified_at_ms: Date.now(),
    signature_verified: true, verified_clip_kind: "text",
    verified_key_epoch: 3, verified_device_sequence: 1,
    verified_envelope_id: args.envelope_id,
    verified_ciphertext_digest: args.digest, ...overrides,
  };
}

const input = () => ({
  kind: "text", envelope_id: "clip_1", ciphertext: new Uint8Array([1, 2, 3]),
});
const req = {request_id: "private_test_only"};
const denied = (code) => (error) =>
  error instanceof CacheAccessError && error.code === code;

test("unconfigured or missing authorization fails closed", async () => {
  const db = new StubD1();
  assert.throws(() => createEncryptedTextCache(db, null), denied("cache_authority_unavailable"));
  const cache = createEncryptedTextCache(db, async () => null);
  await assert.rejects(cache.append(req, input()), denied("cache_authority_unavailable"));
  await assert.rejects(cache.readPage(req), denied("cache_authority_unavailable"));
  assert.equal(db.prepared.length, 0);
  assert.equal(db.batches.length, 0);
});

test("revoked, stale, wrong purpose or unsigned ciphertext never hits D1", async () => {
  for (const change of [
    {active_device: false}, {revocation_checked: false},
    {verified_at_ms: Date.now() - 90_000},
    {purpose: "text_cache.read"}, {signature_verified: false},
    {verified_ciphertext_digest: "a".repeat(64)},
    {account_id: "bad account with space"},
    {verified_clip_kind: "file"}, {verified_device_sequence: 0},
    {verified_key_epoch: 2}, {revocation_epoch: -1},
  ]) {
    const db = new StubD1();
    const cache = createEncryptedTextCache(db,
      async (_request, args) => verified(args, change));
    await assert.rejects(cache.append(req, input()));
    assert.equal(db.prepared.length, 0);
  }
});

test("no client-supplied account, receipt, file or spoofed size accepted", async () => {
  const db = new StubD1();
  const cache = createEncryptedTextCache(db,
    async (_request, args) => verified(args));
  for (const change of [
    {kind: "file"}, {account_id: "account_b"}, {stored_bytes: 1},
    {server_sequence: 9}, {ciphertext: new Uint8Array()},
    {ciphertext: new Uint8Array(5 * 1024 * 1024)},
    {envelope_id: "bad/path"},
  ]) {
    await assert.rejects(cache.append(req, {...input(), ...change}));
  }
  assert.equal(db.prepared.length, 0);
});

test("atomic 5-statement batch binds signed device watermark and owned ciphertext", async () => {
  const db = new StubD1();
  const cache = createEncryptedTextCache(db,
    async (_request, args) => verified(args));
  const source = input();
  const pending = cache.append(req, source);
  source.ciphertext.fill(0); // mutation immediately after synchronous copy
  const result = await pending;
  assert.deepEqual(result, {server_sequence: 9, duplicate: false});
  assert.equal(db.batches.length, 1);
  const [device, sequence, append, prune, receipt] = db.batches[0];
  assert.equal(device.sql, ADVANCE_DEVICE_WATERMARK_SQL);
  assert.deepEqual(device.params, ["account_a", "device_a", 1]);
  assert.equal(sequence.sql, ALLOCATE_SEQUENCE_SQL);
  assert.equal(append.sql, APPEND_TEXT_SQL);
  assert.equal(prune.sql, PRUNE_ACCOUNT_SQL);
  assert.equal(receipt.sql, LOOKUP_RECEIPT_SQL);
  assert.deepEqual(append.params[2], new Uint8Array([1, 2, 3]));
  assert.equal(append.params[0], "account_a");
  assert.equal(append.params[8], 1);
  assert.equal(append.params[9], "account_a");
  assert.equal(append.params[4], 3);
  assert.equal(append.params[5], 515);
  assert.equal(append.params[7], "device_a");
  assert.equal(prune.params[0], "account_a");
  assert.equal(prune.params[1], "account_a");
  assert.equal(append.params[3].length, 64);
});

test("identical replay uses immutable receipt, conflicting replay rejects", async () => {
  const db = new StubD1();
  const proof = verified({purpose: "text_cache.write",
    envelope_id: "clip_1", digest: ""});
  const cache = createEncryptedTextCache(db,
    async (_request, args) => verified(args));
  const fresh = await cache.append(req, input());
  const digest = db.batches[0][2].params[3];
  db.existing = {
    envelope_id: "clip_1", device_id: "device_a",
    ciphertext_digest: digest, ciphertext_bytes: 3,
    device_sequence: 1, server_sequence: 9,
  };
  assert.deepEqual(await cache.append(req, input()),
    {server_sequence: 9, duplicate: true});
  assert.equal(db.batches.length, 1);
  db.existing = {...db.existing, ciphertext_digest: "0".repeat(64)};
  await assert.rejects(cache.append(req, input()), denied("cache_immutable_conflict"));
  assert.equal(db.batches.length, 1);
  assert.deepEqual(fresh, {server_sequence: 9, duplicate: false});
});

test("ambiguous lost response accepts only committed identical receipt", async () => {
  const db = new StubD1();
  db.fail = true;
  const cache = createEncryptedTextCache(db, async (_req, args) => verified(args));
  await assert.rejects(cache.append(req, input()), denied("cache_commit_unavailable"));
  const digest = db.batches[0][2].params[3];
  db.existing = {
    device_id: "device_a", ciphertext_digest: digest,
    ciphertext_bytes: 3, device_sequence: 1, server_sequence: 10,
  };
  assert.deepEqual(await cache.append(req, input()),
    {server_sequence: 10, duplicate: true});
});

test("read page is account-scoped, bounded, partial and returns owned bytes", async () => {
  const db = new StubD1();
  db.page = [{
    envelope_id: "clip_1", server_sequence: 10,
    ciphertext: [42, 43], ciphertext_bytes: 2,
    ciphertext_digest: "f".repeat(64), device_id: "device_a",
  }];
  const cache = createEncryptedTextCache(db, async (_req, args) => verified(args));
  const page = await cache.readPage(req, {before_sequence: 11, limit: 1});
  assert.equal(page.partial_backup, true);
  assert.equal(page.next_before_sequence, 10);
  assert.equal(page.has_more, false);
  assert.deepEqual(page.records[0].ciphertext, new Uint8Array([42, 43]));
  assert.equal(db.prepared.at(-1).sql, READ_CACHE_PAGE_SQL);
  assert.deepEqual(db.prepared.at(-1).params, ["account_a", 11, 11, 2]);
  db.page[0].ciphertext[0] = 99;
  assert.equal(page.records[0].ciphertext[0], 42);
  await assert.rejects(cache.readPage(req, {limit: 101}),
    denied("invalid_cache_limit"));
  await assert.rejects(cache.readPage(req, {before_sequence: -1}),
    denied("invalid_cache_cursor"));
});

test("evicted replay is denied by device watermark even without clip receipt", async () => {
  const db = new StubD1();
  db.watermark = {last_device_sequence: 7}; // original clip was evicted
  const cache = createEncryptedTextCache(db,
    async (_request, args) => verified(args, {verified_device_sequence: 7}));
  await assert.rejects(cache.append(req, input()), denied("cache_device_replay"));
  assert.equal(db.batches.length, 0);

  const fresh = createEncryptedTextCache(db,
    async (_request, args) => verified(args, {verified_device_sequence: 8}));
  const result = await fresh.append(req, input());
  assert.equal(result.server_sequence, 9);
  assert.equal(db.batches.length, 1);
  assert.deepEqual(db.batches[0][0].params, ["account_a", "device_a", 8]);
});

test("duplicate receipt binds signed device sequence, not merely matching ciphertext", async () => {
  const db = new StubD1();
  const cache = createEncryptedTextCache(db,
    async (_request, args) => verified(args, {verified_device_sequence: 9}));
  db.existing = {
    envelope_id: "clip_1", device_id: "device_a",
    device_sequence: 8, ciphertext_digest: "a".repeat(64),
    ciphertext_bytes: 3, server_sequence: 5,
  };
  await assert.rejects(cache.append(req, input()), denied("cache_immutable_conflict"));
  assert.equal(db.batches.length, 0);
});

test("watermark after ambiguous failed response rejects stale signed replay", async () => {
  const db = new StubD1();
  db.fail = true;
  // Simulates another concurrent request having committed the watermark
  // while the exact clip has been evicted from the cache.
  db.batch = async (statements) => {
    db.batches.push(statements);
    db.watermark = {last_device_sequence: 15};
    throw new Error("injected transaction race");
  };
  const cache = createEncryptedTextCache(db,
    async (_request, args) => verified(args, {verified_device_sequence: 14}));
  await assert.rejects(cache.append(req, input()), denied("cache_device_replay"));
});
