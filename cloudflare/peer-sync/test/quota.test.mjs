import test from "node:test";
import assert from "node:assert/strict";
import {MAX_LOGICAL_BYTES, MAX_TEXT_ITEMS, measuredCharge, planRetention} from "../src/quota.mjs";

const row = (id, sequence, ciphertext_bytes = 2) => ({
  kind: "text", envelope_id: id, server_sequence: sequence, ciphertext_bytes
});

test("zero records is a valid account", () => {
  assert.deepEqual(planRetention([]), {retained: [], evicted: [], retained_count: 0, logical_bytes: 0});
});

test("2,001 encrypted records retain the latest 2,000 only", () => {
  const plan = planRetention(Array.from({length: 2001}, (_, i) => row("clip_" + i, i + 1)));
  assert.equal(plan.retained_count, MAX_TEXT_ITEMS);
  assert.deepEqual(plan.evicted, ["clip_0"]);
});

test("5 MiB cap includes conservative metadata reserve", () => {
  assert.equal(measuredCharge(MAX_LOGICAL_BYTES - 512), MAX_LOGICAL_BYTES);
  const plan = planRetention([row("new", 2, MAX_LOGICAL_BYTES - 512), row("old", 1, 2)]);
  assert.deepEqual(plan.retained, ["new"]);
  assert.deepEqual(plan.evicted, ["old"]);
  assert.equal(plan.logical_bytes, MAX_LOGICAL_BYTES);
});

test("newest-prefix semantics never retain older records after crossing cap", () => {
  const plan = planRetention([
    row("old", 1, 1), row("new", 3, MAX_LOGICAL_BYTES - 1024), row("middle", 2, 1024),
  ]);
  assert.deepEqual(plan.retained, ["new"]);
  assert.deepEqual(plan.evicted, ["middle", "old"]);
});

test("sorting is stable regardless of input order", () => {
  const items = [row("b", 2), row("a", 2), row("z", 1)];
  assert.deepEqual(planRetention(items).retained, planRetention([...items].reverse()).retained);
  assert.deepEqual(planRetention(items).retained, ["b", "a", "z"]);
});

test("reject invalid and non-text data fail closed", () => {
  assert.throws(() => measuredCharge(0));
  assert.throws(() => measuredCharge(MAX_LOGICAL_BYTES));
  assert.throws(() => planRetention([row("same", 1), row("same", 2)]));
  assert.throws(() => planRetention([{...row("file", 1), kind: "file"}]));
  assert.throws(() => planRetention([{...row("bad id!", 1)}]));
  assert.throws(() => planRetention([{...row("not-safe", 1), server_sequence: Number.MAX_SAFE_INTEGER + 2}]));
  assert.throws(() => planRetention([row("bad-bytes", 1, -1)]));
});

test("never trust user-supplied byte accounting", () => {
  const plan = planRetention([{...row("a", 1, 100), stored_bytes: 1}]);
  assert.equal(plan.logical_bytes, 612);
});
