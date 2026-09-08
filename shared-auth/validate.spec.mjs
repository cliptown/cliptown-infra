import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const validator = resolve(root, "shared-auth/validate.mjs");

function run(repositoryRoot) {
  return spawnSync(process.execPath, [validator], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, SHARED_AUTH_REPOSITORY_ROOT: repositoryRoot },
  });
}

function withFixture(mutate, assertion) {
  const fixtureRoot = mkdtempSync(resolve(tmpdir(), "cliptown-shared-auth-"));
  try {
    for (const directory of ["shared-auth", "supabase/auth", "supabase/admin", "neon/auth", "neon/admin"]) {
      cpSync(resolve(root, directory), resolve(fixtureRoot, directory), { recursive: true });
    }
    mutate(fixtureRoot);
    assertion(run(fixtureRoot));
  } finally {
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
}

function editTopology(fixtureRoot, mutate) {
  const path = resolve(fixtureRoot, "shared-auth/topology.json");
  const topology = JSON.parse(readFileSync(path, "utf8"));
  mutate(topology);
  writeFileSync(path, `${JSON.stringify(topology, null, 2)}\n`);
}

test("accepts the current shared-Supabase and dedicated-Neon topology", () => {
  const result = run(root);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /validated strict Shared Auth topology for cliptown/);
});

test("rejects a premature dedicated Supabase placement", () => {
  withFixture(
    (fixtureRoot) => editTopology(fixtureRoot, (topology) => {
      topology.supabase.runtimeOrg = "cliptown";
      topology.supabase.placement = "dedicated-org";
    }),
    (result) => {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /supabase runtime organization is not canonical/);
      assert.match(result.stderr, /supabase placement is not canonical/);
    },
  );
});

test("rejects a customer credential on the admin plane", () => {
  withFixture(
    (fixtureRoot) => editTopology(fixtureRoot, (topology) => {
      topology.roles.adminApiServer.supabaseDatabaseUrlEnv = "SUPABASE_AUTH_DATABASE_URL";
    }),
    (result) => {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /adminApiServer uses the wrong auth plane/);
    },
  );
});

test("rejects a missing migration", () => {
  withFixture(
    (fixtureRoot) => rmSync(resolve(fixtureRoot, "neon/admin/migrations/202609070001_shared_auth_runtime_policy.sql")),
    (result) => {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /missing migration neon\/admin\/migrations/);
    },
  );
});

test("rejects a credential-shaped value in a migration", () => {
  withFixture(
    (fixtureRoot) => {
      const path = resolve(fixtureRoot, "supabase/auth/migrations/202609070001_shared_auth_runtime_policy.sql");
      writeFileSync(path, `${readFileSync(path, "utf8")}\n-- postgresql://example.invalid/secret\n`);
    },
    (result) => {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /contains a database URL/);
    },
  );
});
