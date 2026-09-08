import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = process.env.SHARED_AUTH_REPOSITORY_ROOT
  ? resolve(process.env.SHARED_AUTH_REPOSITORY_ROOT)
  : resolve(dirname(fileURLToPath(import.meta.url)), "..");
const t = JSON.parse(readFileSync(resolve(root, "shared-auth/topology.json"), "utf8"));
const errors = [];
const check = (ok, message) => { if (!ok) errors.push(message); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const providers = {
  supabase: {
    authDatabaseUrlEnv: "SUPABASE_AUTH_DATABASE_URL",
    adminDatabaseUrlEnv: "SUPABASE_ADMIN_DATABASE_URL",
    runtimeOrg: "oresoftware",
    placement: "shared-org-schema",
  },
  neon: {
    authDatabaseUrlEnv: "NEON_AUTH_DATABASE_URL",
    adminDatabaseUrlEnv: "NEON_ADMIN_DATABASE_URL",
    runtimeOrg: t.githubOrg,
    placement: "dedicated-org",
  },
};
const roles = {
  webServer: ["customer-auth", providers.supabase.authDatabaseUrlEnv, providers.neon.authDatabaseUrlEnv],
  apiServer: ["customer-auth", providers.supabase.authDatabaseUrlEnv, providers.neon.authDatabaseUrlEnv],
  adminWebServer: ["admin-auth", providers.supabase.adminDatabaseUrlEnv, providers.neon.adminDatabaseUrlEnv],
  adminApiServer: ["admin-auth", providers.supabase.adminDatabaseUrlEnv, providers.neon.adminDatabaseUrlEnv],
};
check(t.contract === "SharedAuthTopology" && t.version === 1, "invalid contract/version");
check(/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(t.githubOrg ?? ""), "invalid githubOrg");
check(["direct", "ores-middleware"].includes(t.integration), "invalid integration");
for (const [name, expected] of Object.entries(providers)) {
  const p = t[name] ?? {};
  check(p.runtimeOrg === expected.runtimeOrg, `${name} runtime organization is not canonical`);
  check(p.targetOrg === t.githubOrg, `${name} target organization must exactly equal githubOrg`);
  check(p.placement === expected.placement, `${name} placement is not canonical`);
  check(p.authDatabaseUrlEnv === expected.authDatabaseUrlEnv && p.adminDatabaseUrlEnv === expected.adminDatabaseUrlEnv, `${name} database settings are not canonical`);
  check(/^[A-Za-z_][A-Za-z0-9_]*$/.test(p.schema ?? ""), `${name} schema is invalid`);
}
check(t.supabase?.schema === t.neon?.schema, "provider schemas must match");
check(t.requestPolicy?.requireBothProvidersConfigured === true, "both providers are required");
check(["availability-first", "strict-paired"].includes(t.requestPolicy?.customerMode), "invalid customer mode");
check(t.requestPolicy?.adminMode === "strict-paired" && t.requestPolicy?.sensitiveMode === "strict-paired", "admin/sensitive must be strict-paired");
check(t.requestPolicy?.rejectProviderDisagreement === true, "provider disagreement must fail closed");
for (const [name, [plane, supabase, neon]] of Object.entries(roles)) {
  check(same(t.roles?.[name], { dataPlane: plane, supabaseDatabaseUrlEnv: supabase, neonDatabaseUrlEnv: neon }), `${name} uses the wrong auth plane`);
}
check(Array.isArray(t.auditRepositories) && t.auditRepositories.length === 5 && new Set(t.auditRepositories).size === 5 && t.auditRepositories.every((repo) => repo.startsWith(`${t.githubOrg}/`)), "auditRepositories must contain five unique same-org repositories");
const migrations = [
  ["supabase", "customer-auth", providers.supabase.authDatabaseUrlEnv, "oresoftware", "supabase/auth/migrations/202609070001_shared_auth_runtime_policy.sql"],
  ["supabase", "admin-auth", providers.supabase.adminDatabaseUrlEnv, "oresoftware", "supabase/admin/migrations/202609070001_shared_auth_runtime_policy.sql"],
  ["neon", "customer-auth", providers.neon.authDatabaseUrlEnv, t.githubOrg, "neon/auth/migrations/202609070001_shared_auth_runtime_policy.sql"],
  ["neon", "admin-auth", providers.neon.adminDatabaseUrlEnv, t.githubOrg, "neon/admin/migrations/202609070001_shared_auth_runtime_policy.sql"],
];
for (const [providerName, dataPlane, databaseUrlEnv, runtimeOrg, path] of migrations) {
  const full = resolve(root, path);
  check(existsSync(full), `missing migration ${path}`);
  if (existsSync(full)) {
    const source = readFileSync(full, "utf8");
    check(source.includes(`'${providerName}'`), `${path} is missing provider ${providerName}`);
    check(source.includes(`'${dataPlane}'`), `${path} is missing data plane ${dataPlane}`);
    check(source.includes(`'${databaseUrlEnv}'`), `${path} is missing database setting ${databaseUrlEnv}`);
    check(source.includes(`'${runtimeOrg}'`), `${path} is missing runtime organization ${runtimeOrg}`);
    check(source.includes(`'${t.githubOrg}'`), `${path} is missing target organization ${t.githubOrg}`);
    check(!/postgres(?:ql)?:\/\//i.test(source), `${path} contains a database URL`);
    check(!/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/i.test(source), `${path} contains a private key`);
  }
}
const source = JSON.stringify(t);
check(!/postgres(?:ql)?:\/\//i.test(source), "topology contains a database URL");
check(!/\"DATABASE_URL\"/.test(source), "generic DATABASE_URL is forbidden");
check(!/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/i.test(source), "topology contains a private key");
if (errors.length) { errors.forEach((error) => console.error(`- ${error}`)); process.exit(1); }
console.log(`validated strict Shared Auth topology for ${t.githubOrg}`);
