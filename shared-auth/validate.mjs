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
const provider = { supabase: ["SUPABASE_AUTH_DATABASE_URL", "SUPABASE_ADMIN_DATABASE_URL"], neon: ["NEON_AUTH_DATABASE_URL", "NEON_ADMIN_DATABASE_URL"] };
const roles = {
  webServer: ["customer-auth", provider.supabase[0], provider.neon[0]], apiServer: ["customer-auth", provider.supabase[0], provider.neon[0]],
  adminWebServer: ["admin-auth", provider.supabase[1], provider.neon[1]], adminApiServer: ["admin-auth", provider.supabase[1], provider.neon[1]],
};
check(t.contract === "SharedAuthTopology" && t.version === 1, "invalid contract/version");
check(/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(t.githubOrg ?? ""), "invalid githubOrg");
check(["direct", "ores-middleware"].includes(t.integration), "invalid integration");
for (const [name, keys] of Object.entries(provider)) {
  const p = t[name] ?? {};
  check(p.runtimeOrg === t.githubOrg && p.targetOrg === t.githubOrg, `${name} organizations must exactly equal githubOrg`);
  check(p.placement === "dedicated-org", `${name} must use dedicated-org placement`);
  check(p.authDatabaseUrlEnv === keys[0] && p.adminDatabaseUrlEnv === keys[1], `${name} database settings are not canonical`);
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
for (const path of ["supabase/auth/migrations/202609070001_shared_auth_runtime_identity.sql", "supabase/admin/migrations/202609070002_shared_auth_admin_runtime_identity.sql", "neon/auth/migrations/202609070003_shared_auth_runtime_identity.sql", "neon/admin/migrations/202609070004_shared_auth_admin_runtime_identity.sql"]) {
  const full = resolve(root, path);
  check(existsSync(full), `missing migration ${path}`);
  if (existsSync(full)) {
    const source = readFileSync(full, "utf8");
    check(!/postgres(?:ql)?:\/\//i.test(source), `${path} contains a database URL`);
    check(!/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/i.test(source), `${path} contains a private key`);
  }
}
const source = JSON.stringify(t);
check(!/shared-org-schema|shared-organization-namespace/i.test(source), "shared provider placement is forbidden");
check(!/postgres(?:ql)?:\/\//i.test(source), "topology contains a database URL");
check(!/\"DATABASE_URL\"/.test(source), "generic DATABASE_URL is forbidden");
check(!/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/i.test(source), "topology contains a private key");
if (errors.length) { errors.forEach((error) => console.error(`- ${error}`)); process.exit(1); }
console.log(`validated strict Shared Auth topology for ${t.githubOrg}`);
