# Cliptown Shared Auth topology

This directory is the source-controlled contract for incorporating `github.com/shared-auth` across Cliptown. It supersedes the temporary shared-Supabase placement recorded before September 7, 2026.

Production requires exact 1:1:1 identity: `cliptown` GitHub organization, `cliptown` Supabase organization, and `cliptown` Neon organization. Shared provider organizations, schemas inside a shared project, cross-organization credentials, and runtime waivers are invalid production placements. This source contract does not claim the dedicated cloud resources already exist.

Customer web/API processes use only `SUPABASE_AUTH_DATABASE_URL` and `NEON_AUTH_DATABASE_URL`. Admin web/API processes use only `SUPABASE_ADMIN_DATABASE_URL` and `NEON_ADMIN_DATABASE_URL`. Admin and sensitive operations require strict paired proof. Provider disagreement fails closed; an invalid result cannot be ignored because the other provider authenticated.

Applications use exactly one identity path: the pinned official Shared Auth client directly, or `ores-middleware` through its explicit Shared Auth readiness boundary. Product-local human JWT/JWKS verification, raw provider tokens as product authorization, the middleware anonymous default, generic `DATABASE_URL`, and customer/admin fallback are forbidden.

The independent migration tracks are `supabase/auth/migrations`, `supabase/admin/migrations`, `neon/auth/migrations`, and `neon/admin/migrations`. Infrastructure/declarative-migration tooling promotes them; application startup never runs DDL. Provider organizations/projects, credentials, release markers, and catalog read-back evidence must be verified before readiness.

Run `node shared-auth/validate.mjs` to enforce exact organization identity, role keys, strict admin behavior, disagreement denial, migration presence, and secret-free source.
