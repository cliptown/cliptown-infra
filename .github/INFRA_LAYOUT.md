# Infrastructure layout decision

Cliptown is modules-first, but its reusable Terraform child modules remain under `terraform/modules/` rather than being moved to root `modules/`.

Reason: the existing OCI toolkit CI and supporting documentation already treat `terraform/modules/oci-registries` as a stable provider-neutral validation surface. Renaming that path would add churn without changing ownership or composition semantics.

The authoritative layout is declared in `.ores-infra.toml`. Independent test-org checks must resolve `modules_root` and `environments_root` from that file rather than hard-coding a pathname.

Provider-native Neon and Supabase roots remain in their provider directories so external Git integrations can continue to use their expected working directories. Environment roots must not duplicate resources owned by those provider-native roots.
