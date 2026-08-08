# cliptown-infra

ClipTown-owned GitOps configuration. `argocd/cliptown-monorepo.yaml` is the root Argo CD application and renders the Helm chart at this repository's root from `main`.

## Safety boundary

The ClipTown API release contract is now published by `cliptown-rust-backend.rs`. The rendered chart contains a **non-production canary** Argo CD child application pinned to both an immutable backend source commit and an immutable GHCR digest.

Live applications must not use `HEAD`, `latest`, development branches, or mutable image tags. Secrets must be supplied through external secret references rather than committed values files.

The canary child application intentionally has no automated sync policy. Before the first manual sync, the `cliptown-canary` namespace must have:

- the reviewed backend `schema/schema.sql` applied to its canary PostgreSQL database;
- Secret `cliptown-api-runtime` with `database-url` and `shared-auth-introspect-secret`;
- ConfigMap `cliptown-api-runtime` with the reviewed HTTPS `shared-auth-base-url` and HTTPS `shared-auth-issuer`;
- cluster/environment ingress, egress NetworkPolicy, and observability wiring appropriate to the canary.

The application-owned canary and rollback procedure lives in the pinned backend revision at `k8s/README.md`. Do not sync the child application until these prerequisites are present; `/readyz` is designed to stay unavailable when the transfer schema is missing.

## Current canary release

- backend source: `c1953e0519e952c682a4e59dc6a931aab7b29cad`
- interface source: `73151bb271c646248d2adca2acfd833dffa6c57a`
- image: `ghcr.io/cliptown/cliptown-rust-backend.rs@sha256:749c4c9020012b4daebdcd04e51e37e47790668274940b5d3a8f9d00f8fd5fa9`
- release workflow: `cliptown/cliptown-rust-backend.rs` Actions run `31283598863`

## Validation

```sh
helm lint . --strict
helm template cliptown-apps .
```

GitHub Actions additionally verifies the root Argo source, the exact canary backend revision and image digest, absence of floating canary references, and repository secret hygiene.
