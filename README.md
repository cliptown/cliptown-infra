# cliptown-infra

ClipTown-owned GitOps configuration. `argocd/cliptown-monorepo.yaml` is the root Argo CD application and renders the Helm chart at this repository's root from `main`.

## Safety boundary

The ClipTown API release contract is now published by `cliptown-rust-backend.rs`. The rendered chart contains a **non-production canary** Argo CD child application pinned to both an immutable backend source commit and an immutable GHCR digest.

Live applications must not use `HEAD`, `latest`, development branches, or mutable image tags. Secrets must be supplied through external secret references rather than committed values files.

The canary child application intentionally has no automated sync policy. The root chart now creates the restricted `cliptown-canary` namespace, the non-secret shared-auth ConfigMap, and the ExternalSecret contract required by the application:

- `shared-auth-base-url = https://auth.oresoftware.dev`
- `shared-auth-issuer = https://auth.oresoftware.dev`
- `shared-auth-introspect-secret` is copied from existing ClusterSecretStore key `dd/shared-auth/introspect-secret`
- `database-url` is copied from dedicated key `dd/cliptown/canary/database-url`

No value for either secret is committed. The remaining operator prerequisite is to seed `dd/cliptown/canary/database-url` in the existing `dd-cluster-secrets` backing store and apply the reviewed backend `schema/schema.sql` to that canary database. Environment ingress, egress NetworkPolicy, and observability wiring must also be reviewed before manual child-app sync.

The application-owned canary and rollback procedure lives in the pinned backend revision at `k8s/README.md`. Do not sync the child application until the database key and schema exist; `/readyz` is designed to stay unavailable when the transfer schema is missing.

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

GitHub Actions verifies the root Argo source, exact canary backend revision and image digest, restricted namespace, shared-auth HTTPS config, external-secret key references, absence of floating canary references, and repository secret hygiene.

## Environment secrets

Secrets live in this repo **encrypted** with [sops](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age):
`env/enc/<dev|prod>.env.enc` is committed; `just env-use <name>` decrypts it to
`env/dec/<name>.env` (gitignored, mode 0600) and symlinks `./.env` to it. The
Nix dev shell provides the tooling, `just env-audit` runs keyless in CI, and
containers decrypt at `docker run` — never at build. See [`env/README.md`](env/README.md).


## Database isolation tests

Run `npm ci --ignore-scripts && npm test` in [`infra-isolation/`](infra-isolation/README.md)
for the canonical/auth/admin infrastructure contract and adversarial tests.
The dedicated GitHub Actions check is offline; live isolation acceptance requires
fresh provider/AWS evidence and explicitly authorized read-only probes. Missing
projects, private endpoints, or evidence remain blocked rather than passing.
