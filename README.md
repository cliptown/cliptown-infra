# cliptown-infra

ClipTown-owned GitOps configuration. `argocd/cliptown-monorepo.yaml` is the root Argo CD application and renders the Helm chart at this repository's root from `main`.

## Safety boundary

The repository does not deploy the API until `cliptown-rust-backend.rs` publishes reviewed Kubernetes manifests and a pinned image/release contract on `main`. The proposed child application remains under `examples/` and is excluded from Helm rendering.

Live applications must not use `HEAD`, `latest`, or development branches. Secrets must be supplied through external secret references rather than committed values files.

## Validation

```sh
helm lint . --strict
helm template cliptown-apps .
```

GitHub Actions additionally verifies the root Argo source, rejects floating revisions, and scans for secret-shaped tracked files.
