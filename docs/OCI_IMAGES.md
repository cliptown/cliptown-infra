# OCI image build, registry, and Lambda contract

Policy source: <https://github.com/ORESoftware/my-ai/blob/main/AGENTS.md>.

Deployable images must live in an OCI Distribution endpoint: AWS ECR for Lambda/ECS/EKS, Google Artifact Registry for Cloud Run/GKE, Azure Container Registry for Container Apps/AKS, or Docker Hub where its plan fits. Cloudflare R2 is an immutable OCI archive and disaster-recovery copy, not a direct runtime registry.

## Infrastructure

`terraform/modules/oci-registries` provides opt-in ECR, Artifact Registry, ACR, and R2 resources. Every provider switch defaults to disabled. `crossplane/oci-registries.example.yaml` contains provider-native AWS, Google Cloud, and Azure examples. Keep all resources unapplied until provider identity, account/project, region, retention, cost, and rollback are reviewed.

Docker Hub account, organization, visibility, and billing remain account-managed. Never place Docker Hub or cloud credentials in Terraform state.

## Build and publish

`scripts/oci/build-and-push.sh` checksum-verifies and executes the merged central publisher at `zed-pkg/zed-infra@e0454f5d0d8c970dfa206595a48eda5ead382544`. Configuration and credentials enter only through the environment or existing credential helpers. The publisher supports ECR, Docker Hub, Artifact Registry, ACR, and already-authenticated OCI registries, and requests SBOM and provenance attestations.

Portable services default to `linux/amd64,linux/arm64`. `PUSH=false` is a local validation mode and supports exactly one platform because `buildx --load` cannot load an image index; it performs no registry login.

AWS Lambda function images require one architecture per image reference. Set `IMAGE_KIND=lambda` and exactly one of `PLATFORMS=linux/amd64` or `PLATFORMS=linux/arm64`. Multi-architecture Lambda requests fail before registry authentication or Docker side effects.

```bash
REGISTRY_PROVIDER=aws-ecr \
REGISTRY_HOST=123456789012.dkr.ecr.us-east-1.amazonaws.com \
AWS_REGION=us-east-1 \
IMAGE_KIND=lambda \
PLATFORMS=linux/arm64 \
IMAGE_NAME=example/lambda-worker \
IMAGE_TAG="sha-$(git rev-parse --short=12 HEAD)-arm64" \
DOCKERFILE=docker/Dockerfile.rust-lambda \
BUILD_ARG_NAMES=LAMBDA_BIN \
LAMBDA_BIN=lambda-worker \
scripts/oci/build-and-push.sh
```

The Rust template retains only the custom-runtime `bootstrap` executable. The Node template copies `src/lambda` by default and can be redirected with `LAMBDA_SOURCE`. Application and `*-lambda` repositories may provide equally narrow multi-stage Dockerfiles for Go, Bun, Deno, or another reviewed runtime.

## R2 archive boundary

After a successful real-registry push, `R2_ARCHIVE_BUCKET`, `R2_ENDPOINT`, and optional `R2_ARCHIVE_PREFIX` export the complete image to an OCI archive with `skopeo`, write a portable SHA-256 sidecar, and upload both through the R2 S3-compatible endpoint. R2 archival is rejected with `PUSH=false`.

Do not configure Lambda, Cloud Run, Kubernetes, Docker, or containerd to pull directly from R2. A separately reviewed Distribution-compatible service would be required to provide authenticated `/v2/` semantics.

## Validation

```bash
bash -n scripts/oci/build-and-push.sh scripts/oci/test-build-and-push.sh
bash scripts/oci/test-build-and-push.sh
terraform -chdir=terraform/modules/oci-registries init -backend=false -input=false
terraform -chdir=terraform/modules/oci-registries validate
```

The contract suite proves invalid Lambda indexes, invalid build arguments, central-publisher tampering, and R2/local-build contradictions fail before Docker side effects. Live publication and cloud apply remain protected-environment operations using workload identity or approved secret delivery.
