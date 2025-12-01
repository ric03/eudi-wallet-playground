# eudi-wallet-demo Helm chart

This chart deploys the Spring Boot wallet/issuer demo and a Keycloak instance configured with the OID4VCI/VCI realm export. It is tuned for AWS (services default to `LoadBalancer` with NLB annotations and an optional ALB ingress), but remains portable to any Kubernetes cluster.

## Contents
- Keycloak 26.4.5 with the provided `wallet-demo` realm and oid4vc-vci feature flag
- Single-instance Keycloak defaults to dev-file (embedded) storage; optional PostgreSQL StatefulSet if you turn it on
- Spring Boot wallet (port 3000) with mock issuer, verifier, and credential storage on a PVC
- Secrets for OIDC client secrets and private keys (wallet/verifier/mock-issuer)

## Prerequisites
- Kubernetes cluster (EKS or compatible)
- Helm 3
- Container registry with an image for the wallet (`mvn spring-boot:build-image -Dspring-boot.build-image.imageName=<registry>/<repo>:<tag>`)

## Basic install
```bash
helm install wallet charts/eudi-wallet-demo \
  --set wallet.image.repository=ghcr.io/ba-itsys/eudi-wallet-playground \
  --set wallet.image.tag=1.0.0
```

By default both Keycloak and the wallet expose NLB-backed `LoadBalancer` services. Set `*.ingress.enabled=true` with ALB annotations to terminate TLS at the ingress instead.

## Common values
- `wallet.image.repository` / `wallet.image.tag`: defaults to `ghcr.io/ba-itsys/eudi-wallet-playground:1.0.0`
- `wallet.keycloak.baseUrl`: override the Keycloak URL (defaults to the in-cluster service)
- `wallet.keycloak.clientSecret`: OIDC client secret for `wallet-mock` (stored in a Secret)
- `wallet.persistence`: PVC for credential storage (`/data/credentials`)
- `postgresql.enabled`: optional; defaults to `false` so Keycloak uses dev-file (embedded) storage. Enable and set `keycloak.database.*` if you want Postgres instead.
- `keycloak.hostname`: public hostname if you want Keycloak to generate absolute URLs
- `wallet.mockIssuer.issuerId`: base URL to embed in mock-issuer offers (use external hostname when fronted by ALB/NLB)
- Disable the bundled Keycloak with `keycloak.enabled=false` and set `wallet.keycloak.baseUrl` to your external issuer.
  - When using the default dev-file DB, leave `keycloak.persistence.enabled=false` for ephemeral storage or enable it to persist the embedded database to a PVC.

## AWS notes
- Services default to `service.beta.kubernetes.io/aws-load-balancer-type: nlb`. Remove or override annotations if you use ALB Ingress instead.
- Set `global.storageClass` to your EKS storage class (for example `gp3`) if it differs from the default.
- For TLS offload with ALB add a certificate ARN and host rules under `wallet.ingress` / `keycloak.ingress`.

## Files embedded in the chart
- Keycloak realm: `files/keycloak/realm-export.json`
- Wallet keys: `files/wallet/wallet-keys.json`
- Verifier keys: `files/wallet/verifier-keys.json`
- Mock issuer keys/config: `files/wallet/mock-issuer-keys.json`, `files/wallet/mock-issuer-configurations.json`

Files above are copied into the wallet PVC on first start; later restarts keep any changes (for example, mock-issuer configurations added through the UI).
