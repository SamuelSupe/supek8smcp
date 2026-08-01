# Changelog

All notable changes to supek8smcp are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. The repository currently records only the v0.1.0 release; no earlier version history is implied.

## [0.1.0] - 2026-08-01

### Added

- Kubernetes Operator support for namespaced `KubernetesMCPServer` resources, with a single-replica HTTPS Streamable HTTP Server and `ClusterIP` Service.
- `ReadOnly`, `SafeWrite`, and `Dangerous` modes with scope, policy, timeout, byte, list, concurrency, and per-identity rate budgets.
- Progressive MCP tools: compact `k8s.help`, signed capability search, bounded `k8s.describe`/`k8s.read`, and the one-time `k8s.plan`/`k8s.commit` write flow.
- Caller-token propagation through TokenReview and delegated Kubernetes API calls, structured `audit_schema=v1` events, Prometheus metrics, and optional monitoring resources.
- Operator-managed shared root CA and serving-leaf certificates, plus validated same-namespace external TLS Secrets, with status conditions and endpoint/CA publication.

### Security and reliability hardening

- Enforced the fixed TokenReview ClusterRole boundary: the Operator can validate and bind only the expected minimal role, while the Server performs TokenReview and never substitutes an Operator credential for the caller.
- Added the dedicated endpoint-namespace trust guidance, Origin-header rejection, managed-resource self-protection, Secret redaction, SafeWrite payload/dry-run checks, and explicit NetworkPolicy ingress behavior.
- Added bounded non-watch resource/discovery/OpenAPI responses, paged list reads, schema field-path-first expansion with a 10,000-node budget and recursive `$ref` termination, bounded logs/exec/attach, and plan-store budgets.
- Added per-identity rate limiting, stable audit outcomes, and failure-safe revision routing: invalid authentication, TLS, configuration, or resource reconciliation leaves the Service without a backend and scales the Server down.
- Hardened TLS key/trust-chain/SAN/usage validation and serving-leaf rotation/root-replacement behavior.
- Added same-name ownership guards: unowned ServiceAccounts, Services, ConfigMaps, Deployments, NetworkPolicies, and managed TLS Secrets are never adopted, deleted, or scaled, and TokenReview binding waits for an owned Server ServiceAccount; CR names are constrained to 63-character lowercase DNS Service labels.
- Kept catalog discovery concurrency safe: partial discovery results are returned without poisoning the shared cache, stale complete snapshots survive partial/failed discovery, and concurrent cold loads do not hold the cache mutex during network discovery.

### Deliberate limitations

- No OAuth, port-forward, `cp`, proxy, evict, drain, TTY, JSON-RPC batch, multi-cluster routing, or multi-replica Server support.

[0.1.0]: https://github.com/samuelsupe/supek8smcp/releases/tag/v0.1.0
