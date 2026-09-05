# Changelog

All notable changes to supek8smcp are documented here. This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. The repository currently records releases from v0.1.0 onward; no earlier version history is implied.

## [0.5.0] - 2026-09-05

### Added

- Configurable Server pod `spec.resources`, with CPU/memory defaults and cross-validation of the memory limit against concurrency and input/output budgets.
- Pre-authentication global rate limiting and per-identity concurrent request limits. Streaming operations reserve one global request slot for ordinary calls.
- Credential- and subject-isolated OpenAPI document caching, with a five-minute TTL, a 64-entry limit, and an estimated 32 MiB memory budget.
- Prometheus metrics for request queue and upstream stage latency, upstream request counts, cache outcomes, active requests/streams, plan/cache bytes, and catalog age/degradation.

### Changed

- Discovery refreshes now honor request cancellation, including waiting for an in-progress refresh, and back off for five seconds after a failed or partial refresh. Existing complete snapshots remain available during discovery failures.
- Identical SelfSubjectAccessReviews are reused only within one search; planning and commit continue to perform fresh authorization checks.
- Each identity may occupy at most `ceil(maxConcurrent / 2)` request slots. Watch, followed logs, and exec/attach together are limited to `maxConcurrent - 1` slots.

### Fixed

- Search no longer hides authorization service outages, evaluation failures, or request cancellation as successful empty results.
- Stream-capacity rejection occurs before consuming a remote plan, so a busy server can be retried with the original approved plan.
- Streaming read authorization and default-container resolution are included in the stream timeout.

### Upgrade notes

- Apply the v0.5.0 CRD before upgrading the Operator; Helm does not upgrade existing CRDs automatically.
- `maxConcurrent: 1` now disables streaming with non-retryable `stream_disabled`; set it to at least `2` to use watch, followed logs, or exec/attach.
- Server memory limits must cover `128 MiB + maxConcurrent × (16 MiB + 4 × (maxInputBytes + maxOutputBytes))`. Default budgets require 212 MiB and remain valid with the default 256 MiB limit. Increase `spec.resources.limits.memory` for larger budgets; this sizing check does not replace workload testing.

## [0.4.0] - 2026-08-25

### Added

- Added TokenReview-backed Server readiness: `/readyz` validates the Server's own Kubernetes credential and returns a retryable `tokenreview_unavailable` response when TokenReview access or authentication infrastructure is unavailable.
- `k8s.read` list/watch calls now accept a target `name`; the Server adds an exact `metadata.name` field selector and rejects a conflicting selector. Watches can resume from `resourceVersion`, request Kubernetes bookmarks, and return the latest resource version plus bounded Kubernetes watch error diagnostics.
- When a Pod container is omitted, logs and Dangerous exec/attach resolve `kubectl.kubernetes.io/default-container` and fall back to the first regular container. Remote execution results retain bounded stdout/stderr and an exit code when the Kubernetes stream reports one.

### Changed

- TokenReview `status.error` is now classified as `tokenreview_error` (retryable infrastructure failure) instead of `invalid_token`, so clients do not treat an authentication backend outage as a bad caller credential.
- Catalog refreshes are single-flight. A complete stale catalog remains usable when discovery is partial or fails, and previously issued process-local `cap_` handles remain decodable across successful catalog refreshes; a Server restart still invalidates them.
- Write capability discovery, planning, and commit authorization now require `get` permission on the base resource in addition to the mutating permission, matching the read needed for previews and resource preconditions.
- Structured tool errors may include bounded, operation-specific `details` while retaining the stable `{code, message, retryable}` envelope.

### Fixed

- Continuous log streaming now bounds an individual overlong line instead of allowing it to bypass the configured output byte budget.
- Oversized JSON object requests are consistently rejected as structured HTTP `413 request_too_large` responses, and stateless `DELETE /mcp` remains a clean `204 No Content` path.

### Security

- Name-scoped list/watch authorization now binds the Kubernetes request to `metadata.name`, preserving `resourceNames` RBAC semantics instead of allowing a broader list or watch selector.
- Readiness and delegated authentication preserve TokenReview failure details only as operational diagnostics; audit events continue to exclude caller tokens, capability handles, resource bodies, and commands, while remote output remains bounded by the configured limits.
- Release and container builds now use Go 1.25.13, fixing the reachable standard-library vulnerabilities GO-2026-6218, GO-2026-6090, GO-2026-6089, GO-2026-5972, and GO-2026-5026 reported against Go 1.25.12.

## [0.3.0] - 2026-08-03

### Added

- `k8s.read` now supports `outputMode: summary | table | full`, object-relative `fieldPaths`, and explicit `omitManagedFields` / `omitAnnotations` controls. List and watch reads default to compact summaries; get reads remain full apart from the default metadata omissions.
- Pod summaries expose the operational fields needed for triage: name, namespace, phase, ready containers, restart count, reason, node, and age. Workload, Event, Service, and metrics summaries retain their corresponding high-value status fields.
- `k8s.search` now accepts exact `exactKind`, `exactResource`, `apiGroup`, and `version` filters in addition to the existing query and action filters.
- Tool and HTTP errors now use the stable `{code, message, retryable}` shape so clients can distinguish stop, re-search, and retry decisions.

### Changed

- Capability IDs are compact, opaque, process-local `cap_` handles backed by the Server's capability map instead of signed JSON payloads. Clients must call `k8s.search` again when a handle is unknown after a Server restart.
- `metadata.annotations` and `metadata.managedFields` are omitted recursively from `k8s.read` by default, including nested Pod template metadata. Callers must opt in explicitly when either field is required.
- This is an intentional breaking read-contract change for list/watch callers that depended on full objects without selecting `outputMode: full`.

### Fixed

- `k8s.describe` field-path traversal now follows local `$ref`, `allOf`, `oneOf`, and `anyOf` branches, including paths such as `spec.template.spec.containers` in composed Deployment schemas.
- Stateless `DELETE /mcp` cleanup requests now return `204 No Content` instead of producing harmless 404 session-close noise.

### Security

- Credential-like annotation keys and embedded assignments containing token, key, password, secret, API key, access key, private key, client secret, or credential markers are redacted even when annotations are explicitly requested.
- Existing Secret and ServiceAccount token policies remain in force; the new metadata defaults reduce accidental model-context exposure for every Kubernetes resource kind.

## [0.2.0] - 2026-08-02

### Changed

- `k8s.plan` now returns a six-digit confirmation challenge for every SafeWrite and Dangerous operation, and `k8s.commit` requires both the one-time `planId` and the code repeated by a human in a later user message.
- This is an intentional breaking MCP tool-contract change. Existing write clients must provide `confirmationCode` when upgrading from v0.1.x.

### Security

- Confirmation codes are generated with `crypto/rand`, stored only as plan-bound digests, share the two-minute plan lifetime, and lock the plan after five well-formed incorrect attempts.
- Correct confirmation is identity-bound and atomically consumes the plan before existing policy, RBAC, object-precondition, and execution checks. Audit logs and metric labels exclude plan IDs and confirmation codes.
- The built-in manual and security guidance explicitly state that a code visible to the model is a compliance guard, not cryptographic proof of human approval; verified separation of duties still requires an external approval gateway.

## [0.1.1] - 2026-08-02

### Added

- Added the v0.1.1 Helm chart, with the default image tag following `appVersion`, automatic Linux amd64/arm64 image selection, and CRD retention on Helm uninstall.
- Published direct GitHub Release downloads for Linux x64 (amd64) and ARM64 archives, plus the release `checksums.txt` file.
- Added Helm installation, upgrade, uninstall-order, and single-Operator-per-cluster guidance to the deployment documentation.

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
- Pinned release and container builds to Go 1.25.12 so reachable standard-library security fixes are present in every published artifact.
- Added same-name ownership guards: unowned ServiceAccounts, Services, ConfigMaps, Deployments, NetworkPolicies, and managed TLS Secrets are never adopted, deleted, or scaled, and TokenReview binding waits for an owned Server ServiceAccount; CR names are constrained to 63-character lowercase DNS Service labels.
- Kept catalog discovery concurrency safe: partial discovery results are returned without poisoning the shared cache, stale complete snapshots survive partial/failed discovery, and concurrent cold loads do not hold the cache mutex during network discovery.

### Deliberate limitations

- No OAuth, port-forward, `cp`, proxy, evict, drain, TTY, JSON-RPC batch, multi-cluster routing, or multi-replica Server support.

[0.5.0]: https://github.com/SamuelSupe/supek8smcp/releases/tag/v0.5.0
[0.4.0]: https://github.com/SamuelSupe/supek8smcp/releases/tag/v0.4.0
[0.3.0]: https://github.com/SamuelSupe/supek8smcp/releases/tag/v0.3.0
[0.2.0]: https://github.com/SamuelSupe/supek8smcp/releases/tag/v0.2.0
[0.1.1]: https://github.com/SamuelSupe/supek8smcp/releases/tag/v0.1.1
[0.1.0]: https://github.com/samuelsupe/supek8smcp/releases/tag/v0.1.0
