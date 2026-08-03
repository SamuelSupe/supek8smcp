# Security model and boundaries

`supek8smcp` limits what a client can call through the intersection of three controls: the CR's capability ceiling, the request Bearer token's Kubernetes RBAC, and runtime resource/network/time budgets. A denial at any layer denies the request. The MCP Server never lends its own ServiceAccount or Operator privileges to a client.

## Trust boundaries

The request path is:

1. The MCP client sends `Authorization: Bearer <token>` over HTTPS Streamable HTTP.
2. The Server validates the token, user, and groups with Kubernetes TokenReview.
3. The Server creates a kube-apiserver client with that same token and performs the request.
4. The Server intersects CR `scope`/`policy` with Kubernetes RBAC, then applies mode, redaction, and resource limits.

The Kubernetes namespace is a hard trust boundary. A principal that can create a Pod in the Server namespace can usually mount that namespace's TLS Secret or Server ServiceAccount and can forge Service selector labels; Secret `get` permissions or NetworkPolicy alone cannot prevent this indirect access. Put each `KubernetesMCPServer` in a dedicated, restricted endpoint namespace, do not grant ordinary workload identities Pod/Deployment creation there, use `scope.namespaces` for workload namespaces, and allow only explicit MCP clients or gateways through NetworkPolicy. Operator managed labels and MCP self-protection do not replace namespace isolation.

In this authentication path the Operator only creates a Server ServiceAccount and a binding to the fixed `supek8smcp-tokenreviewer` ClusterRole. Its RBAC permits reading and binding that role, not `tokenreviews.create`; it never holds a client Bearer token. Before binding, the Operator verifies that the role contains only `authentication.k8s.io/tokenreviews.create` and is not aggregated. Missing, unverifiable, expanded, or conflicting bindings are removed and `AuthReady=False` is reported. The Server ServiceAccount performs TokenReview; subsequent resource calls still use the original client token.

Controller ownership is a safety boundary for same-name resources. The Operator never adopts, deletes, or scales a same-name ServiceAccount, Service, ConfigMap, Deployment, NetworkPolicy, or managed TLS Secret unless its controller ownerReference points to the current CR. It creates the TokenReview binding only after that owned Server ServiceAccount is present; an ownership conflict fails closed instead of changing the unrelated object.

To prevent browser cross-site credential abuse, the Server rejects requests with an `Origin` header. Use a controlled non-browser MCP client, or a trusted backend proxy that removes the header while retaining TLS, authentication, and audit boundaries.

CR rules therefore describe “at most what is allowed”, not an additional grant. Successful TokenReview does not mean that a token can read every resource. Give every MCP integration its own ServiceAccount, short-lived token, and least-privilege Role/ClusterRole.

## Modes and tools

| Mode | Tools | Main boundary |
| --- | --- | --- |
| `ReadOnly` | `k8s.help`, `k8s.search`, `k8s.describe`, `k8s.read` | The handbook is static; resources are read-only, Pod logs require one-shot `follow=false`, and persistent writes/exec/attach are unavailable. |
| `SafeWrite` | Read-only tools plus `k8s.plan`, `k8s.commit` | Logs remain `follow=false`; every write requires a plan and a six-digit code repeated by a human in a later user message. |
| `Dangerous` | All SafeWrite tools plus `follow=true` logs and bounded non-interactive exec/attach | The same human-code gate applies; streams and remote execution remain bounded; no TTY. |

`k8s.help` is exposed in all modes. With no arguments it returns only a tool index and mode-specific `available` state; a second call using the index's `detailsRequest` loads one tool's full usage. ReadOnly can inspect write-tool documentation, but `k8s.plan`/`k8s.commit` are marked unavailable and are not exposed by that Server. The handbook is local static data and does not run discovery, reads, or writes, but the request still requires TokenReview, identity rate limiting, and `audit_schema=v1` auditing.

`k8s.plan` creates a pending write plan and returns its preview, a high-entropy `planId`, and a six-digit confirmation code. The model must show the preview and code to a human, stop write-tool calls, and wait for the human to repeat that code in a later user message. `k8s.commit` requires both values with the same authorized identity within two minutes. A missing code returns `confirmation_required`; a malformed or nonmatching code returns `invalid_confirmation`. Missing and malformed values do not count as attempts. Each well-formed mismatch does, and the fifth deletes the plan and returns `confirmation_locked`. Correct confirmation atomically consumes the plan before policy, RBAC, generation, UID, resourceVersion, and execution checks, so any later failure requires a new plan. Expired, replayed, identity-mismatched, or changed plans are also rejected. Pending plans remain bounded by 1,024 entries and 64 MiB globally, usually 16 MiB per identity.

The model receives the confirmation code, so the Server cannot prove that a human, rather than the model, supplied it to `k8s.commit`. This is a model-compliance guard against accidental execution, not cryptographic human approval and not protection against a malicious model or prompt injection. Use an external approval gateway or out-of-band approver when separation of duties must be enforced.

When a Kubernetes Role uses `resourceNames`, `k8s.search` must receive the target `name`. The Server includes that name in SelfSubjectAccessReview so named permissions are not misclassified. Each page performs at most 100 SelfSubjectAccessReviews; sparse authorization can yield fewer results than requested, so clients must continue with `nextCursor` instead of amplifying one tool call against kube-apiserver.

`k8s.read` supports one-shot Pod logs (`follow=false`) in every mode. `follow=true` opens a continuous stream only in Dangerous and is bounded by `streamTimeout`, `maxListItems` (log lines), and `maxOutputBytes`.

The first release does not provide OAuth, port-forward, `cp`, proxy, evict, drain, TTY, multi-cluster routing, or multi-replica Servers, and it does not accept JSON-RPC batches. Each MCP HTTP request performs at most one call, preventing legacy batches from bypassing identity rate and global concurrency budgets. Dangerous is not an administrator shell: exec/attach is bounded, non-interactive, and subject to input/output, timeout, and concurrency limits.

## CR capability ceiling

### Scope

`spec.scope.namespaces` limits namespaced resources. The CRD does not apply a namespace default; the Operator sets an omitted value to the CR's namespace in the runtime configuration. `allowClusterScopedRead` controls cluster-scoped reads. Cluster-scoped writes additionally require `allowClusterScopedWrite: true` and `Dangerous` mode. Scope does not replace RBAC or turn a namespaced token into cluster-admin.

Admission also requires `metadata.name` to be at most 63 characters and to match a lowercase DNS Service label: it starts with a letter, ends with a letter or digit, and contains only lowercase letters, digits, and hyphens.

### Policy

`spec.policy.rules` describes an upper bound by API group, resource, and verb. `verbs` may contain Kubernetes verbs or logical actions from `k8s.search`, including `logs`, `scale`, `restart`, `apply`, `exec`, and `attach`. An empty rule set selects conservative mode defaults. Rules only narrow the callable set; the token's Kubernetes authorization is still required. Treat mode/scope/policy changes as permission changes requiring review, audit, and release approval.

The Server rejects MCP attempts to modify its own CR, runtime configuration/CA ConfigMap, TLS Secret, Deployment, Service, ServiceAccount, NetworkPolicy, fixed TokenReview role, or binding. It also rejects any other resource carrying `app.kubernetes.io/managed-by=supek8smcp-operator`; this self-protection cannot be relaxed by CR policy or client RBAC.

SafeWrite checks both the submitted content and the kube-apiserver dry-run result. It rejects direct root/root-group, privileged, cluster-critical PriorityClass, Windows GMSA/ContainerAdministrator, or Unconfined Seccomp/AppArmor settings. `null`, parent/container-list replacement, and omitted fields cannot remove existing non-root, `allowPrivilegeEscalation=false`, read-only root filesystem, capability-drop, security-profile, ServiceAccount, or runtime-class constraints. These checks block known unsafe values and constraint weakening; they do not automatically add Restricted Pod Security settings to new workloads. Enable Pod Security Admission or an equivalent cluster admission policy.

### Secret reads

The default `spec.policy.sensitiveReads` value is `Redact`: Secret data and all annotation values are redacted, preventing annotations such as `kubectl.kubernetes.io/last-applied-configuration` from copying `stringData`. Names, namespaces, labels, type, and other metadata remain readable when policy permits. `Deny` rejects sensitive reads completely. Use `Allow` only for an explicitly controlled case with tighter RBAC, network, and audit scope. Never put Secret values, Bearer tokens, TLS private keys, or exec output in logs, client configuration, or issues.

For every resource kind, `k8s.read` recursively omits `metadata.annotations` and `metadata.managedFields` by default. If a caller explicitly sets `omitAnnotations: false`, annotation names or embedded assignments containing credential markers such as token, password, secret, API key, access key, private key, client secret, or credential are still replaced with `<redacted>`. Rotate any credential that was exposed before this protection was deployed; response redaction cannot revoke an already disclosed value.

## Authentication, authorization, and audit

- Use HTTPS and verify both the CA and server name. Operator-managed CA/leaf certificates are published through `status.caConfigMapName`; a `kubernetes.io/tls` Secret may be referenced instead.
- Put tokens only in the `Authorization` header. Proxies, log collectors, and tracing exporters must explicitly exclude that header; query-string tokens are forbidden.
- TokenReview and subsequent kube-apiserver calls use the same token, so Kubernetes audit sees the real subject. The Server must not substitute a high-privilege Operator identity.
- The Server emits structured `audit_schema=v1` JSON for authentication and every MCP tool call that passes parameter validation. It contains stable Kubernetes user/UID identifiers, tool, API target, decision, stable reason, and latency; it never contains Bearer tokens, plan IDs, confirmation codes, objects, patches, exec commands, stdin, log content, or tool responses.
- Use different ServiceAccounts for teams and automation, set short expirations, and rotate regularly. Removing or disabling an identity should immediately block later requests through TokenReview/RBAC.
- Monitor CR status, Operator/Server logs, Kubernetes audit, and NetworkPolicy events. Keep only necessary subject, request class, result, and latency; do not retain credentials or complete resource contents.

## Resource and network protection

CR `limits` make request/stream/exec timeouts, input/output bytes, list items, concurrency, and per-identity `requestsPerMinute`/`burst` explicit budgets. Exceeding a budget fails the request instead of waiting forever or returning unbounded data. Identity rate limiting is isolated by a stable digest of username and UID after TokenReview; token rotation or TokenReview extras do not create a new bucket. Denials return HTTP `429` and `Retry-After`. This does not replace global `maxConcurrent` or Kubernetes RBAC. CRD defaults and generated Server configuration preserve these values; inspect `<name>-config` after deployment. For high-risk environments, lower `maxOutputBytes`, `maxListItems`, `maxConcurrent`, `requestsPerMinute`, and `burst`.

Kubernetes resource lists default to `outputMode: summary`, cap each upstream page at eight objects, and preserve the Kubernetes `continue` token; callers should use `cursor` for progressive reads. `table` further reduces repeated field names, while `fieldPaths` projects only requested object-relative paths. The delegated dynamic client rejects non-watch resource, discovery, or OpenAPI responses over 8 MiB before output truncation can exhaust Server memory. Watches remain bounded by `streamTimeout`, `maxListItems`, and `maxOutputBytes`.

`k8s.describe` locates `fieldPath` before expanding references and caps one schema expansion at 10,000 nodes. A budget response includes a `truncated` marker. Start with shallow `depth` and an exact `fieldPath` rather than expanding a large CRD schema wholesale.

The CRD bounds byte/list/concurrency fields: `maxInputBytes` 1 KiB–10 MiB, `maxOutputBytes` 1 KiB–50 MiB, `maxListItems` 1–1000, `maxConcurrent` 1–32, `requestsPerMinute` 1–6000, and `burst` 1–1000. Duration fields must parse as Kubernetes durations and be greater than zero. Invalid durations or out-of-range CRs are rejected at API admission. Rate-limit state is in one Server Pod's memory; the first release is single-replica, so there is no cross-replica budget skew.

`networkPolicy.enabled` defaults to true. The generated policy is ingress-only for MCP `8443` and metrics/health `9090`; without selectors it allows same-namespace Pods. `allowedNamespaceSelector` and `allowedPodSelector` narrow sources, and both are intersected when set. The policy declares no Egress, so Server access to kube-apiserver, DNS, and TokenReview depends on other cluster policies. A gateway exposing the endpoint externally must retain TLS, restrict sources, hide `Authorization`, and must not turn the Server into an anonymous public endpoint.

The Service is always `ClusterIP` and each CR has one Server replica. The Deployment uses `Recreate`: compact capability handles and plans are Pod-local, so preventing old/new overlap avoids invalidating a `search` capability, losing a `plan` before `commit`, or keeping an old policy on traffic. A client must search again after a Server restart or an `invalid_capability` response. The Service selects only a Pod revision derived from the current CR UID/generation, Server image, configuration, and TLS materials. Authentication, certificate, configuration, or resource reconciliation failure selects no backend and scales the Deployment to zero. The old policy is not restored until a full reconciliation succeeds. Updates and recovery can briefly be unavailable; `Ready=True` means only that the current revision is serving. Do not scale the Deployment manually or share one external identity without bounds across teams.

## TLS and key handling

With Operator-managed certificates, the leaf private key belongs only in a restricted Secret mounted into the Server; clients receive the CA. With `spec.tls.secretName`, the Secret must be same-namespace and type `kubernetes.io/tls`; the Operator verifies key matching, `ca.crt` trust chain, validity, ServerAuth usage, and `<name>.<namespace>.svc` SAN. Any failure sets `TLSReady=False`. Renewal is owned by the external certificate process. During rotation, confirm that the Server reloads the Secret and that clients refresh their CA/connection pool.

The Operator namespace's `supek8smcp-serving-ca` is the shared root for all managed leaves. It contains `ca.crt` and `ca.key` and has no owner reference from an individual CR. Restrict reads, back it up, and include it in key rotation. The root CA is not replaced before expiry automatically; planned replacement requires deleting or replacing this Secret and refreshing client trust. Only a managed TLS Secret whose controller ownerReference points to the same CR may be validated or rotated; an unowned same-name Secret is rejected and the endpoint fails closed. Deleting the root generates a new root and re-signs owned leaves. Clients must fetch each CR's CA ConfigMap during the rotation window. The managed root is valid for about five years, leaves for about 90 days, and leaves are re-signed with fewer than 30 days remaining; verify that clients can reconnect.

For Secrets, the fixed TokenReview ClusterRole, and dynamic ClusterRoleBindings, the Operator uses live single-object reads rather than a shared informer cache containing every Secret or RBAC object. Its RBAC cannot list or watch Secrets. External TLS rotation is therefore discovered on the roughly five-minute reconciliation period, not by an event. Informers for ServiceAccounts, Services, ConfigMaps, Deployments, and NetworkPolicies watch only Operator-managed labels; reconciliation still reads the API directly to detect and repair label drift without caching every same-kind object in the cluster.

If a diagnostic bundle must be exported, first redact YAML, Secrets, tokens, headers, resource data, and exec output. Store the raw bundle only in controlled encrypted storage with a retention limit.

## Operational security checklist

- [ ] Use verifiable image sources and immutable tags/digests; run with non-root and read-only-root-filesystem cluster baselines where the manifests support them.
- [ ] Keep Operator and Server ServiceAccounts least-privileged; never reuse them for clients.
- [ ] Place the Server in a dedicated restricted namespace; ordinary tenants cannot create Pods there, mount TLS Secrets, or use the Server ServiceAccount.
- [ ] Explicitly review `mode`, `scope`, `policy`, `sensitiveReads`, and limits for every CR.
- [ ] Keep `Redact` by default; enable `Allow` or `Dangerous` only with approval, a short window, and audit.
- [ ] Distribute `ca.crt` read-only, never disable TLS checks, and rotate tokens through a Secret manager.
- [ ] Allow only controlled ingress in NetworkPolicy; separately verify kube-apiserver/DNS Egress and ensure the gateway does not log credentials.
- [ ] Monitor TokenReview failures, 403s, invalid/locked confirmations, plan/commit failures, exec limits, and certificate rotation.
- [ ] Collect `audit_schema=v1` with restricted access; if installing the optional PrometheusRule, tune authentication-failure, authorization-denial, rate-limit, and tool-error thresholds to the baseline.
- [ ] Before CRD removal or deleting a Dangerous CR, export configuration and audit records and confirm the impact.

## Security troubleshooting

- **401:** Check the Bearer header and token expiry/validity; do not “fix” it by substituting an Operator token. **503** means TokenReview/delegated-client unavailability or waiting for `maxConcurrent` beyond `requestTimeout`; use the audit reason to check kube-apiserver connectivity, Server ServiceAccount permissions, and concurrency.
- **403:** Run `kubectl auth can-i` as the same ServiceAccount, then inspect CR scope, policy, and mode. Permission is an intersection, so either side can deny it.
- **TLS error:** Verify `status.caConfigMapName`, CA contents, key matching, trust chain, ServerAuth, SAN/validity, and client ServerName. Any BYO Secret validation failure sets `TLSReady=False`; do not use `-k`.
- **Plan/commit failure:** Check the six-digit format, human-repeated code, five-attempt lockout, two-minute expiry, one-shot state, and identity; create a new plan rather than replaying it.
- **Exec/attach failure:** Confirm Dangerous mode, a valid target, non-interactive input, and timeout/byte/concurrency budgets. TTY and port-forward cannot be enabled by configuration.
