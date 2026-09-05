# Deployment guide

This guide installs the `supek8smcp` Operator, creates a `KubernetesMCPServer`, and connects an MCP client over HTTPS Streamable HTTP. Examples use `kubectl`, an image registry reachable by the cluster, and a `platform` workload namespace; replace them for your environment.

## Prerequisites

- A Kubernetes cluster and a `kubectl` version that supports `kubectl create token` (use an equivalent short-lived ServiceAccount token flow on older clusters).
- Administrator permission to install the CRD and create namespaces, RBAC, Deployments, Services, ConfigMaps, Secrets, and NetworkPolicies.
- The deployment manifests must provide the fixed `supek8smcp-tokenreviewer` ClusterRole. It lets a Server ServiceAccount create TokenReviews; the Operator creates one corresponding ClusterRoleBinding per CR. The Operator ClusterRole may only `get` and `bind` that fixed `resourceName`; it does not have `tokenreviews.create` and never holds a client Bearer token. The Operator verifies that the role is not aggregated and contains no extra rules. If the role is missing, unverifiable, expanded, or an existing binding points at another role, abnormal bindings are removed and `AuthReady=False` is reported.
- The default v0.5.1 image, `ghcr.io/samuelsupe/supek8smcp:0.5.1`, is public. Pods in the Operator namespace and in every KMCP endpoint namespace must be able to pull that same image. For a private image, the v0.5.1 chart does not distribute or copy registry credentials into generated Server Pods; use node-runtime credentials or another cluster mechanism that lets both the Operator and every generated Server Pod pull it.
- An MCP client that supports Streamable HTTP, a Bearer header, and a custom CA.

## Install the Operator

Build and publish an image:

```bash
export IMG=registry.example.com/platform/supek8smcp:0.5.1
make docker-build IMG="$IMG"
docker push "$IMG"
```

Install the CRD and deploy the Operator:

```bash
make install
make deploy IMG="$IMG"
kubectl -n supek8smcp-system get deploy,pods
```

`make deploy` creates the Operator namespace, RBAC, and Deployment, and writes `IMG` to both the Operator container's `image` and its `--server-image` argument. The install/deploy targets use manifests under `config/crd/bases`, `config/rbac`, `config/manager`, and `config/default`. To review generated changes, run `make manifests` and inspect the YAML; do not edit generated files by hand. Remove an installation with:

```bash
make undeploy
make uninstall
```

Before uninstalling, delete every `KubernetesMCPServer` and wait for its finalizer to remove TokenReview bindings and workloads. If the Operator is stopped first, CRD deletion can remain blocked by that finalizer.

The Operator runs `supek8smcp operator` and must receive `--server-image` or `SUPEK8SMCP_SERVER_IMAGE` for the image it creates for each CR. Defaults are Operator metrics `:8080`, health probe `:8081`, and leader election enabled; the Operator namespace is `POD_NAMESPACE` or `supek8smcp-system` when unset. A Server runs `supek8smcp serve`, reads `/etc/supek8smcp/config/config.json`, serves HTTPS MCP on `:8443` and metrics/health on `:9090`, and reads certificates from `/etc/supek8smcp/tls/tls.crt` and `/etc/supek8smcp/tls/tls.key`. Custom images or manifests must preserve these probe and port contracts.

The Server `/readyz` probe performs a TokenReview with the Server's own Kubernetes credential. It returns `503` with retryable `tokenreview_unavailable` when the TokenReview permission or authentication backend is unavailable, so a Pod is not marked ready while it cannot validate caller tokens; `/healthz` remains a liveness check.

Deleting the CRD deletes its custom resources and Operator-managed workloads. Back up CRs and confirm the retention policy before doing this in production.

## Install with Helm

The v0.5.1 chart is available from the GitHub Release. Install it, or run the same command to upgrade an existing release:

```bash
helm upgrade --install supek8smcp \
  https://github.com/SamuelSupe/supek8smcp/releases/download/v0.5.1/supek8smcp-0.5.1.tgz \
  --namespace supek8smcp-system --create-namespace
kubectl -n supek8smcp-system rollout status deploy/supek8smcp
kubectl -n supek8smcp-system get deploy,pods
```

The chart defaults `image.tag` to `appVersion`, so v0.5.1 pulls `ghcr.io/samuelsupe/supek8smcp:0.5.1`. That image is published as a Linux amd64/arm64 multi-architecture manifest; the node runtime selects the matching architecture automatically. Override `image.repository`, `image.tag`, or `image.digest` only when using a separately published image.

v0.5.1 adds `spec.resources`, memory-budget validation, and identity/streaming concurrency limits. Apply the new CRD below before upgrading. `maxConcurrent: 1` disables streaming, and high-concurrency or large-output configurations may need a higher Server memory limit. Default configurations still satisfy the budget.

The preceding v0.4.0 release extended the read-tool contract: list/watch use compact summaries by default, accept a name-scoped selector for `resourceNames` RBAC, and can resume from `resourceVersion` with bookmark and bounded error diagnostics. Annotations and managed fields are omitted recursively, and capability IDs are short process-local `cap_` handles; concurrent discovery refreshes share one load and retain existing handles during a successful refresh. Clients that require complete list objects must send `outputMode: full`, and clients must call `k8s.search` again after a Server restart. Explicitly requested annotations still redact credential-like keys and assignments. When `container` is omitted, logs and Dangerous exec/attach use the default-container annotation or first regular container and require Pod `get` permission; continuous logs and remote output remain bounded.

v0.2.0 changes the write-tool contract: every SafeWrite/Dangerous `k8s.commit` now requires the `confirmationCode` returned by `k8s.plan` and repeated by a human. Upgrade MCP clients before rolling out the v0.2.0 Server image; v0.1.x commit payloads containing only `planId` are rejected.

Helm's `crds/` mechanism creates the CRD only on the first install; Helm does not upgrade CRDs. Before a chart version upgrade, apply the matching CRD from that release tag/raw URL or from downloaded source, then confirm it is Established before running the Helm upgrade:

```bash
kubectl apply -f https://raw.githubusercontent.com/SamuelSupe/supek8smcp/v0.5.1/config/crd/bases/mcp.supek8smcp.io_kubernetesmcpservers.yaml
kubectl wait --for=condition=Established --timeout=60s crd/kubernetesmcpservers.mcp.supek8smcp.io
```

Helm installs the CRD from the chart's `crds/` directory and retains it when the release is uninstalled. Before uninstalling, delete every `KubernetesMCPServer` (KMCP) in every namespace and wait for the Operator finalizers to finish:

```bash
kubectl get kubernetesmcpservers --all-namespaces
kubectl delete kubernetesmcpservers --all --all-namespaces
helm uninstall supek8smcp --namespace supek8smcp-system
```

Do not run more than one `supek8smcp` Operator release in a cluster; install one cluster-scoped Operator and create namespaced KMCP resources for each endpoint.

Do not layer a Helm install over an existing `make deploy`/Kustomize install: fixed cluster-scoped RBAC objects already exist, so Helm ownership will conflict. To migrate, delete all KMCP and wait for their finalizers, run the old installation's `make undeploy`, verify that the old Operator is gone, and then install the chart. Run `make uninstall` only when deliberate CRD deletion is intended.

## Create a CR

Each `KubernetesMCPServer` is namespaced. The Operator creates one Server replica, one `ClusterIP` Service, and certificate/CA resources. The Server namespace is also the trust boundary for the TLS private key and Service identity: a principal that can create a Pod there may obtain these capabilities by mounting a Secret or forging a Service selector. Use a dedicated, restricted `supek8smcp-servers` namespace and do not grant ordinary tenants Pod/Deployment creation. The example below puts the endpoint there and grants SafeWrite over two workload namespaces:

```bash
kubectl create namespace supek8smcp-servers
```

The minimal read-only sample is [`config/samples/mcp_v1alpha1_kubernetesmcpserver.yaml`](../config/samples/mcp_v1alpha1_kubernetesmcpserver.yaml). This example also shows scope, write policy, and resource budgets:

```yaml
apiVersion: mcp.supek8smcp.io/v1alpha1
kind: KubernetesMCPServer
metadata:
  name: platform-ops
  namespace: supek8smcp-servers
spec:
  mode: SafeWrite
  scope:
    namespaces:
      - platform
      - platform-staging
    allowClusterScopedRead: false
    allowClusterScopedWrite: false
  policy:
    rules:
      - apiGroups: [""]
        resources: ["configmaps", "services"]
        verbs: ["get", "list", "watch", "create", "patch", "update"]
      - apiGroups: ["apps"]
        resources: ["deployments"]
        verbs: ["get", "list", "watch", "patch", "update"]
    sensitiveReads: Redact
  tls: {}
  limits:
    requestTimeout: 30s
    streamTimeout: 60s
    execTimeout: 30s
    maxInputBytes: 262144
    maxOutputBytes: 1048576
    maxListItems: 100
    maxConcurrent: 4
    requestsPerMinute: 120
    burst: 20
  networkPolicy:
    enabled: true
    allowedNamespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: In
          values: [platform, platform-staging]
```

`metadata.name` is admitted only when it is at most 63 characters and is a lowercase DNS Service label: it starts with a letter, ends with a letter or digit, and contains only lowercase letters, digits, and hyphens. Names and labels make auditing and selection predictable. Deployment, ServiceAccount, Service, and NetworkPolicy use the CR name; the configuration and CA ConfigMaps are `<name>-config` and `<name>-ca`; the default managed leaf Secret is `<name>-tls`; the TokenReview ClusterRoleBinding is `supek8smcp-<first 8 bytes of sha256(namespace/name)>`. Managed resources carry:

```text
app.kubernetes.io/name=supek8smcp-server
app.kubernetes.io/instance=<name>
app.kubernetes.io/managed-by=supek8smcp-operator
```

Before reconciling any same-name object, the Operator requires a controller ownerReference to this CR. It never adopts, deletes, or scales an unowned same-name ServiceAccount, Service, ConfigMap, Deployment, NetworkPolicy, or managed TLS Secret. The TokenReview binding is created only after the Server ServiceAccount exists and is owned by this CR; an ownership conflict leaves the endpoint disabled and the Server scaled to zero.

`allowClusterScopedWrite: true` is valid only in `Dangerous` mode. Even when `policy.rules` allows an action, the request Bearer token must have the corresponding Kubernetes RBAC permission; effective permission is the intersection. An empty rule set selects conservative mode defaults and cannot expand token permissions. Besides Kubernetes verbs, `verbs` may contain logical actions returned by `k8s.search`, such as `logs`, `scale`, `restart`, `apply`, `exec`, and `attach`.

If a Role uses `resourceNames`, pass the target `name` to `k8s.search` so its SelfSubjectAccessReview checks the object name. The Server cannot modify its own CR, configuration/CA/TLS, Deployment, Service, ServiceAccount, NetworkPolicy, or TokenReview RBAC objects. All `KubernetesMCPServer` CRs and any other resource with `app.kubernetes.io/managed-by=supek8smcp-operator` are protected as managed resources. Even a permissive Dangerous policy and client RBAC return `managed_resource_denied`.

The generated NetworkPolicy is ingress-only: it covers MCP `8443` and metrics/health `9090`. Without a source selector, same-namespace Pods are allowed. `allowedNamespaceSelector` and `allowedPodSelector` can narrow sources by namespace and Pod labels; setting both takes their intersection. The policy declares no Egress, so kube-apiserver, DNS, and TokenReview egress must be allowed by other cluster policies and firewalls.

Apply and observe the resource:

```bash
kubectl apply -f kubernetesmcpserver.yaml
kubectl -n supek8smcp-servers get kmcp platform-ops -o wide
kubectl -n supek8smcp-servers describe kmcp platform-ops
kubectl -n supek8smcp-servers get deploy,svc,pods,secret,configmap \
  -l app.kubernetes.io/instance=platform-ops
```

Wait for `status.conditions` to contain `Ready=True` and read the actual endpoint from `status.endpoint`. With Operator-managed TLS, `status.caConfigMapName` names the CA ConfigMap clients must trust. A healthy reconciliation also reports `TLSReady=True` and `AuthReady=True`; these conditions mean that resource orchestration is complete, not that a particular client token is authorized.

The Service selector and Server Pod include a revision derived from the CR UID/generation, Server image, configuration, and TLS material. A new revision is not selected until it is ready. If authentication, TLS, configuration, or resource reconciliation fails, the Operator selects a no-backend revision and scales the Server Deployment to zero; the next complete reconciliation reopens the endpoint after the cause is fixed.

## TLS selection and CA distribution

### Operator-managed certificates (default)

When `spec.tls.secretName` is omitted or empty, the Operator creates a shared root CA and creates or rotates the serving leaf certificate. The root CA is not replaced before expiry automatically; planned root replacement requires an operator to delete or replace the shared Secret and refresh client trust. Distribute the ConfigMap named by `status.caConfigMapName` to clients read-only:

```bash
CA_CONFIGMAP="$(kubectl -n supek8smcp-servers get kmcp platform-ops \
  -o jsonpath='{.status.caConfigMapName}')"
kubectl -n supek8smcp-servers get configmap "$CA_CONFIGMAP" \
  -o jsonpath='{.data.ca\.crt}' > ca.crt
```

The Operator namespace retains a shared `supek8smcp-serving-ca` Secret (`ca.crt`/`ca.key`) that is not owned by an individual CR. Treat it as long-lived key material: restrict reads and back it up. Managed leaves always chain to the current Operator CA. Only a managed TLS Secret whose controller ownerReference points to the same CR may be validated or rotated; an unowned same-name `<name>-tls` Secret is rejected and the endpoint fails closed. Deleting the root Secret creates a new root and re-signs owned leaves; clients must refresh each CA ConfigMap. Deleting a CR or running `make undeploy` does not remove this shared CA automatically; schedule a client CA refresh if you deliberately rotate it.

The managed root CA is valid for about five years and a serving leaf for about 90 days. A leaf is reissued when fewer than 30 days remain. Clients only need to continue trusting the CA ConfigMap, but connection pools must be able to establish a new TLS connection after rotation.

Applications and scripts should re-read the ConfigMap on CA rotation. Never copy the leaf private key to an MCP client. For certificate failures, inspect Operator events, ConfigMap/Secret presence, and the mounted version in the Server Pod.

To avoid listing, watching, or caching every Secret in the cluster, an external TLS Secret is read as one object and checked on roughly a five-minute reconciliation period. Do not assume a Secret event triggers an immediate update; wait for the next complete reconciliation and confirm that the Deployment TLS hash changed.

### Use an existing TLS Secret

Set `spec.tls.secretName` to a same-namespace Secret that follows the Kubernetes TLS convention:

```yaml
spec:
  tls:
    secretName: platform-ops-tls
```

The Secret must be type `kubernetes.io/tls` and contain `tls.crt`, `tls.key`, and `ca.crt`. The Operator verifies key matching, the `ca.crt` trust chain, validity, ServerAuth usage, and the `<name>.<namespace>.svc` SAN. Any failure sets `TLSReady=False` and prevents a Ready Server. The private key is not written to CR status; your certificate process owns renewal. Clients still use `ca.crt`, which the Operator publishes through `status.caConfigMapName`.

## Bearer tokens and client connection

Create a separate ServiceAccount and least-privilege RBAC binding per integration; do not reuse an administrator token:

```bash
kubectl -n platform create serviceaccount mcp-client
kubectl create rolebinding mcp-client-read \
  --namespace platform \
  --serviceaccount platform:mcp-client \
  --clusterrole view
TOKEN="$(kubectl -n platform create token mcp-client --duration=1h)"
```

Send a short-lived token in `Authorization: Bearer <token>`. The Server performs TokenReview and then calls kube-apiserver with that same token, so `policy.rules` cannot grant extra Kubernetes permissions. Inject tokens through a Secret manager and configure expiry and rotation.

Use `status.endpoint`; the in-cluster shape is usually:

```text
https://<service>.<namespace>.svc:8443/mcp
```

Configure the CA, Bearer header, and Streamable HTTP transport. Do not disable TLS verification, put a token in a URL query, or let a reverse proxy log the `Authorization` header.

## Runtime checks

```bash
kubectl -n supek8smcp-servers get kmcp platform-ops \
  -o jsonpath='{.status.endpoint}{"\n"}{.status.caConfigMapName}{"\n"}'
kubectl -n supek8smcp-servers get events --sort-by=.lastTimestamp \
  --field-selector involvedObject.name=platform-ops
kubectl -n supek8smcp-system logs deploy/supek8smcp-controller-manager \
  -c manager --tail=200
```

Check the Operator Deployment first, then the CR `Ready` condition, Service endpoints, and Server Pod. MCP clients should record request IDs and error categories, never tokens, Secret contents, or sensitive exec output.

## Audit, identity rate limiting, and alerts

Every authentication and every MCP tool call that passes parameter validation writes one `audit_schema=v1` JSON event to Server stdout. Events include the subject, tool, Kubernetes target, allow/deny/error decision, stable reason, and latency; they exclude tokens, plan IDs, resource/patch bodies, exec commands, stdin, Pod logs, and response bodies:

```bash
kubectl -n supek8smcp-servers logs deploy/platform-ops --tail=200 | \
  jq 'select(.msg == "MCP security audit")'
```

`limits.requestsPerMinute` and `limits.burst` create an independent token bucket for each authenticated Kubernetes identity; defaults are `120` and `20`. Exhaustion returns HTTP `429` with `Retry-After`. `maxConcurrent` remains a global Server guard; both limits apply.

Each identity can occupy at most `ceil(maxConcurrent / 2)` request slots. Watches, followed logs, and exec/attach together can occupy at most `maxConcurrent - 1` slots, reserving capacity for short calls; `maxConcurrent: 1` therefore rejects these streaming operations with non-retryable `stream_disabled`. Exhausted stream capacity returns retryable `stream_capacity` before consuming a remote plan, allowing the original commit to be retried. A pre-authentication global token bucket multiplies the per-identity rate and burst by `maxConcurrent`; it returns `global_rate`, while excess identity concurrency returns `identity_concurrency`.

`spec.resources.requests` / `spec.resources.limits` configure the Server pod resources. Omitted CPU/memory requests default to `50m` / `64Mi`, and limits to `500m` / `256Mi`. Startup and Operator configuration generation require a memory limit of at least `128 MiB + maxConcurrent × (16 MiB + 4 × (maxInputBytes + maxOutputBytes))`; default budgets require 212 MiB. This conservative capacity check reserves space for plans, schema caching, decoded objects, and serialization, but does not replace workload testing. Raise `spec.resources.limits.memory` when increasing concurrency or byte budgets; invalid combinations produce a configuration error.

Catalog refresh respects tool cancellation, backs off for five seconds after failures, and serves an older complete snapshot when available. Search filters only explicit policy/RBAC denials and propagates authorization service failures. Identical SSARs are reused within one search; commits always reauthorize. OpenAPI documents are cached for five minutes per reviewed identity and exact token hash, up to 64 entries and an estimated 32 MiB. Tokens are not retained in this cache, and describe still performs authorization.

The Server exposes these security and reliability metrics on `9090/metrics`:

- `supek8smcp_authentication_attempts_total`
- `supek8smcp_rate_limit_rejections_total`
- `supek8smcp_audit_events_total`
- `supek8smcp_tool_calls_total`
- `supek8smcp_tool_duration_seconds`
- `supek8smcp_stage_duration_seconds`
- `supek8smcp_upstream_requests_total`
- `supek8smcp_cache_requests_total`
- `supek8smcp_active_requests` / `supek8smcp_active_streams`
- `supek8smcp_plan_store_bytes` / `supek8smcp_schema_cache_bytes`
- `supek8smcp_catalog_age_seconds` / `supek8smcp_catalog_degraded`

`supek8smcp_tool_calls_total` labels `result` as `ok`, policy/RBAC `denied`, or infrastructure/execution `error`, so reliability alerts do not mistake expected permission denials for service failures.

With Prometheus Operator, optionally install the repository's ServiceMonitor and alert rule:

```bash
kubectl apply -k config/monitoring
```

These resources are not included by default in `make deploy`, which keeps clusters without `monitoring.coreos.com` CRDs deployable. If your Prometheus selects ServiceMonitor/PrometheusRule objects by label, add the cluster's required labels. The default NetworkPolicy allows same-namespace sources only; for Prometheus in another namespace, explicitly allow its `9090` scrape with `allowedNamespaceSelector`/`allowedPodSelector` instead of disabling the whole policy. Tune alert thresholds against the normal traffic baseline.

## Troubleshooting

### CR never becomes Ready

Inspect `kubectl describe kmcp <name> -n <namespace>` and Operator logs. Common causes:

- `spec.tls.secretName` is missing, has the wrong type, lacks `tls.crt`/`tls.key`/`ca.crt`, or fails key, trust-chain, validity, ServerAuth, or SAN checks.
- Image pull failure, insufficient ServiceAccount/RBAC, or NetworkPolicy blocking Operator/Server access to kube-apiserver.
- `allowClusterScopedWrite` does not match `mode`, or another field fails CRD validation.

### Client TLS handshake fails

Confirm that the client trusts the CA in `status.caConfigMapName` (or the external Secret's issuing CA), that ServerName matches the certificate SAN, and that the URL points to the intended Service. Do not hide the issue with `-k`; inspect validity and the mounted certificate.

### 401/403 or a tool permission error

401 normally means a missing, expired, or invalid Bearer token; a browser `Origin` header is also rejected. 403 means at least one of token RBAC, CR `scope`, or `policy.rules` denies the action. Run `kubectl auth can-i` as the same identity, check namespace and API group/resource/verb spelling, then wait for reconciliation and re-read `status.conditions` after CR changes.

Resource lists read at most eight upstream objects per call and return `metadata.continue` as the next `k8s.read` `cursor`. Even when `maxListItems` is larger, loop with the cursor so one list cannot exhaust model context or Server memory. Non-watch delegated resources, discovery, and OpenAPI responses also have an 8 MiB hard limit; narrow selectors or schema scope when they are exceeded.

When TokenReview or the delegated client is temporarily unavailable, the Server returns `503` with `tokenreview_error` or `delegated_client_error` in audit/metrics; it does not misreport an infrastructure outage as invalid credentials. Check kube-apiserver connectivity and the Server ServiceAccount's `tokenreviews.create` permission rather than repeatedly changing the client token. Waiting for `maxConcurrent` beyond `requestTimeout` also returns `503` with reason `concurrency_timeout`.

### A write is denied or commit fails

SafeWrite/Dangerous writes must call `k8s.plan`, show its preview and six-digit code to a human, then wait for the human to repeat the code in a later user message. Call `k8s.commit` within two minutes with both `planId` and `confirmationCode` using the same identity. Missing/malformed codes are rejected; five incorrect six-digit attempts invalidate the plan. Plans are one-shot, and a correctly confirmed plan is consumed even if a later safety or Kubernetes check fails. Expiration, replay, or token/request-context mismatch requires a new plan. ReadOnly never exposes write tools. SafeWrite still compares the pre-change object with the kube-apiserver dry-run result and rejects unsafe constraint removal. Because the model can see the code, use an external approval gateway when verified human approval is required.

### exec/attach fails

Only Dangerous supports bounded, non-interactive exec/attach. Check the target Pod/container, input/output size, concurrency, and `execTimeout`. TTY, port-forward, `cp`, proxy, evict, and drain are outside the first release.

### Continuous Pod logs are denied

`k8s.read` supports one-shot `follow=false` logs in every mode. `follow=true` is a continuous stream allowed only in Dangerous. For `mode_denied`, use one-shot logs or confirm Dangerous mode and check `streamTimeout`, `maxOutputBytes`, `maxListItems`, and concurrency budgets.

## Uninstall and data retention

Delete each `KubernetesMCPServer` first and confirm its Server, Service, NetworkPolicy, and certificate resources are removed as intended. Then run `make undeploy`, followed by `make uninstall` to delete the CRD. Export YAML and audit records before the CRD deletion in production.
