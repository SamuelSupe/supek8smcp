# 部署指南

本文说明如何安装 `supek8smcp` Operator、创建 `KubernetesMCPServer`，并让
MCP 客户端通过 HTTPS Streamable HTTP 访问它。示例假设使用 `kubectl`、一个
可被集群拉取的镜像仓库，以及 `platform` 命名空间；请按实际环境替换。

## 前置条件

- Kubernetes 集群可用，客户端版本支持 `kubectl create token`（老版本可用
  等价的短期 ServiceAccount Token 方案）。
- 具备安装 CRD、创建 namespace/RBAC/Deployment/Service/ConfigMap/Secret 和
  NetworkPolicy 的管理员权限。
- 部署清单需提供 `supek8smcp-tokenreviewer` ClusterRole（允许 Server ServiceAccount
  创建 TokenReview；Operator 为每个 CR 创建对应 ClusterRoleBinding）。Operator
  的 ClusterRole 只允许对这个固定 `resourceName` 使用 `get`、`bind`，本身不拥有
  `tokenreviews.create`，也不会代持客户端 Bearer Token。Operator 会校验固定角色
  不是聚合角色且不含任何额外规则；角色缺失、不可校验、被扩权，或已有绑定
  指向其他角色时会撤掉异常绑定并报告 `AuthReady=False`。
- 默认的 v0.4.0 镜像 `ghcr.io/samuelsupe/supek8smcp:0.4.0` 是公开的。Operator 命名空间
  以及每个 KMCP 端点命名空间中的 Pod 都必须能够拉取同一个镜像。若使用私有镜像，
  v0.4.0 chart 不会向生成的 Server Pod 分发或复制 registry 凭据；请通过节点运行时凭据
  或其他集群机制，确保 Operator Pod 与所有生成的 Server Pod 都能拉取该镜像。
- MCP 客户端支持 Streamable HTTP、Bearer header 和自定义 CA。

## 安装 Operator

从源码构建并发布镜像：

```bash
export IMG=registry.example.com/platform/supek8smcp:0.4.0
make docker-build IMG="$IMG"
docker push "$IMG"
```

然后安装 CRD 并部署 Operator：

```bash
make install
make deploy IMG="$IMG"
kubectl -n supek8smcp-system get deploy,pods
```

`make deploy` 创建 Operator 的命名空间、RBAC 和 Deployment，并把 `IMG` 同时
写入 Operator 容器的 `image` 与 `--server-image` 参数。安装/部署目标分别对应
`config/crd/bases`、`config/rbac`、`config/manager` 和 `config/default` 下的
清单。预览或审计变更时，可以先
运行 `make manifests`，再检查生成的 YAML；不要手工编辑生成文件。卸载时：

```bash
make undeploy
make uninstall
```

卸载前先删除各命名空间中的 `KubernetesMCPServer`，等待其 finalizer 清理
TokenReview binding 和工作负载；否则 Operator 已停止时，CRD 删除可能因
finalizer 无法完成。

Operator 容器运行 `supek8smcp operator`，必须通过 `--server-image` 或
`SUPEK8SMCP_SERVER_IMAGE` 指定它为每个 CR 创建的 Server 镜像。默认参数为：
Operator metrics `:8080`、health probe `:8081`、leader election 开启；
Operator 命名空间取 `POD_NAMESPACE`，未设置时为 `supek8smcp-system`。Server
容器运行 `supek8smcp serve`，默认读取 `/etc/supek8smcp/config/config.json`，
在 `:8443` 提供 HTTPS MCP、在 `:9090` 提供 metrics/health；证书路径为
`/etc/supek8smcp/tls/tls.crt` 和 `/etc/supek8smcp/tls/tls.key`。如通过自定义
镜像或清单覆盖这些参数，必须保持探针和端口契约一致。

Server 的 `/readyz` 探针会使用 Server 自己的 Kubernetes 凭据执行 TokenReview。
当 TokenReview 权限或认证后端不可用时，它返回带有可重试
`tokenreview_unavailable` 的 `503`，因此无法校验调用者 Token 时 Pod 不会被标记为
Ready；`/healthz` 仍然只负责存活检查。

卸载 CRD 会删除该 CRD 下的自定义资源及其由 Operator 管理的工作负载；在
生产集群执行前先备份 CR，并确认保留策略。

## 使用 Helm 安装

v0.4.0 chart 发布在 GitHub Release。首次安装或升级已有 release 都使用同一条命令：

```bash
helm upgrade --install supek8smcp \
  https://github.com/SamuelSupe/supek8smcp/releases/download/v0.4.0/supek8smcp-0.4.0.tgz \
  --namespace supek8smcp-system --create-namespace
kubectl -n supek8smcp-system rollout status deploy/supek8smcp
kubectl -n supek8smcp-system get deploy,pods
```

chart 默认将 `image.tag` 设为 `appVersion`，因此 v0.4.0 会拉取
`ghcr.io/samuelsupe/supek8smcp:0.4.0`。该镜像发布为 Linux amd64/arm64 多架构
manifest，节点运行时会自动选择匹配的架构。只有使用另行发布的镜像时才需要覆盖
`image.repository`、`image.tag` 或 `image.digest`。

v0.4.0 扩展了读工具契约：list/watch 默认使用紧凑摘要，支持按名称约束以保持
`resourceNames` RBAC 语义，并可从 `resourceVersion` 续传，返回 bookmark 和有界错误诊断。
annotations 和 managedFields 仍递归剔除，能力 ID 是进程内短 `cap_` 句柄；并发 discovery
刷新共享一次加载，成功刷新期间保留已有句柄。需要完整列表对象的客户端必须显式发送
`outputMode: full`；Server 重启后必须重新调用 `k8s.search`。显式请求 annotations 时仍会
脱敏带有凭据特征的 key 和赋值。省略 `container` 时，日志和 Dangerous exec/attach 使用
默认容器注解或第一个常规容器，并要求 Pod `get` 权限；持续日志和远程输出仍受字节上限约束。

v0.2.0 修改了写工具契约：SafeWrite/Dangerous 的每次 `k8s.commit` 都必须携带
`k8s.plan` 返回、并由人类复述的 `confirmationCode`。部署 v0.2.0 Server 镜像前应先
升级 MCP 客户端；仅包含 `planId` 的 v0.1.x commit 请求会被拒绝。

Helm 的 `crds/` 机制只会在首次 install 时创建 CRD，upgrade 不会升级 CRD。升级 chart
版本前，应先从对应 release tag/raw URL 或已下载源码应用 CRD，再确认其状态为
Established，之后才执行 Helm upgrade：

```bash
kubectl apply -f https://raw.githubusercontent.com/SamuelSupe/supek8smcp/v0.4.0/config/crd/bases/mcp.supek8smcp.io_kubernetesmcpservers.yaml
kubectl wait --for=condition=Established --timeout=60s crd/kubernetesmcpservers.mcp.supek8smcp.io
```

Helm 从 chart 的 `crds/` 目录安装 CRD，并在卸载 release 时保留该 CRD。卸载前必须
删除所有命名空间中的 `KubernetesMCPServer`（KMCP），并等待 Operator finalizer 完成：

```bash
kubectl get kubernetesmcpservers --all-namespaces
kubectl delete kubernetesmcpservers --all --all-namespaces
helm uninstall supek8smcp --namespace supek8smcp-system
```

一个集群不要运行多个 `supek8smcp` Operator release；只安装一个集群级 Operator，
再为各个端点创建 namespaced KMCP 资源。

不要把 Helm 安装直接叠加到已有的 `make deploy`/Kustomize 安装上：固定的集群级 RBAC
对象已经存在，Helm ownership 会冲突。迁移时先删除全部 KMCP 并等待 finalizer，再执行
旧安装的 `make undeploy`，确认旧 Operator 已移除后再安装 chart。只有明确要删除 CRD
时才执行 `make uninstall`。

## 创建 CR

每个 `KubernetesMCPServer` 是 namespaced 资源，Operator 为它创建一个单副本
MCP Server、一个 `ClusterIP` Service，以及证书/CA 相关资源。Server 所在
命名空间也是 TLS 私钥和 Service 身份的安全边界：能在其中创建 Pod 的主体可通过
挂载 Secret 或伪造 selector 间接取得这些能力。因此生产环境应先创建专用、受限的
`supek8smcp-servers` 命名空间，不给普通租户 Pod/Deployment 创建权限。下面的配置
在该专用命名空间部署端点，并给 `platform` 工作负载命名空间提供 SafeWrite：

```bash
kubectl create namespace supek8smcp-servers
```

仓库中的最小只读样例位于
`config/samples/mcp_v1alpha1_kubernetesmcpserver.yaml`；以下示例额外展示
范围、写策略和资源预算。

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

`metadata.name` 只有在长度不超过 63 个字符、且符合小写 DNS Service label 时才会被接纳：必须以字母开头，以字母或数字结尾，只能包含小写字母、数字和连字符。资源名称与标签便于审计和选择：Deployment、ServiceAccount、Service、NetworkPolicy
使用 CR 名称；配置/CA ConfigMap 分别为 `<name>-config`、`<name>-ca`；默认自管
叶子 Secret 为 `<name>-tls`；TokenReview 的 ClusterRoleBinding 名称为
`supek8smcp-<sha256(namespace/name) 前 8 字节>`。这些资源带有以下标签：
`app.kubernetes.io/name=supek8smcp-server`、
`app.kubernetes.io/instance=<name>`、
`app.kubernetes.io/managed-by=supek8smcp-operator`。

Operator 调谐任何同名对象前都要求该对象具有指向当前 CR 的 controller ownerReference；绝不会接管、删除或缩容不受当前 CR 控制的同名 ServiceAccount、Service、ConfigMap、Deployment、NetworkPolicy 或自管 TLS Secret。只有确认 Server ServiceAccount 已存在且由当前 CR 控制后，才会创建 TokenReview binding；发生所有权冲突时端点保持禁用，Server 缩容为零。

`allowClusterScopedWrite: true` 只有在 `Dangerous` 模式才是合法配置。即使
CR 的 `policy.rules` 允许某个动作，请求 Bearer Token 仍必须在 Kubernetes
RBAC 中拥有对应权限；最终权限是两者的交集。留空 `policy.rules` 时采用该
模式的保守默认能力，不能借此扩大 Token 权限。`verbs` 除 Kubernetes 原生动词
外，也可使用 `k8s.search` 返回的逻辑 action，例如 `logs`、`scale`、`restart`、
`apply`、`exec`、`attach`。
Role 若使用 `resourceNames`，调用 `k8s.search` 时需传入目标 `name`，以便
SelfSubjectAccessReview 按该对象名匹配权限。
Server 自身的 CR、配置/CA/TLS、Deployment、Service、ServiceAccount、
NetworkPolicy 与 TokenReview RBAC 对象属于不可通过该 Server 修改的控制面资源；
所有 KubernetesMCPServer CR 及带
`app.kubernetes.io/managed-by=supek8smcp-operator` 标签的其他实例资源也受保护。
即使 Dangerous policy 和客户端 RBAC 同时允许，也会返回
`managed_resource_denied`。

NetworkPolicy 默认只限制入站到 MCP `8443` 和 metrics/health `9090`。未设置
来源选择器时允许同命名空间 Pod；`allowedNamespaceSelector` 和
`allowedPodSelector` 可按命名空间/Pod 标签收窄来源，同时设置时取交集。该
策略不限制 Egress，因此 Server 到 kube-apiserver、DNS 和 TokenReview 的出站
路径仍需由集群网络策略和防火墙保证。

应用并观察状态：

```bash
kubectl apply -f kubernetesmcpserver.yaml
kubectl -n supek8smcp-servers get kmcp platform-ops -o wide
kubectl -n supek8smcp-servers describe kmcp platform-ops
kubectl -n supek8smcp-servers get deploy,svc,pods,secret,configmap \
  -l app.kubernetes.io/instance=platform-ops
```

等待 `status.conditions` 中的 `Ready=True`，并从 `status.endpoint` 读取实际
访问地址。若使用 Operator 自管 TLS，`status.caConfigMapName` 是客户端应信任
的 CA ConfigMap 名称。正常调谐还会报告 `TLSReady=True`（证书已就绪）和
`AuthReady=True`（最小 TokenReview ClusterRole 已校验且 ClusterRoleBinding 已配置）；
这些条件反映的是 Operator 已完成资源编排，不替代对实际 Token/RBAC 的授权检查。
Service selector 和 Server Pod 都带有由当前 CR UID/generation、Server 镜像、配置
和 TLS 材料共同确定的 revision；新 revision 完成前旧 Pod 不会被 Service 选中。
认证、TLS、配置或资源调谐失败时 Operator 会将
Service 切到无后端 revision，并把 Server Deployment 缩容为零，修复后由下一次
完整调谐重新开放。

## TLS 选择和 CA 分发

### Operator 自管证书（默认）

省略 `spec.tls.secretName` 或设为空对象时，Operator 创建共享根 CA，并创建或轮换
服务端叶子证书。根 CA 不会在到期前自动替换；计划中的根替换需要运维删除或替换
共享 Secret，并刷新客户端信任。将 `status.caConfigMapName` 指向的 ConfigMap
以只读方式分发给客户端：

```bash
CA_CONFIGMAP="$(kubectl -n platform get kmcp platform-ops \
  -o jsonpath='{.status.caConfigMapName}')"
kubectl -n platform get configmap "$CA_CONFIGMAP" -o yaml
```

Operator 命名空间中还会保留共享的 `supek8smcp-serving-ca` Secret（`ca.crt`/
`ca.key`），它不是每个 CR 的 owner resource。请像长期密钥材料一样限制读取并
备份；自管叶子始终以当前 Operator CA 为信任锚。只有 controller ownerReference
指向同一 CR 的自管 TLS Secret 才会被校验或轮换；同名但不受控制的 `<name>-tls`
Secret 会被拒绝，端点安全失败。删除根 Secret 会触发新根和受控叶子重签，客户端
必须刷新对应 CA ConfigMap。删除 CR 或执行 `make undeploy` 不会自动清理这个共享
CA，确需轮换时应安排客户端刷新 CA。

自管根 CA 的有效期约为 5 年，单个服务叶子证书约为 90 天；Operator 在叶子
剩余不足 30 天时重新签发。轮换后客户端只需继续信任对应的 CA ConfigMap，
但应确保连接池能够重新建立 TLS 连接。

应用或脚本应在 CA 轮换时重新读取 ConfigMap；不要把叶子私钥复制给 MCP
客户端。证书异常时先检查 Operator 事件、ConfigMap/Secret 是否存在以及
Server Pod 是否挂载了最新版本。

为避免 Operator 列举、watch 或缓存集群内全部 Secret，外部 TLS Secret 使用实时
单对象读取并按约 5 分钟周期检查。轮换后不要假设事件会立即触发更新；应等待 CR
完成下一次调谐并确认 Deployment 的 TLS hash 已变化。

### 使用已有 TLS Secret

将 `spec.tls.secretName` 设置为同一命名空间内、按 Kubernetes TLS 约定创建的
`kubernetes.io/tls` Secret：

```yaml
spec:
  tls:
    secretName: platform-ops-tls
```

Secret 必须包含 `tls.crt`、`tls.key` 和 `ca.crt`，且必须是
`kubernetes.io/tls` 类型。Operator 会校验密钥匹配、`ca.crt` 信任链、有效期、
ServerAuth 用途和 `<name>.<namespace>.svc` SAN；校验失败时 `TLSReady=False`，
不会继续提供 Ready Server。Operator 不会把该 Secret 的私钥写入 CR 状态；负责
轮换和续期的是你的证书管理流程。客户端仍需配置 `ca.crt`（Operator 会将它发布
到 `status.caConfigMapName` 指向的 ConfigMap）。

## Bearer Token 和客户端连接

为每个集成建立独立 ServiceAccount 和最小 RBAC，不要复用管理员 token。示例：

```bash
kubectl -n platform create serviceaccount mcp-client
kubectl create rolebinding mcp-client-read \
  --namespace platform \
  --serviceaccount platform:mcp-client \
  --clusterrole view
TOKEN="$(kubectl -n platform create token mcp-client --duration=1h)"
```

短期 token 通过 `Authorization: Bearer <token>` 发送。服务端会对 token 做
TokenReview，然后用同一 token 访问 kube-apiserver，因此客户端不能只依靠 CR
中的 `policy.rules` 获得额外 Kubernetes 权限。token 应由 Secret 管理器注入，
并设置过期/轮换策略。

客户端配置的 URL 以 `status.endpoint` 为准；集群内默认形状为：

```text
https://<service>.<namespace>.svc:8443/mcp
```

配置 `ca.crt`、Bearer header 和 Streamable HTTP transport。不要关闭 TLS 校验、
把 token 放进 URL query 或让反向代理记录 `Authorization` header。

## 运行时检查

```bash
kubectl -n platform get kmcp platform-ops \
  -o jsonpath='{.status.endpoint}{"\n"}{.status.caConfigMapName}{"\n"}'
kubectl -n platform get events --sort-by=.lastTimestamp \
  --field-selector involvedObject.name=platform-ops
kubectl -n supek8smcp-system logs deploy/supek8smcp-controller-manager \
  -c manager --tail=200
```

先确认 Operator Deployment 健康，再确认 CR 的 `Ready` 条件、Service endpoints
和 Server Pod。MCP 客户端应记录请求 ID/错误类别，不要记录 token、Secret 内容
或 exec 输出中的敏感数据。

## 审计、身份限流和告警

每次认证与通过 MCP 参数校验的工具调用都会向 Server 标准输出写一条
`audit_schema=v1` 的 JSON 事件。事件包含主体、工具、Kubernetes API 目标、
allow/deny/error 决策、稳定原因和延迟，不包含 Token、计划 ID、资源/patch
内容、exec 命令、stdin、Pod 日志或响应正文。可按下面方式抽查：

```bash
kubectl -n platform logs deploy/platform-ops --tail=200 | \
  jq 'select(.msg == "MCP security audit")'
```

`limits.requestsPerMinute` 和 `limits.burst` 对每个通过 TokenReview 的 Kubernetes
身份建立独立令牌桶；默认分别为 `120` 和 `20`。超过预算返回 HTTP `429`，并带
`Retry-After`。现有 `maxConcurrent` 仍是 Server 的全局并发保护，两者同时生效。

Server 在 `9090/metrics` 暴露以下安全和可靠性指标：

- `supek8smcp_authentication_attempts_total`
- `supek8smcp_rate_limit_rejections_total`
- `supek8smcp_audit_events_total`
- `supek8smcp_tool_calls_total`
- `supek8smcp_tool_duration_seconds`

`supek8smcp_tool_calls_total` 的 `result` 明确区分 `ok`、策略/RBAC 拒绝的
`denied` 和基础设施/执行失败的 `error`，因此可靠性告警不会把预期的权限拒绝
误判成服务故障。

使用 Prometheus Operator 时，可选安装仓库提供的 ServiceMonitor 和告警规则：

```bash
kubectl apply -k config/monitoring
```

该目录不在默认 `make deploy` 中，避免未安装 `monitoring.coreos.com` CRD 的集群
部署失败。Prometheus 实例若通过 label selector 选择 ServiceMonitor/PrometheusRule，
请按集群约定给这些对象补充选择标签。默认 NetworkPolicy 只允许同命名空间来源；
Prometheus 位于其他命名空间时，必须在 CR 的 `allowedNamespaceSelector`/
`allowedPodSelector` 中显式允许其抓取 `9090`，不要直接关闭整个 NetworkPolicy。
告警阈值是安全起点，上线前应结合正常流量基线调整。

## 故障排查

### CR 一直不是 Ready

查看 `kubectl describe kmcp <name> -n <namespace>` 和 Operator 日志。常见原因：

- `spec.tls.secretName` 不存在、类型不是 `kubernetes.io/tls`、缺少 `tls.crt`/
  `tls.key`/`ca.crt`，或证书密钥、信任链、有效期、ServerAuth/SAN 校验失败；
- 镜像拉取失败、ServiceAccount/RBAC 不足、NetworkPolicy 阻断 Operator 或
  Server 到 kube-apiserver 的连接；
- `allowClusterScopedWrite` 与 `mode` 不匹配，或其他字段未通过 CRD 校验。

### 客户端 TLS 握手失败

确认客户端使用的是 `status.caConfigMapName` 中的 CA（或外部 TLS Secret 的
签发 CA），ServerName 与证书 SAN 匹配，且 URL 没有误指向其他 Service。不要
用 `-k` 掩盖问题；检查证书有效期和 Pod 挂载内容。

### 401/403 或工具返回权限错误

401 通常表示缺少、过期或无效 Bearer Token；带有浏览器
`Origin` header 的请求也会被拒绝。403 表示该
Token 的 RBAC、CR `scope` 或 `policy.rules` 至少有一层拒绝。先用同一身份执行
`kubectl auth can-i`，再检查命名空间范围、API group/resource/verb 拼写。CR
更新后等待 Operator 重新调谐并重新读取 `status.conditions`。

资源列表每次最多从 kube-apiserver 读取 8 项；响应中的 `metadata.continue` 会作为
下一次 `k8s.read` 的 `cursor`。即使 CR 中 `maxListItems` 更大，也应循环使用 cursor
渐进读取，避免让模型上下文和 Server 内存被单个列表占满。非 watch 的委派动态
客户端资源、discovery 和 OpenAPI 响应还有 8 MiB 硬上限；超过时缩小选择器、
继续分页，或只请求更小的 schema 范围。

TokenReview API 或委派客户端暂时不可用时 Server 返回 `503`，并在审计/指标中
使用 `tokenreview_error` 或 `delegated_client_error`，避免将服务端故障误报为
无效凭据。此时检查 kube-apiserver 连通性和 Server ServiceAccount 的
`tokenreviews.create`，不要反复更换客户端 Token。等待 `maxConcurrent` 超过
`requestTimeout` 也会返回 `503`，对应 reason 为 `concurrency_timeout`。

### 写操作被拒绝或 commit 失败

SafeWrite/Dangerous 的写入必须先调用 `k8s.plan`，向人类展示预览和 6 位确认码，
再等待人类在后续用户消息中复述该码。随后必须在两分钟内使用同一身份，同时携带
`planId` 和 `confirmationCode` 调用 `k8s.commit`。缺失或格式错误的码会被拒绝；
连续 5 次错误的 6 位码会使计划失效。计划是一次性的，正确确认后即使后续安全检查
或 Kubernetes 请求失败也必须重新 plan；过期、重放、token/请求上下文不一致同样
要求新计划。ReadOnly 永远不会暴露写工具。SafeWrite 仍会比较变更前对象和
kube-apiserver dry-run 最终对象并拒绝不安全的约束移除。由于模型本身能看到确认码，
需要可验证的人工审批时必须使用外部审批网关。

### exec/attach 失败

仅 Dangerous 模式支持有界、非交互 exec/attach。确认目标 Pod、容器、输入输出
大小、并发和 `execTimeout` 均在限制内；TTY、port-forward、cp、proxy、evict
和 drain 不在第一版支持范围。

### 持续 Pod 日志被拒绝

`k8s.read` 读取 Pod 日志时，`follow=false` 的一次性结果在三种模式均可用；
`follow=true` 的持续日志流仅 Dangerous 模式允许。若收到 `mode_denied`，请改用
一次性读取，或确认 CR 为 Dangerous，并检查 `streamTimeout`、`maxOutputBytes`、
`maxListItems` 日志行数和并发预算。

## 卸载和数据保留

先删除引用的 `KubernetesMCPServer`，确认相关 Server、Service、NetworkPolicy
和证书资源已按预期清理，再执行 `make undeploy`。最后执行 `make uninstall`
删除 CRD；这一步会删除该 CRD 下的对象，生产环境应先导出 YAML 和审计记录。
