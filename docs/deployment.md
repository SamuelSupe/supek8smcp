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
  的 ClusterRole 只允许对这个固定 `resourceName` 使用 `bind`，本身不拥有
  `tokenreviews.create`，也不会代持客户端 Bearer Token。
- 集群节点能拉取 Operator 镜像；若使用私有仓库，先配置 imagePullSecret。
- MCP 客户端支持 Streamable HTTP、Bearer header 和自定义 CA。

## 安装 Operator

从源码构建并发布镜像：

```bash
export IMG=registry.example.com/platform/supek8smcp:0.1.0
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

卸载 CRD 会删除该 CRD 下的自定义资源及其由 Operator 管理的工作负载；在
生产集群执行前先备份 CR，并确认保留策略。

## 创建 CR

每个 `KubernetesMCPServer` 是 namespaced 资源，Operator 为它创建一个单副本
MCP Server、一个 `ClusterIP` Service，以及证书/CA 相关资源。下面的配置给
`platform` 命名空间提供 SafeWrite：

仓库中的最小只读样例位于
`config/samples/mcp_v1alpha1_kubernetesmcpserver.yaml`；以下示例额外展示
范围、写策略和资源预算。

```yaml
apiVersion: mcp.supek8smcp.io/v1alpha1
kind: KubernetesMCPServer
metadata:
  name: platform-ops
  namespace: platform
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
  networkPolicy:
    enabled: true
```

资源名称与标签便于审计和选择：Deployment、ServiceAccount、Service、NetworkPolicy
使用 CR 名称；配置/CA ConfigMap 分别为 `<name>-config`、`<name>-ca`；默认自管
叶子 Secret 为 `<name>-tls`；TokenReview 的 ClusterRoleBinding 名称为
`supek8smcp-<sha256(namespace/name) 前 8 字节>`。这些资源带有以下标签：
`app.kubernetes.io/name=supek8smcp-server`、
`app.kubernetes.io/instance=<name>`、
`app.kubernetes.io/managed-by=supek8smcp-operator`。

`allowClusterScopedWrite: true` 只有在 `Dangerous` 模式才是合法配置。即使
CR 的 `policy.rules` 允许某个动作，请求 Bearer Token 仍必须在 Kubernetes
RBAC 中拥有对应权限；最终权限是两者的交集。留空 `policy.rules` 时采用该
模式的保守默认能力，不能借此扩大 Token 权限。`verbs` 除 Kubernetes 原生动词
外，也可使用 `k8s.search` 返回的逻辑 action，例如 `logs`、`scale`、`restart`、
`apply`、`exec`、`attach`。

NetworkPolicy 默认只限制入站到 MCP `8443` 和 metrics/health `9090`。未设置
来源选择器时允许同命名空间 Pod；`allowedNamespaceSelector` 和
`allowedPodSelector` 可按命名空间/Pod 标签收窄来源，同时设置时取交集。该
策略不限制 Egress，因此 Server 到 kube-apiserver、DNS 和 TokenReview 的出站
路径仍需由集群网络策略和防火墙保证。

应用并观察状态：

```bash
kubectl apply -f kubernetesmcpserver.yaml
kubectl -n platform get kmcp platform-ops -o wide
kubectl -n platform describe kmcp platform-ops
kubectl -n platform get deploy,svc,pods,secret,configmap \
  -l app.kubernetes.io/instance=platform-ops
```

等待 `status.conditions` 中的 `Ready=True`，并从 `status.endpoint` 读取实际
访问地址。若使用 Operator 自管 TLS，`status.caConfigMapName` 是客户端应信任
的 CA ConfigMap 名称。正常调谐还会报告 `TLSReady=True`（证书已就绪）和
`AuthReady=True`（TokenReview ClusterRoleBinding 已配置）；这些条件反映的是
Operator 已完成资源编排，不替代对实际 Token/RBAC 的授权检查。

## TLS 选择和 CA 分发

### Operator 自管证书（默认）

省略 `spec.tls.secretName` 或设为空对象时，Operator 创建并轮换服务端叶子
证书和 CA。将 `status.caConfigMapName` 指向的 ConfigMap 以只读方式分发给
客户端：

```bash
CA_CONFIGMAP="$(kubectl -n platform get kmcp platform-ops \
  -o jsonpath='{.status.caConfigMapName}')"
kubectl -n platform get configmap "$CA_CONFIGMAP" -o yaml
```

Operator 命名空间中还会保留共享的 `supek8smcp-serving-ca` Secret（`ca.crt`/
`ca.key`），它不是每个 CR 的 owner resource。请像长期密钥材料一样限制读取并
备份；删除它会触发重建，现有仍有效的叶子会暂时继续使用原 CA，但后续叶子
轮换会切换到新 CA，客户端必须刷新对应 CA ConfigMap。删除 CR 或执行
`make undeploy` 不会自动清理这个共享 CA，确需轮换时应安排客户端刷新 CA。

自管根 CA 的有效期约为 5 年，单个服务叶子证书约为 90 天；Operator 在叶子
剩余不足 30 天时重新签发。轮换后客户端只需继续信任对应的 CA ConfigMap，
但应确保连接池能够重新建立 TLS 连接。

应用或脚本应在 CA 轮换时重新读取 ConfigMap；不要把叶子私钥复制给 MCP
客户端。证书异常时先检查 Operator 事件、ConfigMap/Secret 是否存在以及
Server Pod 是否挂载了最新版本。

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

401 通常表示缺少/过期/无效 Bearer Token，或 TokenReview 失败；带有浏览器
`Origin` header 的请求也会被拒绝。403 表示该
Token 的 RBAC、CR `scope` 或 `policy.rules` 至少有一层拒绝。先用同一身份执行
`kubectl auth can-i`，再检查命名空间范围、API group/resource/verb 拼写。CR
更新后等待 Operator 重新调谐并重新读取 `status.conditions`。

### 写操作被拒绝或 commit 失败

SafeWrite/Dangerous 的持久写必须先调用 `k8s.plan`，并在两分钟内使用同一
身份调用 `k8s.commit`。计划是一次性的；过期、重复提交、token/请求上下文
不一致都应重新 plan。ReadOnly 永远不会暴露写工具。

### exec/attach 失败

仅 Dangerous 模式支持有界、非交互 exec/attach。确认目标 Pod、容器、输入输出
大小、并发和 `execTimeout` 均在限制内；TTY、port-forward、cp、proxy、evict
和 drain 不在第一版支持范围。

### 持续 Pod 日志被拒绝

`k8s.read` 读取 Pod 日志时，`follow=false` 的一次性结果在三种模式均可用；
`follow=true` 的持续日志流仅 Dangerous 模式允许。若收到 `mode_denied`，请改用
一次性读取，或确认 CR 为 Dangerous，并检查 `streamTimeout`、`maxOutputBytes`
和并发预算。

## 卸载和数据保留

先删除引用的 `KubernetesMCPServer`，确认相关 Server、Service、NetworkPolicy
和证书资源已按预期清理，再执行 `make undeploy`。最后执行 `make uninstall`
删除 CRD；这一步会删除该 CRD 下的对象，生产环境应先导出 YAML 和审计记录。
