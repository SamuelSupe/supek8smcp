# supek8smcp

`supek8smcp` 是一个 Kubernetes Operator：每个命名空间中的
`KubernetesMCPServer` 自定义资源（CR）对应一个单副本、HTTPS
Streamable HTTP MCP Server。MCP 客户端用 Kubernetes Bearer Token 连接；
服务端先用 TokenReview 校验令牌，再用同一个令牌调用 kube-apiserver。
因此，MCP 请求永远不会比该令牌在 Kubernetes RBAC 中已有的权限更多。

项目模块为 `github.com/samuelsupe/supek8smcp`，CRD 为
`mcp.supek8smcp.io/v1alpha1/KubernetesMCPServer`（简称 `kmcp`）。

## 能力概览

- **ReadOnly**：只读工具 `k8s.search`、`k8s.describe`、`k8s.read`；Pod 日志
  仅允许一次性读取（`follow=false`）。
- **SafeWrite**：包含上述只读能力和 `k8s.plan`、`k8s.commit`；Pod 日志仍只允许
  `follow=false`，所有持久写操作必须先生成计划，计划两分钟后过期且只能提交一次。
- **Dangerous**：包含 SafeWrite 能力，并允许受 `streamTimeout`/
  `maxOutputBytes` 限制的持续 Pod 日志（`follow=true`），以及受 `execTimeout`/
  `maxOutputBytes` 限制的有界、非交互 `exec/attach`。不提供 TTY。
- 资源范围由 CR 的 `scope` 与 `policy` 先做能力上限，再与请求 Bearer
  Token 的 Kubernetes RBAC 求交集。
- `policy.rules.verbs` 支持 Kubernetes 动词，也支持 `k8s.search` 返回的逻辑
  action（如 `logs`、`scale`、`restart`、`apply`、`exec`、`attach`）。
- Secret 默认脱敏（`policy.sensitiveReads: Redact`）；也可选择
  `Deny` 或显式 `Allow`。
- Operator 默认自管 CA 和叶子证书，也可通过 `spec.tls.secretName` 使用
  现有 `kubernetes.io/tls` Secret（需提供 `tls.crt`、`tls.key`、`ca.crt`，并通过
  Operator 的密钥、信任链、有效期、ServerAuth 和 Service SAN 校验）。服务仅创建
  `ClusterIP` Service。

详细的安装步骤、安全边界和故障排查见：

- [部署指南](docs/deployment.md)
- [安全模型](docs/security.md)

## 快速开始

### 1. 安装 Operator 和 CRD

准备可被集群拉取的镜像后，在仓库根目录执行：

```bash
make install
make deploy IMG=registry.example.com/platform/supek8smcp:0.1.0
```

`make install` 安装 CRD；`make deploy` 创建 Operator 的命名空间、RBAC 和
Deployment，并将 `IMG` 同时用于 Operator 与每个 CR 的 Server 镜像。生产环境
应使用不可变镜像标签或 digest，并在变更前阅读
[部署指南](docs/deployment.md)。

### 2. 创建一个只读 MCP Server

```yaml
apiVersion: mcp.supek8smcp.io/v1alpha1
kind: KubernetesMCPServer
metadata:
  name: team-readonly
  namespace: platform
spec:
  mode: ReadOnly
  scope:
    namespaces:
      - platform
    allowClusterScopedRead: false
  policy:
    sensitiveReads: Redact
  tls: {}
```

保存为 `kubernetesmcpserver.yaml` 后应用：

```bash
kubectl apply -f kubernetesmcpserver.yaml
kubectl -n platform get kmcp team-readonly -o yaml
kubectl -n platform get svc -l app.kubernetes.io/instance=team-readonly
```

CRD 会在接纳时为 `mode`、`policy.sensitiveReads`、limits 和
`networkPolicy.enabled` 应用安全默认值；Operator 还会在生成 Server 配置时将
`scope.namespaces` 默认设为 CR 所在命名空间。默认值分别为：`ReadOnly`、
`Redact`、NetworkPolicy 启用；请求/流/exec 超时为 `30s`/`60s`/`30s`，
输入/输出/列表/并发上限为 `262144`/`1048576`/`100`/`4`。排障时以 Server
Pod 挂载的 `<name>-config` ConfigMap 和状态条件为准。

### 3. 取 CA 和 Bearer Token

Operator 自管证书时，CA 位于 CR 状态中的 `status.caConfigMapName` 指向的
ConfigMap。复制 CA 到本地（示例使用 `ca.crt` 键）：

```bash
CA_CONFIGMAP="$(kubectl -n platform get kmcp team-readonly \
  -o jsonpath='{.status.caConfigMapName}')"
kubectl -n platform get configmap "$CA_CONFIGMAP" \
  -o jsonpath='{.data.ca\.crt}' > ca.crt
```

给 MCP 客户端使用的身份应是一个单独的 ServiceAccount，并通过 Kubernetes
RBAC 精确授予所需资源和动词。短期调试可以：

```bash
TOKEN="$(kubectl -n platform create token mcp-client --duration=1h)"
```

Token 只放在客户端的进程环境或 Secret 管理器中；不要提交到 Git 或写入
日志。客户端每次请求都发送：

```http
Authorization: Bearer <token>
```

服务端会对该令牌执行 TokenReview，并用同一令牌访问 kube-apiserver。

### 4. 配置 Streamable HTTP MCP 客户端

使用 `status.endpoint` 作为服务地址；集群内通常是
`https://<service>.<namespace>.svc:8443/mcp`，实际值以 CR 状态为准。客户端
需要信任 `ca.crt`，并发送上一步的 Bearer Token。一个通用的配置形状如下
（不同 MCP 客户端的字段名可能不同）：

```json
{
  "mcpServers": {
    "team-readonly": {
      "type": "streamable-http",
      "url": "https://team-readonly.platform.svc:8443/mcp",
      "headers": {
        "Authorization": "Bearer ${K8S_MCP_TOKEN}"
      },
      "tls": {
        "caFile": "/path/to/ca.crt"
      }
    }
  }
}
```

不要以 `curl -k`、跳过证书验证或把 token 拼进 URL 的方式连接。若客户端
运行在集群外，应通过受控的 TLS 入口暴露服务，并保持端到端的 CA/证书校验；
Service 本身仍然是 `ClusterIP`。

## 版本和限制

第一版明确不支持：OAuth、port-forward、`cp`、proxy、evict、drain、多集群、
Server 多副本和 TTY。`exec/attach` 与持续 Pod 日志（`k8s.read` 的
`follow=true`）只在 Dangerous 模式可用，且必须满足请求/流/exec 超时、输入输出
大小和并发上限；一次性日志（`follow=false`）仍是各模式的只读能力。SafeWrite/
Dangerous 的持久写不能绕过 `k8s.plan` -> 两分钟一次性计划 -> `k8s.commit` 流程。

升级或排障前请先阅读 [安全模型](docs/security.md) 和
[部署指南](docs/deployment.md) 的限制、证书轮换及故障排查章节。
