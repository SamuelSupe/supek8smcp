# 安全模型与边界

`supek8smcp` 将“客户端能调用什么”限制为三层交集：CR 配置的能力上限、
请求 Bearer Token 的 Kubernetes RBAC，以及运行时资源/网络/时间预算。任何
一层拒绝都应拒绝请求；MCP Server 不会把自己的 ServiceAccount 或 Operator
权限借给客户端。

## 信任边界

请求链路如下：

1. MCP 客户端通过 HTTPS Streamable HTTP 发送 `Authorization: Bearer <token>`。
2. Server 使用 Kubernetes TokenReview API 验证 token、用户和群组。
3. Server 使用同一个 token 创建 kube-apiserver 客户端，并执行请求。
4. Server 将 CR 的 `scope`/`policy` 与 Kubernetes RBAC 求交集，再应用模式、
   脱敏和资源限制。

在这条认证授权链路中，Operator 只负责为每个 CR 创建 Server ServiceAccount 与固定的
`supek8smcp-tokenreviewer` ClusterRoleBinding；它的 RBAC 仅允许对该固定
ClusterRole 执行 `bind`，不授予 Operator `tokenreviews.create`，也不让 Operator
代持客户端 Bearer Token。实际 TokenReview 由 Server ServiceAccount 发起，后续
资源请求仍使用客户端原始 token。

为避免浏览器跨站凭据滥用，Server 拒绝带 `Origin` header 的请求；集成应使用
受控的非浏览器 MCP 客户端或在受信任的后端代理中移除该 header（代理仍必须
保留 TLS、认证和审计边界）。

因此，CR 中的规则是“最多允许什么”，不是额外授权；TokenReview 成功也不
代表 token 能访问所有资源。应为每个 MCP 集成建立独立 ServiceAccount、短期
token 和最小 Role/ClusterRole。

## 模式与工具

| 模式 | 工具 | 主要边界 |
| --- | --- | --- |
| `ReadOnly` | `k8s.search`、`k8s.describe`、`k8s.read` | 仅读取；Pod 日志只允许一次性 `follow=false`，不能持久写或 exec/attach |
| `SafeWrite` | 上述只读工具 + `k8s.plan`、`k8s.commit` | Pod 日志仍只允许 `follow=false`；所有持久写必须先 plan，再在两分钟内一次性 commit |
| `Dangerous` | SafeWrite 全部工具 + `follow=true` 持续日志、有界非交互 exec/attach | 日志流受 `streamTimeout`/`maxOutputBytes`，exec/attach 受 `execTimeout`/`maxOutputBytes` 等限制；不提供 TTY |

`k8s.plan` 生成待执行的写计划；计划有效期为两分钟且只能成功提交一次。
`k8s.commit` 必须带同一计划和同一授权身份。过期、重复、身份不匹配或内容
改变时拒绝提交并要求重新 plan。客户端不应缓存或重放计划。

`k8s.read` 的 Pod 日志读取在所有模式都支持 `follow=false` 的一次性结果；
`follow=true` 会建立持续日志流，仅 Dangerous 模式允许，并受 `streamTimeout`
和 `maxOutputBytes` 限制。

第一版不提供 OAuth、port-forward、`cp`、proxy、evict、drain、TTY、多集群或
Server 多副本。不要把 `Dangerous` 当作管理员 shell：exec/attach 必须是有界、
非交互请求，并服从 `execTimeout`、输入输出大小和并发上限。

## CR 能力上限

### Scope

`spec.scope.namespaces` 限定 namespaced 资源；CRD 不做命名空间相关默认，Operator
在运行配置中将省略值设为 CR 所在命名空间。
`allowClusterScopedRead` 控制是否可读集群级资源；集群级写入还要求
`allowClusterScopedWrite: true` 且模式为 `Dangerous`。scope 不会替代 RBAC，
也不会把 namespaced token 变成 cluster-admin。

### Policy

`spec.policy.rules` 按 API group、resource 和 verb 描述上限。`verbs` 可填写
Kubernetes 原生动词，也可填写 `k8s.search` 返回的逻辑 action（例如 `logs`、
`scale`、`restart`、`apply`、`exec`、`attach`）。留空使用当前模式的保守默认
能力。规则只会收窄可调用集合；最终调用仍由 token 的 Kubernetes 授权决定。
修改 CR 的 mode/scope/policy 应视为权限变更，纳入代码审查、审计和发布审批。

### Secret 读取

`spec.policy.sensitiveReads` 的默认值是 `Redact`：Secret 元数据可按其他规则
读取，但数据字段脱敏。`Deny` 完全拒绝敏感读取；`Allow` 只应在明确的受控
场景使用，并同时收紧 RBAC、网络和审计范围。不要把 Secret 值、Bearer Token、
TLS 私钥或 exec 输出写入日志、MCP 客户端配置或 issue。

## 认证、授权与审计

- 使用 HTTPS；客户端必须校验 CA 和服务端名称。默认 Operator 自管 CA/叶子
  证书，CA 名称通过 `status.caConfigMapName` 发布；也可引用
  `kubernetes.io/tls` Secret。
- Token 只放在 `Authorization` header。代理、日志采集器和 tracing exporter
  必须显式排除该 header；禁止 query 参数传 token。
- TokenReview 和后续 kube-apiserver 请求使用同一 token，确保 Kubernetes 审计
  能看到真实主体。不要让 Server 用 Operator 的高权限身份代替客户端调用。
- 为不同团队/自动化任务使用不同 ServiceAccount，设置短过期时间并定期轮换；
  删除或禁用身份后，TokenReview/RBAC 应立即阻止后续请求。
- 监控 CR 状态、Operator/Server 日志、Kubernetes 审计和 NetworkPolicy 事件。
  日志只保留必要的主体、请求类别、结果和延迟，不保留凭据或完整资源内容。

## 资源和网络防护

CR 的 `limits` 将请求、流、exec 超时，输入/输出字节数、列表条目数和并发数
设为显式预算；超限请求应失败而不是无限等待或无限制返回。CRD 会为这些字段
应用默认值，Operator 生成的 Server 配置也会保留这些值；部署后应检查
`<name>-config` ConfigMap 中的实际值。对高风险场景，进一步降低 `maxOutputBytes`、
`maxListItems` 和 `maxConcurrent`。

CRD 还限制字节/列表/并发字段的范围：`maxInputBytes` 为 1 KiB–10 MiB，
`maxOutputBytes` 为 1 KiB–50 MiB，`maxListItems` 为 1–1000，`maxConcurrent`
为 1–32；时间字段使用 Kubernetes duration 字符串。超过范围的 CR 会在 API
接纳阶段被拒绝。

`networkPolicy.enabled` 默认启用。当前生成的是仅限入站（Ingress）的策略，端口
为 MCP `8443` 和 metrics/health `9090`；未设置 selector 时默认允许同命名空间
Pod，`allowedNamespaceSelector` 与 `allowedPodSelector` 可进一步收窄来源（两者
同时设置时取交集）。策略不声明 Egress，Server 到 kube-apiserver、DNS 和
TokenReview 的出站连通性依赖集群的其他网络策略。若通过入口/网关暴露到集群外，
入口必须保持 TLS、限制来源、隐藏 `Authorization`，并避免将 Server 扩展为公网
匿名端点。

Service 固定为 `ClusterIP`，每个 CR 只有一个 Server 副本。不要通过手工修改
Deployment 将副本数扩展为多副本，也不要把同一外部身份无边界地共享给多个团队。

## TLS 和密钥处理

Operator 自管证书时，叶子私钥只应存在于受限 Secret 并挂载到 Server；客户端
只获取 CA。使用 `spec.tls.secretName` 时，Secret 必须是同命名空间的
`kubernetes.io/tls`；Operator 会校验密钥匹配、`ca.crt` 信任链、有效期、
ServerAuth 用途和 `<name>.<namespace>.svc` SAN，任何一项不满足都会使
`TLSReady=False`。轮换由外部证书流程负责。
轮换期间应确认 Server 重新加载新 Secret，并让客户端刷新 CA/连接池。

Operator 命名空间的 `supek8smcp-serving-ca` 是所有自管叶子的共享根 CA，包含
`ca.crt` 和 `ca.key`，没有随单个 CR 自动删除的 owner reference。应限制其读取、
纳入备份和密钥轮换流程；删除它会重新生成根，现有仍有效的叶子暂时继续使用原
CA，但后续轮换会切换到新链，要求客户端重新获取各 CR 的 CA ConfigMap。自管根 CA
有效期约 5 年，叶子约 90 天，剩余不足
30 天时由 Operator 重签；轮换期间要验证客户端能重新建立 TLS 连接。

如果必须导出诊断包，先脱敏 YAML、Secret、token、headers、资源数据和 exec
输出；原始包只能进入受控的加密存储，并设置保留期限。

## 运维安全清单

- [ ] 镜像使用固定 tag/digest、来源可验证，并以非 root、只读根文件系统等
      集群基线运行（具体安全上下文以部署清单为准）。
- [ ] Operator 和 Server ServiceAccount 使用最小 RBAC；客户端身份不复用它们。
- [ ] 所有 CR 显式评审 `mode`、`scope`、`policy`、`sensitiveReads` 和 limits。
- [ ] 默认保留 `Redact`，只有有审批、短窗口和审计的场景才启用 `Allow` 或
      `Dangerous`。
- [ ] `ca.crt` 以只读配置分发，TLS 校验不关闭；token 在 Secret 管理器中轮换。
- [ ] NetworkPolicy 只放行受控入站来源；另行验证 Server 到 kube-apiserver/DNS 的
      Egress 连通性，入口不记录凭据。
- [ ] 监控 TokenReview 失败、403、plan/commit 失败、exec 超限和证书轮换事件。
- [ ] 卸载 CRD 或删除 Dangerous CR 前，先导出配置和审计记录并确认影响范围。

## 安全故障排查

- **401**：检查 Bearer header、token 是否过期，及 TokenReview 是否可达；不要
  通过改成 Operator token 来“修复”。
- **403**：用同一 ServiceAccount 执行 `kubectl auth can-i`，然后检查 CR scope、
  policy 和 mode；权限取交集，任一侧不足都会拒绝。
- **TLS 错误**：核对 `status.caConfigMapName`、CA 内容、证书密钥匹配、信任链、
  ServerAuth、SAN/有效期和客户端 ServerName；BYO Secret 任一校验失败都会使
  `TLSReady=False`，不要使用 `-k`。
- **plan/commit 失败**：计划是否超过两分钟、已被提交或身份已变；重新 plan，
  不要重放旧计划。
- **exec/attach 失败**：确认 Dangerous、目标资源合法、非交互、超时/字节/并发
  预算未超限；TTY 和 port-forward 等未实现功能不会通过配置启用。
