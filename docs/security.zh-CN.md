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

Kubernetes 命名空间是这里的强信任边界。任何能在 Server 所在命名空间创建 Pod
的主体，通常都能让 Pod 挂载该命名空间的 TLS Secret 或 Server ServiceAccount，
也能伪造 Service selector 标签；仅依赖 Secret 的 `get` RBAC 或 NetworkPolicy
不能阻止这种间接访问。生产环境必须把 `KubernetesMCPServer` 放进专用、受限的
端点命名空间，不向普通工作负载身份授予 Pod/Deployment 创建权限，再通过
`scope.namespaces` 指向被管理的工作负载命名空间，并用 NetworkPolicy 只放行明确
的 MCP 客户端或入口。Operator 的 managed 标签和 MCP 自保护不是命名空间隔离的
替代品。

在这条认证授权链路中，Operator 只负责为每个 CR 创建 Server ServiceAccount 与固定的
`supek8smcp-tokenreviewer` ClusterRoleBinding；它的 RBAC 仅允许读取并绑定该固定
ClusterRole，不授予 Operator `tokenreviews.create`，也不让 Operator 代持客户端
Bearer Token。Operator 会在绑定前校验该角色只包含
`authentication.k8s.io/tokenreviews.create` 且不是聚合角色；角色缺失、不可校验、
包含额外权限，或已有绑定指向其他角色时，它会删除已有绑定并将
`AuthReady=False`。实际 TokenReview 由 Server
ServiceAccount 发起，后续资源请求仍使用客户端原始 token。

同名资源的 controller ownerReference 是安全边界。除非同名 ServiceAccount、Service、
ConfigMap、Deployment、NetworkPolicy 或自管 TLS Secret 的 controller ownerReference
指向当前 CR，Operator 绝不会接管、删除或缩容它们。只有确认由当前 CR 控制的 Server
ServiceAccount 已存在后才会创建 TokenReview binding；发生所有权冲突时会安全失败，不修改无关对象。

为避免浏览器跨站凭据滥用，Server 拒绝带 `Origin` header 的请求；集成应使用
受控的非浏览器 MCP 客户端或在受信任的后端代理中移除该 header（代理仍必须
保留 TLS、认证和审计边界）。

因此，CR 中的规则是“最多允许什么”，不是额外授权；TokenReview 成功也不
代表 token 能访问所有资源。应为每个 MCP 集成建立独立 ServiceAccount、短期
token 和最小 Role/ClusterRole。

## 模式与工具

| 模式 | 工具 | 主要边界 |
| --- | --- | --- |
| `ReadOnly` | `k8s.help`、`k8s.search`、`k8s.describe`、`k8s.read` | 手册只返回内置静态说明；资源仅读取，Pod 日志只允许一次性 `follow=false`，不能持久写或 exec/attach |
| `SafeWrite` | 上述只读工具 + `k8s.plan`、`k8s.commit` | Pod 日志仍只允许 `follow=false`；每次写入都要求计划和人类在后续用户消息中复述的 6 位确认码 |
| `Dangerous` | SafeWrite 全部工具 + `follow=true` 持续日志、有界非交互 exec/attach | 同样强制人工确认码；日志流和远程执行仍有界；不提供 TTY |

`k8s.help` 在三种模式中始终直接暴露。无参数调用只给出工具索引和当前模式
`available` 状态；使用索引中的 `detailsRequest` 再调用一次，才加载单个工具的
完整用法。ReadOnly 可以查询写工具的说明，但 `k8s.plan`/`k8s.commit` 会标记为
不可用，且不会出现在该 Server 实际暴露的工具列表中。手册内容是本地静态数据，
不执行 discovery、资源读取或写入，但请求仍必须完成 TokenReview，并计入身份限流
与 `audit_schema=v1` 审计。

`k8s.plan` 生成待执行的写计划，并返回预览、高熵 `planId` 和 6 位确认码。模型必须
向人类展示预览和确认码，停止写工具调用，等待人类在后续用户消息中复述该码。
`k8s.commit` 必须在两分钟内使用同一授权身份同时提交 planId 和确认码。缺失确认码
返回 `confirmation_required`；格式错误或不匹配返回 `invalid_confirmation`。缺失和
格式错误不计入尝试次数；每次格式正确但不匹配会计数，第 5 次会删除计划并返回
`confirmation_locked`。正确确认会在策略、RBAC、generation、UID、resourceVersion 和实际
执行复检前原子消费计划，因此之后任何失败都必须重新 plan。过期、重复、身份不匹配
或内容改变同样会被拒绝。内存计划仍受 1024 条、全局 64 MiB 和通常单身份 16 MiB
预算限制。

模型本身能够看到确认码，因此 Server 无法证明 `k8s.commit` 中的码确实由人类提供。
这是依赖模型遵从的防误执行约束，不是密码学意义上的人工审批，也不能抵抗恶意模型
或 Prompt Injection。需要强制职责分离时，必须使用外部审批网关或带外审批系统。

Kubernetes Role 使用 `resourceNames` 限制对象时，调用 `k8s.search` 必须同时传入
目标 `name`；Server 会用该名称执行 SelfSubjectAccessReview，避免把本来允许的
命名资源能力误判为无权限。每页最多执行 100 次 SelfSubjectAccessReview；权限
稀疏时页面可能少于请求的 `limit`，客户端应继续使用 `nextCursor`，避免单次工具
调用把请求无界放大到 kube-apiserver。

`k8s.read` 的 Pod 日志读取在所有模式都支持 `follow=false` 的一次性结果；
`follow=true` 会建立持续日志流，仅 Dangerous 模式允许，并受 `streamTimeout`、
`maxListItems`（日志行数）和 `maxOutputBytes` 限制。

第一版不提供 OAuth、port-forward、`cp`、proxy、evict、drain、TTY、多集群或
Server 多副本，也不接受 JSON-RPC batch。每个 MCP HTTP 请求最多执行一个调用，
避免旧协议 batch 绕过身份速率和全局并发预算。不要把 `Dangerous` 当作管理员 shell：exec/attach 必须是有界、
非交互请求，并服从 `execTimeout`、输入输出大小和并发上限。

## CR 能力上限

### Scope

`spec.scope.namespaces` 限定 namespaced 资源；CRD 不做命名空间相关默认，Operator
在运行配置中将省略值设为 CR 所在命名空间。
`allowClusterScopedRead` 控制是否可读集群级资源；集群级写入还要求
`allowClusterScopedWrite: true` 且模式为 `Dangerous`。scope 不会替代 RBAC，
也不会把 namespaced token 变成 cluster-admin。

API 接纳还要求 `metadata.name` 长度不超过 63 个字符，并匹配小写 DNS Service label：
以字母开头、以字母或数字结尾，只能包含小写字母、数字和连字符。

### Policy

`spec.policy.rules` 按 API group、resource 和 verb 描述上限。`verbs` 可填写
Kubernetes 原生动词，也可填写 `k8s.search` 返回的逻辑 action（例如 `logs`、
`scale`、`restart`、`apply`、`exec`、`attach`）。留空使用当前模式的保守默认
能力。规则只会收窄可调用集合；最终调用仍由 token 的 Kubernetes 授权决定。
修改 CR 的 mode/scope/policy 应视为权限变更，纳入代码审查、审计和发布审批。
无论采用哪种模式，Server 都拒绝通过自身 MCP 修改对应 CR、运行配置/CA ConfigMap、
TLS Secret、Deployment、Service、ServiceAccount、NetworkPolicy、固定 TokenReview
角色及其绑定，也拒绝修改带有
`app.kubernetes.io/managed-by=supek8smcp-operator` 的其他实例资源；这条自保护规则
不会因 CR policy 或客户端 RBAC 放宽而取消。

SafeWrite 会同时检查提交内容和 kube-apiserver dry-run 后的最终对象。直接设置
root/root group、特权、集群关键 PriorityClass、Windows GMSA/
ContainerAdministrator、Unconfined Seccomp/AppArmor 等字段会被拒绝；patch、update 或 apply
也不能通过 `null`、父对象/容器列表替换或字段省略，移除已有的 non-root、
`allowPrivilegeEscalation=false`、只读根文件系统、capability drop、安全配置文件、
ServiceAccount 或 runtime class 约束。该检查只阻止已知的不安全值和安全约束弱化，
不会自动为新工作负载补齐 Restricted Pod Security 配置；集群仍应启用适当的
Pod Security Admission 或同等准入策略。

### Secret 读取

`spec.policy.sensitiveReads` 的默认值是 `Redact`：Secret 的数据字段和全部
annotation 值都会脱敏，防止 `kubectl.kubernetes.io/last-applied-configuration`
等注解复制 `stringData`；名称、命名空间、标签、类型等其余元数据仍可按规则读取。
`Deny` 完全拒绝敏感读取；`Allow` 只应在明确的受控场景使用，并同时收紧 RBAC、
网络和审计范围。不要把 Secret 值、Bearer Token、TLS 私钥或 exec 输出写入日志、
MCP 客户端配置或 issue。

对所有资源类型，`k8s.read` 默认递归剔除 `metadata.annotations` 和
`metadata.managedFields`。调用者即使显式设置 `omitAnnotations: false`，注解名称或
内部赋值只要含有 token、password、secret、API key、access key、private key、
client secret、credential 等凭据特征，也会替换为 `<redacted>`。在此保护上线前
已经暴露的凭据必须轮换；响应脱敏无法撤销已经泄露的值。

## 认证、授权与审计

- 使用 HTTPS；客户端必须校验 CA 和服务端名称。默认 Operator 自管 CA/叶子
  证书，CA 名称通过 `status.caConfigMapName` 发布；也可引用
  `kubernetes.io/tls` Secret。
- Token 只放在 `Authorization` header。代理、日志采集器和 tracing exporter
  必须显式排除该 header；禁止 query 参数传 token。
- TokenReview 和后续 kube-apiserver 请求使用同一 token，确保 Kubernetes 审计
  能看到真实主体。不要让 Server 用 Operator 的高权限身份代替客户端调用。
- Server 为认证和每次通过 MCP 参数校验的工具调用输出 `audit_schema=v1` 的结构化
  JSON 审计
  事件，包含 Kubernetes 用户/UID 的稳定标识、工具、API 目标、决策、稳定原因和
  延迟。审计事件不记录 Bearer Token、planId、确认码、资源对象、patch、exec 命令、
  stdin、日志内容或工具响应。
- 为不同团队/自动化任务使用不同 ServiceAccount，设置短过期时间并定期轮换；
  删除或禁用身份后，TokenReview/RBAC 应立即阻止后续请求。
- 监控 CR 状态、Operator/Server 日志、Kubernetes 审计和 NetworkPolicy 事件。
  日志只保留必要的主体、请求类别、结果和延迟，不保留凭据或完整资源内容。

## 资源和网络防护

CR 的 `limits` 将请求、流、exec 超时，输入/输出字节数、列表条目数、并发数，
以及每个认证身份的 `requestsPerMinute`/`burst` 设为显式预算；超限请求应失败
而不是无限等待或无限制返回。身份限流在 TokenReview 成功后按用户名和 UID 的
稳定摘要隔离；Token 轮换或 TokenReview extra 变化不会创建新预算。拒绝时返回
HTTP `429` 和 `Retry-After`。它不会替代
全局 `maxConcurrent`，也不会改变 Kubernetes RBAC。CRD 会为这些字段应用默认值，
Operator 生成的 Server 配置也会保留这些值；部署后应检查 `<name>-config`
ConfigMap 中的实际值。对高风险场景，进一步降低 `maxOutputBytes`、`maxListItems`、
`maxConcurrent`、`requestsPerMinute` 和 `burst`。

Kubernetes 资源 `list` 默认使用 `outputMode: summary`，把单次上游分页进一步限制为
8 项，并原样返回 Kubernetes `continue` token；调用方应使用 `cursor` 渐进读取后续页。
`table` 可进一步减少重复字段名，`fieldPaths` 只投影指定的对象相对路径。委派动态
客户端还会拒绝超过 8 MiB 的非 watch 资源、discovery 或 OpenAPI 响应，避免在
输出裁剪前因大型列表或聚合 API 响应耗尽 Server 内存。watch 继续由
`streamTimeout`、`maxListItems` 和 `maxOutputBytes` 约束。

`k8s.describe` 会先定位 `fieldPath` 再展开引用，并把单次 schema 展开限制为
10,000 个节点；达到预算时返回带 `truncated` 标记的局部 schema。调用方应从较浅
`depth` 和精确 `fieldPath` 开始，而不是一次展开整个大型 CRD schema。

CRD 还限制字节/列表/并发字段的范围：`maxInputBytes` 为 1 KiB–10 MiB，
`maxOutputBytes` 为 1 KiB–50 MiB，`maxListItems` 为 1–1000，`maxConcurrent`
为 1–32，`requestsPerMinute` 为 1–6000，`burst` 为 1–1000；时间字段使用
可解析且大于 0 的 Kubernetes duration 字符串。非法 duration 或超过范围的 CR
会在 API 接纳阶段被拒绝。限流状态
保存在单个 Server Pod 内存中；第一版固定单副本，因此不存在跨副本预算偏差。

`networkPolicy.enabled` 默认启用。当前生成的是仅限入站（Ingress）的策略，端口
为 MCP `8443` 和 metrics/health `9090`；未设置 selector 时默认允许同命名空间
Pod，`allowedNamespaceSelector` 与 `allowedPodSelector` 可进一步收窄来源（两者
同时设置时取交集）。策略不声明 Egress，Server 到 kube-apiserver、DNS 和
TokenReview 的出站连通性依赖集群的其他网络策略。若通过入口/网关暴露到集群外，
入口必须保持 TLS、限制来源、隐藏 `Authorization`，并避免将 Server 扩展为公网
匿名端点。

Service 固定为 `ClusterIP`，每个 CR 只有一个 Server 副本。Deployment 使用
`Recreate` 更新：紧凑能力句柄和 plan 都是 Pod 本地状态，禁止新旧 revision 重叠可避免
`search` 后 capability 失效、`plan` 后 commit 丢失，以及收紧策略时旧 revision
继续接流量。Server 重启或返回 `invalid_capability` 后，客户端必须重新 search。Service 只选择由当前 CR UID/generation、Server 镜像、配置和 TLS
材料共同确定的 Pod revision；任何认证、证书、配置或资源调谐失败都会把 Service
切到无后端 revision，并把现有 Server
Deployment 缩容为零。修复失败原因并成功完成整轮调谐前，旧策略不会重新接流量。
更新和故障恢复期间会有短暂不可用，`Ready=True` 只表示当前 revision 已可用。
不要通过手工修改 Deployment 将副本数扩展为多副本，也不要把同一外部身份无边界
地共享给多个团队。

## TLS 和密钥处理

Operator 自管证书时，叶子私钥只应存在于受限 Secret 并挂载到 Server；客户端
只获取 CA。使用 `spec.tls.secretName` 时，Secret 必须是同命名空间的
`kubernetes.io/tls`；Operator 会校验密钥匹配、`ca.crt` 信任链、有效期、
ServerAuth 用途和 `<name>.<namespace>.svc` SAN，任何一项不满足都会使
`TLSReady=False`。轮换由外部证书流程负责。
轮换期间应确认 Server 重新加载新 Secret，并让客户端刷新 CA/连接池。

Operator 命名空间的 `supek8smcp-serving-ca` 是所有自管叶子的共享根 CA，包含
`ca.crt` 和 `ca.key`，没有随单个 CR 自动删除的 owner reference。应限制其读取、
纳入备份和密钥轮换流程。根 CA 不会在到期前自动替换；计划中的替换需要运维删除或
替换该 Secret，并刷新客户端信任。只有 controller ownerReference 指向同一 CR 的
自管 TLS Secret 才会被校验或轮换；同名但不受控制的 Secret 会被拒绝，端点安全失败。
删除根 Secret 会生成新根并触发受控叶子重签，客户端必须在轮换窗口重新获取各 CR 的
CA ConfigMap。自管根 CA 有效期约 5 年，叶子约 90 天，剩余不足 30 天时由 Operator
重签；轮换期间要验证客户端能重新建立 TLS 连接。

Operator 对 Secret、固定 TokenReview ClusterRole 和动态 ClusterRoleBinding 使用
实时单对象读取，不把完整 Secret 或集群 RBAC 对象放入共享 informer cache。其 RBAC
不允许列举或 watch Secret；因此外部 TLS Secret 轮换不是事件触发，而是在最多约
5 分钟的调谐周期内发现并滚动 Server。ServiceAccount、Service、ConfigMap、
Deployment 和 NetworkPolicy 的 informer 只 watch 带 Operator 管理标签的对象，
调谐读取仍直连 API，既避免缓存全集群同类资源，也能发现并修复标签漂移。

如果必须导出诊断包，先脱敏 YAML、Secret、token、headers、资源数据和 exec
输出；原始包只能进入受控的加密存储，并设置保留期限。

## 运维安全清单

- [ ] 镜像使用固定 tag/digest、来源可验证，并以非 root、只读根文件系统等
      集群基线运行（具体安全上下文以部署清单为准）。
- [ ] Operator 和 Server ServiceAccount 使用最小 RBAC；客户端身份不复用它们。
- [ ] Server 位于专用受限命名空间；普通租户不能在其中创建 Pod、挂载 TLS Secret
      或使用 Server ServiceAccount。
- [ ] 所有 CR 显式评审 `mode`、`scope`、`policy`、`sensitiveReads` 和 limits。
- [ ] 默认保留 `Redact`，只有有审批、短窗口和审计的场景才启用 `Allow` 或
      `Dangerous`。
- [ ] `ca.crt` 以只读配置分发，TLS 校验不关闭；token 在 Secret 管理器中轮换。
- [ ] NetworkPolicy 只放行受控入站来源；另行验证 Server 到 kube-apiserver/DNS 的
      Egress 连通性，入口不记录凭据。
- [ ] 监控 TokenReview 失败、403、确认码错误/锁定、plan/commit 失败、exec 超限和证书轮换事件。
- [ ] 收集 `audit_schema=v1` 日志并限制访问；启用可选 PrometheusRule 后根据业务
      基线调整认证失败、授权拒绝、限流和工具错误阈值。
- [ ] 卸载 CRD 或删除 Dangerous CR 前，先导出配置和审计记录并确认影响范围。

## 安全故障排查

- **401**：检查 Bearer header 和 token 是否过期或无效；不要通过改成 Operator
  token 来“修复”。**503** 表示 TokenReview/委派客户端不可用，或请求等待
  `maxConcurrent` 超过 `requestTimeout`；结合审计 reason 检查 kube-apiserver
  连通性、Server ServiceAccount 权限和并发占用。
- **403**：用同一 ServiceAccount 执行 `kubectl auth can-i`，然后检查 CR scope、
  policy 和 mode；权限取交集，任一侧不足都会拒绝。
- **TLS 错误**：核对 `status.caConfigMapName`、CA 内容、证书密钥匹配、信任链、
  ServerAuth、SAN/有效期和客户端 ServerName；BYO Secret 任一校验失败都会使
  `TLSReady=False`，不要使用 `-k`。
- **plan/commit 失败**：检查确认码是否为人类复述的 6 位数字、是否已因 5 次错误
  被锁定，以及计划是否超过两分钟、已被提交或身份已变；重新 plan，不要重放旧计划。
- **exec/attach 失败**：确认 Dangerous、目标资源合法、非交互、超时/字节/并发
  预算未超限；TTY 和 port-forward 等未实现功能不会通过配置启用。
