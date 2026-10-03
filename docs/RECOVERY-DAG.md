# 重复恢复的平坦来源图合同

本文先作为待审阅的实施合同。现有 `issuer-recovery-v1`、Proof2、Proof3、恢复 transition-v1/recovered-v1 的类型、规范字节与向量保持原义。本合同的密码学实现与 HTTP、手机、CLI 接入分别验证；保存本文不代表这些新入口已经可用。

## 必须完成的用户路径

原初始化 A/X → 连续恢复并显式登记管理设备 E → E 新增或轮换环境 Z/X、批准 F → 丢失设备后用当前恢复码再次恢复 → 完整新码回填并完成连续轮换 → 显式登记 G → G 可管理所选环境、批准设备并作为全环境 Admin 再次轮换恢复码。

第一层 E/F 普通管理复用现有 Proof3，原 grant、mutation、environment-change 和 origin 原语不变。第二次恢复及恢复设备发起的全环境轮换必须能引用此前恢复设备的身份与权限；旧接受前 `issuerEvidence:Proof2` 不能表示这些来源，不能用目录补钥或把 E 变成原 root。

只用已有 Ed25519、确定性 UTF-8 JSON 数组、SHA256、用途派生恢复钥和既有 HPKE。恢复签名钥不作为 vault key；不新增见证或账号策略。

## 版本与迁移提案

新能力固定 `issuer-recovery-dag-v1`，普通完整图 profile 固定 `harmonia/issuer-proof/v4`。新恢复签包使用 v2 域；新来源叶使用独立域。现有 v1/v2/v3/v4 证书及原 HTTP parser 不接受本合同材料，不默默扩字段、降级或重解释旧向量。

整个协议 major 尚无正式线上协商字段。本合同提出：旧合同归协议 major 1，DAG 合同归新 major 2；产品版本独立。接入前实现独立的 `GET /protocol-info`，返回 `{supportedProtocolMajors:[1,2],capabilities:{"1":[...],"2":["issuer-recovery-dag-v1"]}}`。客户端与服务器选共同支持的 major，DAG 操作只允许共同 major 2 与该 capability；没有交集拒绝远端同步/写入并提示升级。已需 DAG 的受保护状态不能降到 major 1。双方每请求/响应明确 `Harmonia-Protocol-Major: 2`，能力仍按该操作严格检查。该数字及协商字段是接入提案，不把当前 URL 的 `/v1` 或证书数字当作已实现的协议 major。

建议独立 `recovery-authority-challenges-v2`、`recovery-authority-transitions-v2`、`recovered-device-challenges-v2`、`recovered-devices-v2` 路由及原操作 ID 查询，只有新能力接受新 wrapper；旧路由维持原 schema。普通配对使用独立 `pairings-v5`，证书版本 `"5"`、capabilities 精确 `["issuer-recovery-dag-v1"]`，固定 `harmonia/device-enrollment/v5` 域和原 16 项顺序，末项绑定 Proof4 hash。同账号/设备/操作 ID 跨 profile 不形成新写；内容不同报冲突。

## 来源分支与平坦材料

所有字段 exact，数组不能省略或为 null；只有下文明确允许的指针可为 null。

```text
RecoverySource =
 {kind:"proof2",proof:IssuerProofV2}
 | {kind:"proof3",view:RecoverySourceView}

RecoverySourceView = {
 profile:"harmonia/issuer-proof/v3-source/v1",
 accountId,accountGeneration,initializationHash,trustRoot,recoveryHeadHash,
 path,authorities,targets,origins,identityPaths,dependencies
}

Dependency = {
 kind:"transition-v1"|"recovered-v1"|"transition-v2"|"recovered-v2",
 referenceHash
}

RecoveryDependencyBundle = {initialization:OriginalInitialization,records:Record[]}
Record = {kind:"transition-v1",record:AcceptedRecoveryTransition}
       | {kind:"recovered-v1",record:AcceptedRecoveredDevice}
       | {kind:"transition-v2",record:AcceptedRecoveryTransitionV2}
       | {kind:"recovered-v2",record:AcceptedRecoveredDeviceV2}

IssuerRecoveryDAG = {
 profile:"harmonia/issuer-proof/v4",accountId,accountGeneration,
 initialization:OriginalInitialization,source:RecoverySource,records:Record[]
}
```

`proof3` 表示有恢复身份来源的分支；其 view 是新类型，不是对旧 `IssuerRecoveryProof` 的兼容反序列化。view 不含完整 record、嵌套 Source 或其它 bundle。依赖表只保存每个完整已接受包一次。paired archive 仍只保存证书标量、对应 grants 和双签，不含完整旧 approval proof。path/authority/target/origin 行沿 Proof3：authority 最后字段 `recoveryEnrollmentHash` 只能引用已验证恢复记录；普通 genesis、委派与 origin 节点为空。

来源的 `initializationHash` 精确等于 bundle 唯一 originalInitialization 的原引用。根 Ed/X 保持原双签初始化承诺。view 的 TrustRoot 与 `recoveryHeadHash` 指向的已认证历史恢复链尾精确相同；主体身份及权限可引用该链尾之后、当前接受前的已接受设备。旧 v1 new-only gap 只能通过明确 ALL Admin manager-reanchor 连接，不能作为历史 head。其差异公钥只在 legacyState 与管理签授权中处理，不能成为隐式恢复锚。

新 transition submission 仍为原九字段结构，但 `transition` 使用独立 `RecoveryAuthorityTransitionV2`，`issuerEvidence` 改为 `RecoverySource|null`。old-recovery 保持 authoritySet `[]`、issuerEvidence `null`、相应标量空字符串，必须连续旧码授权；ALL Admin 要求非空来源。新 recovered submission 仍为原九字段结构，但 certificateVersion 固定 `"5"`、capabilities 固定新能力，enrollment 使用 `RecoveredDeviceEnrollmentV2`，issuerEvidence 是非空 `RecoverySource`。新 HTTP command 为 `{submission,dependencyBundle}`，不能送入旧九字段路由。

## 固定规范编码

`J` 是无空白 UTF-8 JSON，`H=SHA256(J(...))` 小写 hex，`b64` 为无 padding base64url。标量沿既有规范全部为字符串；接受序号 DTO 使用 JS 安全范围正整数，规范行转十进制字符串。

```text
SourceBytes(proof2) = J(["harmonia/recovery-source/v1","proof2",
 "harmonia/issuer-proof/v2",b64(originalProof2Canonical)])
SourceBytes(proof3) = J(["harmonia/recovery-source/v1","proof3",
 "harmonia/issuer-proof/v3-source/v1",b64(ViewCanonical)])
SourceHash = SHA256(SourceBytes)

ViewCanonical = J([profile,accountId,accountGeneration,initializationHash,
 rootRow,recoveryHeadHash,pathRows,authorityRows,targetRows,originRows,
 identityPathRows,dependencyRows])
dependencyRow = [kind,referenceHash]

Proof4Canonical = J([profile,accountId,accountGeneration,
 initializationRow,SourceHash,recordRows])
recordRow = [kind,referenceHash,b64(recordSigningBytes),signature1,
 signature2,acceptedSequence]
```

root/init/path/authority/target/origin 行保持现有独立类型的固定编码。dependencyRows 和 recordRows 按 `(kind,referenceHash)` ASCII 升序；同 hash 不能以另一 kind 重复。共享身份路径允许精确公共前缀，整条重复路径、同 device 不同证书或不同双公钥拒绝。

transition-v2 固定 `harmonia/recovery-authority-transition/v2` 域及现原 24 标量顺序，共 25 项；issuerEvidenceHash 引用本合同 SourceHash。其 ref 为 `H(["harmonia/recovery-authority-transition-ref/v2",b64(signingBytes),authorizationSignature,newRecoverySignature])`。

recovered-v2 固定 `harmonia/recovered-device-enrollment/v2` 域及现原 17 标量顺序，共 18 项；issuerEvidenceHash 引用 SourceHash。其 ref 为 `H(["harmonia/recovered-device-enrollment-ref/v2",b64(signingBytes),recoverySignature,deviceSignature])`。

manifest、ALL Admin 权源集合、封套、TrustRoot、恢复角色选择、普通 grants 的 hash 仍各用原独立域。不能只信行内摘要：完整 DTO 每个引用集合重新计算，与签包中 hash 相等。v1 记录调用原 parser、原 canonical/ref 验证；不得把新域改回 v1 来重用签名。

## DAG 依赖与接受次序

先独立验证受保护 original root pin、原初始化双签、sequence=1、完整 proposalHash 和精确原 genesis grant 集合。此集合永久冻结，candidate 不能新增 root selfAdmin。

然后按由签包推导的 `expectedSequence+1` 数值升序处理 record，接受序号字段必须精确一致。同序号两个记录、同操作 ID 跨 record 重用、引用缺失或冲突拒绝。接受中间普通数据写入可留下序号空隙；不能因此把当前声明值当成已接受权源。

直接依赖定义为：

- transition 的 previousTransitionHash（原初始化 hash 无需 record）；
- recovered 的 recoveryTransitionHash；
- SourceView 的 recoveryHeadHash（原初始化 hash 无需 record），以及 path、identityPaths、authority 中每个非空 recoveryEnrollmentHash。

view.dependencies 必须精确列出该 view 的非初始化直接依赖，不多、不少、不重复，kind 必须匹配对应 node。节点必须已经接受：依赖 acceptedSequence <= 本操作 expectedSequence，严格小于本节点 acceptedSequence。图处理采用迭代拓扑和 memo，不递归展开完整证明。源图 origin 的 `expectedSequence+1` 也不得超过该来源截止序号。旧 paired archive 的接受时间不能从服务器裸时间推断；服务器还必须与原始已接受归档及其历史序号精确比对。

外层完整 graph 的所有 records 必须属于 source 的完整传递闭包；未引用节点拒绝。该闭包包含必要恢复链前缀、历史恢复设备及其来源。内部每个 record 仍引用不可变的原 source view，而不是后来的当前图。缺少依赖不能用 global Managers 或目录补全。

旧 record 来源 Proof2 的类型自带不递归性质；新来源只能为 Proof2 或 leaf view。不存在把完整 Proof4/其它 bundle 塞回 record 的字段。历史链可任意交错 transition→recovered→transition→recovered，但受容量约束。

## 权限和回放门槛

历史身份、历史有效 Admin/RO/RW 授权可用于验当时签名，后来到期/降权/撤销不删除历史证据。新写或轮换不能以历史有效替代当前有效：ALL Admin 必须在当前全部环境逐项匹配 actor、KV、GG、role=Admin、expiry 和完整封套清单，客户端签前与服务器事务内都检查。root 身份本身不代表全账号 Admin。

old-recovery 的旧签钥必须精确来自原初始化或已验证连续链，manager-reanchor 需完整可验 ALL Admin，当前输入码与服务器 current pub 不能修复 v1 断链。新恢复码仍须完整重输，授权签与新持钥签为同一固定原文。恢复设备仍先受限，再显式选择环境/角色/期限、自签 grants、验全部设备 HPKE，并以恢复钥/设备钥双签原子登记；接受不自动制造 device-bound session。

保留仅进程内 old Ed 用途钥、短 TTL 和逐次系统认证。HPKE 接收私钥在 Begin 后清除。种子/完整码/old private 不序列化。原签包先密封再 POST，签包密封成功立即清 old private；结果不明只查原 ID/重试原包。进程被杀、过期或所需 KV 改变需重新开始恢复，不从磁盘恢复私钥。

originalInitialization hash、原根双公钥、account generation 不变。已有 recovery head 必须在 candidate 中以精确 hash/序号/公钥保留；新最新 head 不得回退。Cloud auth/data 检查点、权限指纹、本机 epoch、暂停规则与同一 AES/Engine 原子 commit 均继续独立检查。首见 head 不证明服务器绝对最新或未隐藏未见环境；不新增外部 witness 承诺。

当前普通环境删除最后一项已有 409 gate、初始化至少一项；本合同保持非空 manifest/明确非空恢复设备选择，不以空权限集合真空获得 ALL Admin。将来开放零环境须独立账号级管理合同。

## 容量与失败原子性

完整命令/图 JSON 和 canonical 最多 2 MiB；严格 UTF-8、重复对象键、未知字段、尾随内容和 JSON 深度 64 检查。transition 最多 128，recovered 最多 128，DAG 合计最多 256 节点、8,192 直接依赖边、图最长路径 256。每 view 权源最多 1,024、origin 最多 128、identity branches 最多 32、单 path 最多 32、总 archive 最多 256；manifest/targets/每组清单最多 256。

每个节点只验证一次。超过任一边界明确失败，不截断旧链或退回旧 profile。服务器 challenge 冻结 source/闭包/head/seq，接受事务再次核对原 accepted history、当前完整环境/权限集合及原恢复代际；SQL 持久化失败不切换公钥或部分封套。跨 route/idempotency 同一原包不能成为新写。

## 验证范围

密码学切片必须实际执行两次连续恢复、第二次显式恢复设备、恢复设备 ALL Admin 第三次轮换，并包括 E 新环境 origin 的权限来源及密文实际 HPKE/AEAD 解密。必要负例是原根/初始化替换、跨代际、依赖缺失/错误 kind、循环或向前引用、unused record、partial ALL Admin、过期当前权限、公钥重用、完整封套缺项、旧 parser 拒新包及 bound。

之后独立真实 HTTPS/SQLite、正式 CLI daemon/boot/pull/write、手机 native 系统认证/进程句柄与丢响应原包重试验收。这些产品测试未跑时只能报告密码学切片通过。
