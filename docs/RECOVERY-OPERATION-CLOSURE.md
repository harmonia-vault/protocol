# 恢复原事务查询与终止契约 v1

这是实验性服务器合同。客户端冷恢复的原记录验证、显式终止意图、全状态 CAS 与退役尚未接通；本文不表示手机能够安全取消或重新开始恢复。

## 入口与当前授权

`POST /v1/accounts/{accountId}/recovery-operation-resolutions-v1?capability=recovery-operation-closure-v1`

请求选择 `Harmonia-Protocol-Major: 2`；此路由要求 major2，能力参数只能出现一次，禁止其他 query。成功及失败回应回显选择的 major。`/protocol-info` 的 major2 能力包括 `issuer-recovery-dag-v1` 和 `recovery-operation-closure-v1`。旧 parser 不得自动降级。

还需 `Authorization: Bearer <当前随机受限恢复session>`、`X-Harmonia-Account-Generation` 和 `Content-Type: application/json`。body 上限8192字节，拒绝非法UTF-8、重复JSON字段、未知字段与错误类型。响应三个独立字段集，正常长度小于4096字节。

受限 session 必须经过现有恢复挑战、当前完整码派生签钥签名证明，仍为 `rotationRequired=true`，恢复代际必须等于服务器当前值。普通密码登录、已经完成轮换的会话、过期/旧恢复代际会话均不能使用。每次请求在唯一账号事务中重新检查权限；查询 accepted 也不例外。原 `originalSessionHash` 仅标识历史，不能当 bearer。

## 请求与原 target

body exact：`{version:1, mode:"query"|"resolve-or-close", target, deviceSignature}`。

target exact字段：

| 字段 | 限制 |
| --- | --- |
| profile | `issuer-recovery-dag-v1` |
| kind | `transition-v2` 或 `recovered-v2` |
| accountId、operationId、deviceId | 现有ASCII identifier规则 |
| accountGeneration | 正数规范uint64十进制 |
| originalSessionHash | SHA256原bearer UTF-8字节的小写hex |
| authorizationKind | `old-recovery` 或 `all-environments-admin`；recovered只能前者 |
| deviceSigningPublicKey、deviceReceivingPublicKey | 32字节规范base64url，无padding且两钥不同 |
| stage | `intent`、`challenged` 或 `sealed` |
| basis | 以下8字段，exact |
| declaredIntentHash | 本机原准备材料严格公开记录字节摘要；小写64位hex |
| knownChallengeHash | intent为空；challenged/sealed为小写64位hex |
| declaredContentHash | intent/challenged为空；sealed为既有原包接受摘要 |

basis exact：`initializationHash, expectedSequence, recoveryGeneration, recoveryHeadHash, recoverySigningPublicKey, recoveryReceivingPublicKey, dependencyBundleHash, environmentManifestHash`。generation规范正整数；expectedSequence还必须不超过JS安全整数上限；双钥各32字节且不同，其他摘要小写64位hex。

新建closed和accepted分支从原初始化和接受序号不超过expectedSequence的完整DAG历史验证basis。未来基点、缺祖先、错旧恢复双钥/head/gen/bundle均拒绝。新的当前受限会话可以查询旧恢复generation的原target；不能为查询修改target到当前generation。

`declaredIntentHash` 只绑定调用者公开声明，不是服务器见证；服务端没有原本机preparation时不能证明实际用户选择。transition挑战能验证原session、基点、恢复双钥、manifest和all-Admin历史身份；old-recovery挑战未记录新本机设备双钥，只能验证声明钥持有签名。recovered挑战精确记录目标双钥，但未记录完整selectedRights/期限/manifest，不能声称验证未见选择。无挑战时只有历史基点、当前恢复所有权及请求签名可验；closed只阻止同ID晚到操作，不证明从未发送。

## 规范数组与签名

`H(x)=SHA256(UTF8(JSON.stringify(x)))`，结果小写hex；`b64` 为无padding base64url。所有标量字符串，数组顺序固定，不签对象JSON。

```text
["harmonia/recovery-operation-target/v1", "1", profile, kind, accountId,
 accountGeneration, operationId, originalSessionHash, authorizationKind,
 deviceId, deviceSigningPublicKey, deviceReceivingPublicKey, stage,
 initializationHash, expectedSequence, recoveryGeneration, recoveryHeadHash,
 recoverySigningPublicKey, recoveryReceivingPublicKey, dependencyBundleHash,
 environmentManifestHash, declaredIntentHash, knownChallengeHash, declaredContentHash]
```

targetHash为以上数组的H，不含mode、新session或signature。deviceSignature用本机独立Ed25519签下面数组：

```text
["harmonia/recovery-operation-resolution/v1", mode,
 SHA256(当前bearer UTF-8字节).hex, targetHash]
```

签名防止中间人改mode/target，不赋设备管理权。新session重新查询仍使用同targetHash。客户端必须由原受保护记录计算target，不能信服务端返回的新pin/选择。

bundle摘要复用成熟DAG编码：

```text
H(["harmonia/recovery-operation-basis/v1",
 b64(canonical(initializationDAGRow)), b64(canonical(recordRows))])
```

known/observedChallengeHash是以下数组的H，expiresAt转规范十进制；manifest/admin/source摘要复用现有编码。old-recovery空Admin集为 `H(["harmonia/recovery-admin-authorities/v1",[]])`，source=null记空字符串。该空集摘要只用于此新挑战概括；旧授权签包继续按原规则拒绝空Admin权限列表。

```text
["harmonia/recovery-operation-challenge/v1", "transition-v2", accountId,
 accountGeneration, operationId, challengeId, nonce, expiresAt, sessionHash,
 authorizationKind, chainMode, authorizerDeviceId, expectedSequence,
 previousTransitionHash, oldRecoveryGeneration, oldRecoverySigningPublicKey,
 oldRecoveryReceivingPublicKey, environmentManifestHash, authoritySetHash,
 sourceHash, dependencyBundleHash]

["harmonia/recovery-operation-challenge/v1", "recovered-v2", accountId,
 accountGeneration, operationId, challengeId, nonce, expiresAt, restrictedSessionHash,
 expectedSequence, recoveryGeneration, recoveryTransitionHash, deviceId,
 deviceSigningPublicKey, deviceReceivingPublicKey, sourceHash, dependencyBundleHash]
```

sealed原内容摘要继续使用 `transitionHashV2` 或 `recoveredDeviceHashV2`，不改既有双签包/domain。

## 三态收据

公共exact字段：`version:1, profile:"harmonia-recovery-operation-resolution-v1", accountId, accountGeneration, kind, operationId, targetHash, state`。

| state | 唯一附加字段 | 语义 |
| --- | --- | --- |
| pending | 无 | 没有权威终态，不允许清原记录 |
| accepted | sequence:number、contentHash:string | 只返回原接受历史seq/hash；sealed必须原hash相同 |
| closed | sequence:number、observedChallengeHash:null或hex | 原ID永久消费，首次关闭seq不再变化；null仅未观察到挑战 |

已接受永远不被终止覆盖。intent/challenged没有完整原包时，accepted不能单凭hash/seq变设备可信或Applied；应另取完整历史并核原材料。closed不是接受证明或DAG节点，不赋权限、不完成轮换；仍须客户端显式终止确认及整体保护状态CAS。只有严格终态回应才允许后续客户端退役；timeout/未知错误不是closed。

## 原子性与旧入口

当前授权→同ID目录→已持久closed精确匹配只读返回；没有closed时才完整当前DAG→历史basis→accepted/挑战精确匹配→预算→`next(account)`→删除本ID未接受挑战并写墓碑→共同validator→UPDATE→COMMIT，均在同一账号事务。Node使用SQLite `BEGIN IMMEDIATE`；Workers使用per-account SQLite DO `transactionSync`。D1只有目录，不新增安全权威副本。

持久closed已由统一Store验证版本、完整target/hash、账号generation、接受序号与无挑战/accepted碰撞。当前新session/当前恢复generation与请求签名仍必须先通过；同targetHash还核规范target数组逐字段相等后才只读返回原收据。此分支不依赖后来当前DAG连续性：合法legacy单签rotation可能造成当前DAG gap，但不能改变原closed事实。新ID关闭与accepted分支没有该豁免，仍完整验证当前DAG及原历史basis。错声明、双钥、基点、accountgeneration或旧/普通会话不能借closed获回复。

只query不新增状态。submit先COMMIT可能使并发close旧session失效；此时鉴权拒绝，不能推断未接受。以当前完整新码建立fresh受限会话后查询才返回原accepted。close先COMMIT时任何晚到同ID挑战/提交在nonce和幂等分支前拒绝。持久化或回应未知时只能同target/originalID查询，不自动新nonce/重签/换ID。

共同guard覆盖十个写入口：`recovery-authority-challenges-v2`、`recovery-authority-transitions-v2`、`recovered-device-challenges-v2`、`recovered-devices-v2`；原v1对应四入口；`recovery-rotations`以及`recovery-rotations/{id}/complete`。同账号generation的ID跨kind/profile不能复用。其他旧route仍保持原DAGRequired/current权限门槛，不能笼统说所有旧路由426。旧GET status不改shape，不能凭accepted:false当closed。

仅新错误 `operation_closed`（409）和 `recovery_operation_state_invalid`（409）；绑定冲突沿 `idempotency_conflict`，容量沿 `account_capacity_reached`。当前session/代际错误沿既有固定分类。不要输出body/bearer/原服务器任意错误文本。

## 持久化、预算与兼容

account.data新增可选 `recoveryOperationClosures:{version:1,entries:{[operationId]:{version:1,target,targetHash,sequence,observedChallengeHash}}}`；只存closed，无accepted副本。读与写共同exact校验，未知version、坏hash、跨account/gen、重复closure seq、closure+challenge/accepted冲突全部failclosed。

联合新分配预算256：closed数量加五个挑战/rotation表的未接受ID集合size。保留挑战的真正accepted ID不占预算；碰撞不能因Set去重而静默合法。原五表各128写上限不变；历史总预留理论最多640。硬读上限640只兼容旧预留的预算中性challenge→closed转换，不允许新分配超过256。既有257总预留时可转换原challenge；新ID关闭/新挑战拒绝；满1MB账号文档时整个关闭回滚，pending保持。无TTL/LRU清理或驱逐墓碑。只有破坏性账号reset新generation可清旧账号文档，所有旧gen请求先失效。

旧持久账号无此字段正常读；一旦产生墓碑，必须所有写进程升级后才能运行。旧binary即便JSON保留未知字段也不执行guard，回滚会让晚到操作绕过终态；不存在能让未改旧binary可靠自阻塞的额外版本标记。本切片未提供安全旧writer回滚/混跑，属于部署阻塞，不能用旧schema=1承诺兼容。详见服务器实现说明的实际存储审计。

## 实际验证边界

[静态向量](../vectors/recovery-operation-resolution-v1.json)和[独立Node协议测试](../tests/recovery-operation-resolution.test.ts)验证固定字节、Ed25519绑定及三态字段。服务器六组NodeTCP/workerd及受影响回归结果见服务器 `docs/RECOVERY-OPERATION-CLOSURE-VALIDATION.md`。

未验证手机SDK/native whole-state closure CAS、冷退役、Go客户端/CLI、真实SMTP/线上DO、fsync硬件断电。服务器测试原接受包用成熟Ed签名与DAG验证；测试envelope为合成编码占位，不冒称HPKE/PAKE。
