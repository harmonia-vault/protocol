# 恢复授权连续链设计草案

状态：下一批实现合同，供父任务与服务端共同复核；本批不修改现有恢复轮换、入网或证明 profile。本文没有任何已实现或已测试承诺。

## 目标与信任锚

旧根设备私钥丢失后，恢复码必须仍可恢复环境数据，并由用户显式授权一台新的管理手机。普通客户端需要验证新手机的签权来源，不能直接信任服务器返回的当前恢复公钥或设备目录，也不能把新手机替换成旧根。

原账号的 root 设备 ID、Ed25519 和 X25519 公钥保持不变。连续链从原初始化的双签材料开始：原 root Ed25519 签名绑定 initialization proposalHash，proposal 精确承诺原恢复 Ed25519/X25519 公钥及原初始化授权；原恢复签名也验证同一 initialization proof。普通客户端只有已由 PAKE 确认的管理者证书及受保护回执所固定的根，恢复客户端则由用户完整输入恢复码认证当前 manifest 后固定同一个根。服务器目录不是第三种根来源。

后续恢复公钥的每次过渡都必须保留可验证的授权来源。新恢复签名只证明持有新种子派生的签名钥，不能单独证明旧恢复权限交给了新公钥。既有仅新码签名的 `recovery-rotation/v1` 历史不能被重新解释为这种连续证据。

拟新增独立能力 `issuer-recovery-v1`、证明 profile `harmonia/issuer-proof/v3`、证书版本 `4` 和独立恢复过渡/恢复设备入网路由。旧 profile、证书与路由保持严格原 schema；未知能力、缺过渡或旧记录不得静默升级、补签或降级。

## 过渡提案与固定签名包

提案 `RecoveryAuthorityTransition` 的标量全部为字符串：

```text
{accountId,accountGeneration,operationId,challengeId,nonce,expiresAt,
 sessionHash,expectedSequence,previousTransitionHash,
 oldRecoveryGeneration,oldRecoverySigningPublicKey,oldRecoveryReceivingPublicKey,
 newRecoveryGeneration,newRecoverySigningPublicKey,newRecoveryReceivingPublicKey,
 authorizationKind,authorizerDeviceId,environmentManifestHash,
 authoritySetHash,issuerEvidenceHash,envelopesHash,newTrustRootHash}
```

`authorizationKind` 仅 `old-recovery` 或 `all-environments-admin`。前者的 `authorizerDeviceId`、authoritySetHash 和 issuerEvidenceHash 使用规范空值；后者精确绑定一台已有可信管理设备及其全部环境 Admin 证明。`previousTransitionHash` 为原初始化锚摘要或前一个已接受过渡的摘要；每条新记录须精确接续，不接受省略中间公钥或跳代。newRecoveryGeneration 必须为旧值加一，旧两公钥精确匹配前一个可信状态。newTrustRoot 的 root ID/两公钥保持原值；只更新恢复代际、恢复两公钥和对应签名。

签名原文是固定域 `harmonia/recovery-authority-transition/v1`，随后按上述字段顺序排列的 UTF-8 JSON 字符串数组。签名、摘要和数组规范沿用既有协议，签名采用成熟标准 Ed25519；不增加密码原语或自行设计曲线运算。所有授权方与新恢复钥均签同一原文，不能把不同用途或不同封套清单的签名拼接。

完整 `environmentManifest` 为按 ASCII environmentId 升序排列的 `[environmentId,keyVersion]` 字符串行数组，仅包含接受前所有当前环境；完整 `authoritySet` 为同顺序的 `[environmentId,keyVersion,grantGeneration,expiresAt,authorityHash]` 行数组；`envelopes` 为同顺序的 `[environmentId,keyVersion,envelope]` 行数组。各 hash 使用独立引用域及完整规范行数组 SHA256；签名同时绑定三个集合，不能将权限集合和封套集合指向不同环境。issuerEvidenceHash 冻结标准证明完整规范字节与其 profile，不能只引用未验证的候选 hash。精确引用域在本文后半部固定，下一批实现须提供 Go/Node 静态向量。

HTTP 完成包附原提案、所引用 manifest、完整封套清单、必要控制面证明、授权签名和新恢复持钥签名。challengeId/nonce/operationId/sessionHash/旧恢复代际/expectedSequence 均由本次短时单次操作绑定。客户端重建固定签名原文，不盲签服务器返回数组。原操作 ID、签名包、封套和内容 hash 在首次提交前受保护持久化；断网结果不明先查原 ID，不生成新 nonce 或新包重复切换。

## 两种发起授权

### 用户持有旧恢复码

有效受限恢复会话可以发起。客户端由用户输入的旧恢复种子派生旧用途签名钥，验证它的公钥精确匹配已可信链尾，再用旧恢复 Ed25519 对本次完整过渡包签名。新种子须由用户完整重新输入，从重输种子派生新用途签名钥，对同一包签名。旧签名证明连续授权，新签名证明新私钥持有；两者都不证明用户真实备份了新码。

服务器再次核对当前旧恢复代际/两公钥、单次挑战、受限会话、expectedSequence 和完整环境/封套集合，并在一个账号事务中切换公钥、所有恢复封套和保持旧 root 双公钥的新 manifest。旧码在事务提交后才失效；回滚时全部保持原状态。该路径不要求旧 root 私钥或仍在线的旧设备。

### 已有可信管理设备不持旧恢复码

用户已允许可信管理设备轮换恢复码，但单个环境的 Admin 不能提升为整个账号恢复权限。发起设备必须对接受前每个当前环境都有有效、精确的 Admin 授权。其 Ed25519 签名对同一完整过渡包承担授权；新码重输派生的新 Ed25519 仍签同一包。

客户端首先验证 authorizer 的原根归档身份链、所有环境的 Admin 来源、每项 KV/GG/期限、精确设备双公钥及已见检查点，再签包。当前 root 身份本身不能替代全环境 Admin。proof 内的 historical Admin 也不能替代提交时仍有效的全环境 Admin。

服务器在完成事务内重新计算全部当前环境集合，逐项比较 environmentManifest 和 authoritySet；每条 Admin 授权须与当前已接受精确签名包一致，actor/current session、代际、撤销、期限和 expectedSequence 均重查。遗漏、多余、过期、降权、同角色换代、环境新增/删除、轮换或授权集合变化均拒绝原提案，用户须显式开始新操作。随后原子切换新恢复公钥/完整封套/新 manifest，并保存 actor 签名、精确权限来源及接受序号。

客户端验证历史已接受过渡时使用该记录冻结的身份、权限和序号，不因之后正常撤销就删掉有效历史链；当前新增签名仍必须通过服务器的即时权限检查。不能以现在恢复公钥或 unsigned server directory 补齐缺失的历史链。

## 旧轮换记录迁移

旧 v1 轮换仅新种子签名且旧会话授权由服务器执行，它不是新 profile 所需的公开连续证据。old-recovery 路径只接受能够从 original initialization 或已验证 transition 链认证的旧公钥。若 v1 new-seed-only 历史已打断连续链，用户手输当前有效码加服务器当前公钥仍不足以重建普通客户端来源；此时迁移只能由当前具备全部环境 Admin、具有可验证身份及权限来源的可信设备签新完整包，或保持受限。迁移提案冻结可信原初始化锚、原根、已有可信链尾、精确旧 v1 差异材料摘要、当前恢复代际/两公钥和全权限来源；消费者验证全权限设备授权后才接受这次明确的新连接。

不能替旧记录秘密补签、把 root 身份当全权限、用当前 server recovery pub 作锚，或声称已经找回不存在的连续证据。若当前设备只有部分环境 Admin，且可用恢复码及其它全权限来源都丢失，则该新管理授权路径保持阻断；仍可执行旧 profile 已有的受限数据恢复范围，不伪造普通客户端可验证的来源。

## 显式恢复设备入网

恢复过渡完成后仍是受限恢复状态，不能自动登记新管理手机。用户必须另外明确选择每个环境、RO/RW/Admin 角色及期限，并通过本机系统强认证保护新设备本地产生的独立 Ed25519/X25519 私钥。

拟定 `RecoveredDeviceEnrollment`：

```text
{accountId,accountGeneration,recoveryGeneration,recoveryTransitionHash,
 operationId,challengeId,nonce,expiresAt,restrictedSessionHash,expectedSequence,
 deviceId,deviceSigningPublicKey,deviceReceivingPublicKey,
 selectedRightsHash,grantsHash,issuerEvidenceHash,envelopesHash}
```

固定域为 `harmonia/recovered-device-enrollment/v1`，按上述顺序编码 UTF-8 JSON 字符串数组。selectedRightsHash 冻结用户明确选择，不接受服务端自动补全部 Admin；grantsHash 精确绑定新设备各环境授权签名包，issuerEvidenceHash 固定对应环境的当前来源控制图，envelopesHash 固定发给新设备的全部 HPKE 封套。精确引用域及新证明节点结构在本文后半部固定。

当前可信恢复 Ed25519 钥和新设备 Ed25519 钥分别签同一包。恢复方签名沿原初始化及全部过渡链获得明确的恢复用途权限；新设备签名精确绑定自己的双公钥、账号/恢复代际、会话、操作和全部选择。新设备必须成功解开全部选定 HPKE 封套、核对环境/密钥版本及当前来源证明后才签名；不能以服务器声明代替本地验证。恢复签名种子不是 vault 环境钥，恢复接收钥和设备接收钥也不混用。

服务器原子重查受限会话、当前恢复链尾/代际、单次 nonce、expectedSequence、每个选定环境当前版本、完整授权和封套，再接受新设备及权限。收到完整接受回执后客户端走相同签名验证/pull 下发流，将回执、来源账本、检查点和缓存一次受保护持久化，成功后才能标记可信。丢响应只查原操作；未明确完成、失权、取消或未知结果只返回元数据，不读写普通共享数据。

新 proof/profile 必须明确区分普通设备双签归档路径和恢复设备双签来源节点，沿同一原 root 和恢复过渡链验证；不能给已丢失的 root 私钥伪造签名，也不能换 Root。普通客户端仅为证明中对应环境和角色接受该恢复来源，不扩大全局 Managers 名单。

## 完整集合、检查点与已知限制

服务器的账号权威事务和 expectedSequence 保证正常服务下操作间没有集合竞态；本机已见账号 generation、数据/授权序号、环境墓碑、原初始化授权和过渡 hash 持久化，拒绝回退、缺已见环境或跨代际替换。暂停只接收经过验证的授权/来源账本，不前移数据序号或接收变量值。

签名能证明管理者声明了完整清单及服务器按该清单原子接受，但没有外部 witness 的新设备不能从密码学上证明服务器未隐瞒它从未见过的环境、未分叉账号历史或提供了绝对最新状态。该方案只做明确的根/代际/已见检查点和精确权限集合检查，不宣称恶意服务器全局一致性或复杂外部见证。历史有效授权不能追回已读明文；旧恢复码加旧密文副本同样不能被远程撤回。

## 实施前门槛

待审核准确 DTO、空值规则、全部引用域、proof v3/证书 v4 的恢复节点形式与归档边界；随后才做 Go/Node 确定向量、逐字段替换/跨代际/旧 nonce/缺全环境权限/回放/SQL 回滚/断网重查测试。真实手机强认证、重输新码和完全丢旧设备恢复入网还须独立端到端验收。现有生产入口继续拒绝未经该新方案验证的恢复管理设备登记。

## DTO、引用域和空值冻结

以下是下一批的明确实现合同，尚未实现；当前 profile 完全不变。

过渡标量在原提案末尾增加 `chainMode,legacyStateHash`。固定签名数组为域加前述 22 个标量、chainMode、legacyStateHash，共 25 项。`chainMode` 仅 `continuous` 或 `manager-reanchor`：

- continuous 要求旧两公钥/代际精确匹配从原初始化或已验证 transition 链得到的可信链尾，legacyStateHash 为空字符串。
- manager-reanchor 只允许 `all-environments-admin`。previousTransitionHash 仍引用已认证原初始化或已有可信链尾，但当前旧恢复状态可因 v1 历史断链而不同；该差异必须由 actor 对完整过渡包及 legacyStateHash 明确签名承担。它是经过全权限设备授权的新连接，不把 v1 历史变成旧恢复钥连续授权。

`old-recovery` 的 authorizerDeviceId、authoritySetHash、issuerEvidenceHash 固定为空字符串；authoritySet 固定 `[]`，issuerEvidence 固定 `null`。不能省字段、填零摘要或使用全权限设备签名冒充旧恢复签名。`all-environments-admin` 必须非空 actor ID、完整 authoritySet 和经验证的证明，hash 为规范小写 64 字符 hex；不能 null。所有数组显式编码为数组，合法空组为 `[]`；未知/重复对象字段、无效 UTF-8、尾随 JSON、超深或超限材料拒绝。

所有引用摘要精确采用 UTF-8 JSON 数组 SHA256，小写 hex：

```text
initializationHash = H(['harmonia/recovery-initialization-anchor/v1',
 b64(originalProposalCanonical),b64(originalInitProofCanonical),
 deviceSignature,recoverySignature,'1'])
environmentManifestHash = H(['harmonia/recovery-environment-manifest/v1',manifestRows])
authoritySetHash = H(['harmonia/recovery-admin-authorities/v1',authorityRows])
issuerEvidenceHash = H(['harmonia/recovery-issuer-evidence-ref/v1',profile,b64(proofCanonical)])
envelopesHash = H(['harmonia/recovery-envelopes/v1',envelopeRows])
newTrustRootHash = H(['harmonia/recovery-trust-root-ref/v1',b64(rootCanonical),rootSignature])
transitionHash = H(['harmonia/recovery-authority-transition-ref/v1',
 b64(transitionCanonical),authorizationSignature,newRecoverySignature])
legacyStateHash = H(['harmonia/recovery-legacy-state/v1',oldRecoveryGeneration,
 oldRecoverySigningPublicKey,oldRecoveryReceivingPublicKey,
 b64(oldCurrentTrustRootCanonical),oldCurrentTrustRootSignature,legacyRotationRows])
```

`legacyRotationRows` 每行 `[idempotencyKey,b64(originalV1RotationSigningBytes),newSignature,acceptedSequence]`，按 acceptedSequence 数值升序，不重复；它仅冻结差异材料，验证器不能把这些新钥单签当作旧钥授权。无 gap 时 legacyStateHash 为空。原 proposal、proof 的规范字节直接复用既有 Go/Node 合同；proof 的登录字段为 `loginTokenHash`，不是 server 内部的 sessionHash 记录名。

过渡 HTTP 完成包精确为：

```text
{transition,environmentManifest,authoritySet,issuerEvidence,envelopes,
 newTrustRoot,legacyState,authorizationSignature,newRecoverySignature}
```

其中 legacyState 在 continuous 固定 `null`；manager-reanchor 为 `{recoveryGeneration,recoverySigningPublicKey,recoveryReceivingPublicKey,trustRoot,rotations}`，rotations 保存上述原 v1 编码及签名/接受序号。已接受记录 `{submission,sequence}` 的 sequence 必须精确为 expectedSequence+1。过渡原文不会包含服务器自报的接受时间；历史有效性依原签名来源和已见单调序号，不将当前撤销解释成历史签名失效。

## 新证明与恢复设备节点

下一批 `IssuerRecoveryProof` 精确字段为：

```text
{profile,accountId,accountGeneration,trustRoot,initialization,
 path,authorities,targets,origins,identityPaths,transitions,recoveredDevices}
```

profile 固定 `harmonia/issuer-proof/v3`。initialization 保存原双签 DTO `{proposal,proof,deviceSignature,recoverySignature,sequence}`，sequence 必须为 1，与 initializationHash 一致；根 Ed/X 与独立受保护 pin 精确相同。transitions 是上述已接受记录数组；recoveredDevices 是下面的恢复设备双签记录。两数组按各完整引用 hash 的 ASCII 顺序规范排序，重复/冲突/回环/跨代际拒绝；依赖按 hash 定位，而不是相信数组顺序。

权限节点精确 `{grant,parentHash,originHash,previousGrantHash,recoveryEnrollmentHash}`。普通委派、原 genesis 和环境 origin 节点的最后字段为空，继续使用既有来源语义。恢复设备初始授权仅能使用非空 recoveryEnrollmentHash：grant 的 issuerDeviceId 与 subjectDeviceId 均为该新设备 ID，Ed/X 精确相同、GG=1、KV/角色/期限与恢复用户选择逐项相同；newdevice Ed 签普通 grant；对应双签恢复证书赋予这项明确来源。其它父字段为空，不得因此被解释为 root genesis。它只是该环境的权限节点，不是全局 root 或恢复管理锚。

设备归档 path 节点采用显式 tagged union：`{kind:'paired',enrollment:IssuerEnrollment}` 或 `{kind:'recovered',recoveryEnrollmentHash}`，未知 kind/多余字段拒绝。paired 的证书可为 1/2/3/4，4 使用新域 `harmonia/device-enrollment/v4` 和 proof v3 摘要；前者仍按原字节验证，不能将旧证书包装成 4。recovered 只能是 path 从原根出发的第一条边，先验证原初始化→连续过渡或全权限重连→恢复设备双签，不伪造 root 的 Ed 签名。其后 paired 节点由该设备作为 approver 签；历史审批仍需逐环境 Admin 来源。分支保持原根、精确公共前缀和双公钥不重用约束。

恢复设备完成包精确为：

```text
{enrollment,selectedRights,grants,issuerEvidence,envelopes,
 recoverySignature,deviceSignature}
```

enrollment 使用前述 17 标量和固定域。selectedRights 行 `[environmentId,keyVersion,role,expiresAt]` 严格按 environmentId 升序；grants 是对应新设备自签授权；envelopes 行 `[environmentId,keyVersion,envelope]`，与 grants 内的新设备 HPKE 封套精确相同。摘要为：

```text
selectedRightsHash = H(['harmonia/recovered-device-rights/v1',selectedRightsRows])
grantsHash = H(['harmonia/recovered-device-grants/v1',
 [[environmentId,b64(grantCanonical),grantSignature],...]])
envelopesHash = H(['harmonia/recovered-device-envelopes/v1',envelopeRows])
recoveryEnrollmentHash = H(['harmonia/recovered-device-enrollment-ref/v1',
 b64(enrollmentCanonical),recoverySignature,deviceSignature])
```

issuerEvidenceHash 沿上节引用域，引用接受前已有的完整控制图，不能包含尚未接受的自身节点。恢复记录 `{submission,sequence}` 的 sequence 必须为 expectedSequence+1，且新设备初始 grant 接受在同一个事务/序号。恢复两公钥、链尾与 recoveryGeneration 均精确匹配；两签绑定所有明确选择与新双公钥，不能把手机登录会话当信任。

proof v3 规范数组共 12 项：域/profile、accountId、accountGeneration、rootRow、initializationRow、pathRows、authorityRows、targetRows、originRows、identityPathRows、transitionRows、recoveredDeviceRows。root/target/origin 排序沿 v2；authorityRow 是 v2 八项后附 recoveryEnrollmentHash。paired path row 为 `['paired',certificateVersion,b64(certificateBytes),approverSignature,initiatorSignature]`；recovered path row 为 `['recovered',recoveryEnrollmentHash]`。initializationRow 为 `[initializationHash,b64(proposalCanonical),b64(proofCanonical),deviceSignature,recoverySignature,'1']`。transitionRow 为 `[transitionHash,b64(transitionCanonical),authorizationSignature,newRecoverySignature,acceptedSequence]`；recoveredDeviceRow 为 `[recoveryEnrollmentHash,b64(enrollmentCanonical),recoverySignature,deviceSignature,acceptedSequence]`。所有旁证引用的规范行集合必须在完整 DTO 中重算并与签名 hash 匹配，不依赖行中的裸 hash。

边界初定：环境与每组清单最多 256、transition/recoveredDevices 各最多 128、权限节点最多 1,024、身份归档总节点最多 256、单条 path 最多 32、分支最多 32、完整规范材料最多 2 MiB。开始新增过渡/登记前检查新记录仍可完整表示；超限拒绝，不丢旧链或静默截断。尚无历史压缩/外部 witness，不能宣传无限历史支持。

## 仅内存恢复会话生命周期

不新增可恢复磁盘持久化旧恢复私钥。曾讨论原生 AES 密封派生旧签名钥的方案未获授权，已经撤回，不能实现或把该私钥放入已有 encrypted record。

原生层持有 `RecoverySession`，Go 只在进程内保存用途派生的旧 Ed25519 签名私钥；不保存原恢复种子或完整码，也不把私钥/句柄返给 Dart、HTTP 或日志。句柄由原生对象管理，Dart 不得任意提供或替换。概念接口为 `BeginMemoryRecovery`、`PrepareTransitionWithSession`、`CompleteTransitionWithSession`、`PrepareRecoveredDeviceWithSession`、`CloseMemoryRecovery`；准确原生 ABI 在下一批实现前复核。Begin 完成 HPKE 解开并校验恢复材料后，立即清除恢复接收私钥；它不留在句柄中。已验证环境钥留在原受限保护缓存，仅用于同版本验值和恢复封套重封。若环境新增或 KV 轮换使这些钥不齐、需要新 HPKE 解套，关闭本次 nonce/session 并要求重新开始恢复，属于并发中断重试；不能静默增加驻留私钥种类或正常表单。同 KV 的普通值更新可用已有环境钥沿原下发流核验。

会话绑定原 protected record 摘要、restrictedSessionHash、账号/账号代际、恢复代际、原 root Ed/X、transitionHead、当前本地 epoch 和 native instance。每个操作仍须系统设备密码/强生物认证，检查绑定精确不变。TTL 同时受进程 monotonic 截止和服务器 15 分钟恢复会话期限限制；墙钟回退不能延长。busy 时不能并行签两个操作；跨账号/代际/epoch、句柄串用、失效会话、取消/退出/销毁均擦除私钥并拒绝。

Begin 不自动轮换；正常流程仍为一次完整旧码输入→受限→用户显式生成新码→完整新码回填→签同一 transition。过渡原包成功密封后立即清旧私钥，首次 POST 前也不再保留；attempted unknown 仅保存原 ID/原签包，用原包查询或幂等重试，不能另签 nonce。挑战已过期若需新授权，必须重启受限恢复流程，属于中断重试而非正常流程新增输入。

完整新码回填派生的新钥只在当前进程会话内使用。确认服务器接受、相同 pull 验证及最终 protected save 完成后，可在同一进程将新钥提升为新恢复代际的受限 RecoverySession，让用户另行显式选择环境/角色/期限并完成新设备双签；不会自动授权，也不会正常流程要求第三次输入新码。该 session 仍是受限恢复来源，不是可信设备或 Root 替换。

App 被杀或 TTL 到期后，私钥句柄不能从磁盘恢复。重启可依据已密封原签包查询已接受结果，不能签新过渡或新设备授权；若要继续新授权，用户重新开始输入对应有效恢复码。软件钥短时驻留进程内存，逐操作强认证和尽力清理不代表始终在硬件内或保证运行时所有副本彻底擦除。v1 断链时即使持有当前码，也不建立 old-recovery 普通客户端来源。

下一批必须新增正常流程一次旧码/完整新码回填、签后擦钥、unknown 原包重试、kill/restart 不恢复私钥、跨账号/gen/epoch/instance、单次 nonce、TTL/墙钟回退、busy/cancel/logout/失效及新设备未显式完成始终受限的负例；本批未跑这些新接口。
