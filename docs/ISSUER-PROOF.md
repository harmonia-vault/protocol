# 多管理设备的逐环境签发者证明

本切片实现 `cryptox/issuer_proof.go`、Go v2 入网控制器、逐环境 verifier、受保护完整回执及重启验证，并提供合成 Go/Node 向量。新设备 C 经管理手机 B 批准后，可以验证历史管理者 A 的精确签名与接收公钥。旧 v1 入口保持单管理者 pin。真实手机多管理批准界面与全部平台安全门槛仍需分别验收，不能宣称生产可用。

## 信任从哪里建立

C 的第一个可信输入是本机真实 SPAKE2 双向确认的 B：已冻结账号代际、会话、用途、挑战 nonce、期限、两端独立 Ed25519/X25519 公钥及 transcriptHash。仅登录成功、HTTPS、服务器公钥目录或服务器返回的 `TrustRoot` 均不能建立这个锚。

B 在本次 v2 入网证书中签署完整 `issuerProofHash`。C 首先以本机已确认的 B 签名公钥验证该证书，然后才验证证明内容。证明中的历史 B 入网证书包含 B 自己的 initiator 签名，精确固定其父管理者 A 的两把公钥；每个父子节点都有两端证书签名，路径最后一端必须精确等于本次已确认的 B。这使祖先身份受 B 的确认和历史双签约束。

批准端也必须有信任边界：B 只能对本地受保护既有根 pin、已确认 PAKE 和已经验证的逐环境权限证据签名。`SignEnrollmentApprovalV2` 要求 `PinnedIssuerRoot` 和 `ConfirmedEnrollmentAnchor`，先核对根设备 ID/Ed/X 双公钥、账号与代际，再验证路径和权限图，验证成功后才返回签名。禁止从服务器复制一个新 root 来填这个 pin。底层 `SignEnrollmentCertificateV2` 只是标准签名助手，批准工作流不能用它盲签服务器提供的数组或摘要。

证明中的恢复公钥只作为 B 确认的根声明元数据检查自洽性。`VerifiedIssuerProof` 不输出恢复授权锚，不提供恢复签名能力，也不使用恢复签名种子作 vault 钥。可信恢复钥仍由独立的初始化、既有受保护恢复资料或用户恢复种子流程提供。

## 明确的兼容边界

本扩展要求双方显式共同支持 capability `issuer-proof-v1`，使用 `certificateVersion: "2"` 和 `harmonia/device-enrollment/v2` 签名域。SPAKE2 原语 profile 保持 `boringssl-spake2-edwards25519-draft02-v1`；证书版本与原语 profile 分别表达，不把草案原语冒称 RFC 9382。

既有 v1 schema 和签名域保持原义，不能在未知字段中携带证明、静默扩充 `Managers` 或把 v2 签名当成 v1。需要此能力却没有共同支持时，入网和相关远程操作拒绝，并明确提示能力缺失；不能为多管理流程降级成单一签发者猜测。v2 使用独立 `/v1/accounts/:id/pairings-v2` 路由。开始请求采用原有五字段再加 `certificateVersion:"2"`、`capabilities:["issuer-proof-v1"]`；每次状态也必须明确这两字段。批准请求为 `{certificateVersion,capabilities,grants,transcriptHash,issuerProof,signature}`，完成请求仍为 `{signature}`，中继仍为原有四字段。v1 路由拒绝未知 v2 字段，v2 客户端拒绝任何降级或能力缺失。产品版本、整个协议 major 的协商属于独立机制，不由本证书版本代替。

## 公开数据结构

`IssuerProof` 包含以下精确字段：

- `profile`：固定 `harmonia/issuer-proof/v1`；`accountId`、`accountGeneration`。
- `trustRoot`：现有根声明，含根设备两把公钥、恢复代际/两把公钥和恢复签名。
- `path`：按根到本次管理者排序的已完成入网节点。每项为 `{certificateVersion,issuerProofHash,approval}`。v1 项的摘要必须为空；v2 项保留历史 v2 证书签过的摘要。`approval` 使用原有完整包装对象，必须具备两端签名。
- `authorities`：`{grant: SignedGrantWire,parentHash}`，每项都是精确 `admin` 授权。`grant` 内仍采用嵌套 `{grant,signature}`。
- `targets`：`{environmentId,authorityHash}`，把本次新设备的每个环境授权绑定到本次管理者的精确 Admin 证据。

当前 `EnrollmentApprovalV2` 是新类型，字段为 `{certificateVersion,context,pairingProfile,transcriptHash,grants,issuerProof,approverSignature,initiatorSignature?}`。审批阶段允许尚无 initiator 签名；完成后必须保存两端签名。上下文的用途固定为 `enroll-device`，由固定入网域及严格用途检查约束，不能挪用为恢复、登录或其它会话。

## 确定编码

所有签名和摘要采用紧凑 UTF-8 JSON 固定数组。标识是现有 ASCII 标识规范，代际是规范正十进制字符串，公钥、签名和封套是规范无 padding base64url。v2 证书沿用 v1 字段顺序，替换域并在末尾追加证明摘要：

```text
["harmonia/device-enrollment/v2",pairingProfile,accountId,accountGeneration,
 sessionId,challengeNonce,expiresAt,initiatorDeviceId,initiatorSigningPublicKey,
 initiatorReceivingPublicKey,approverDeviceId,approverSigningPublicKey,
 approverReceivingPublicKey,transcriptHash,grantsHash,issuerProofHash]
```

每项权限证据的标识为：

```text
authorityHash = SHA256(JSON([
  "harmonia/issuer-authority/v1",base64url(canonicalGrantBytes),signature
])) // lowercase hex
```

证明摘要编码为：

```text
["harmonia/issuer-proof/v1",accountId,accountGeneration,
 [base64url(canonicalTrustRootBytes),trustRoot.signature],
 pathRows,authorityRows,targetRows]

pathRow = [certificateVersion,base64url(canonicalCertificateBytes),
           approverSignature,initiatorSignature]
authorityRow = [environmentId,subjectDeviceId,grantGeneration,
                base64url(canonicalGrantBytes),signature,parentHash]
targetRow = [environmentId,authorityHash]
```

路径保留原顺序。权限证据按环境 ID ASCII 顺序、设备 ID ASCII 顺序、授权代际数值升序排序；目标按环境 ID ASCII 顺序排序。`grantsHash` 继续采用现有精确授权排序规范。v2 历史节点的旧证明摘要已被该节点双签冻结；不能把其历史证书签名改用 v1 域。

## 身份、权限和历史检查

路径检查账号代际、固定用途、全部双公钥、父子连续性和双签，拒绝重复设备 ID、任何设备公钥复用、循环或换公钥。每个历史入网节点的授权都须绑定该节点新设备的精确双公钥，并由其父管理者签名。

权限图只允许根设备精确自签 `admin` 作为无父节点。非根节点必须以 `parentHash` 引用已验证的同环境、同 keyVersion 的 Admin 证据，父项 subject 必须是本项 issuer。每个 subject 双公钥必须对应已经验证的设备路径，授权期限不得超过父项期限。图可以无序传输，验证器拒绝循环、缺父项或自造无父 Admin。

允许历史不同 grantGeneration 共存，但同一环境/subject/grantGeneration 不得出现不同签名字节；同一 issuer/idempotencyKey 也不得在路径、权限证据和本次授权中分叉。当前目标必须与本次管理者、环境和 keyVersion 精确匹配，不能把一个环境的 Admin 推广到全部环境。

已完成旧证书的挑战即使过期仍可验证历史签名；这不意味着旧设备现在未撤销、旧 Admin 现在有效或账号代际可以回退。结果类型仅提供逐环境 `IssuerBindings` 和 `VerifyDelegatedGrant` / `VerifyHistoricalGrant`，没有 `Active`、当前管理权或全局 `Managers` 入口。历史签名的验证也不证明服务器接受时刻；接受顺序和当前权限仍由对应业务机制和本地已见检查点处理。

服务器批准和最终完成必须在同一个账号事务中再次检查当前设备未撤销、账号代际、精确双公钥、当前逐环境 Admin、期限、keyVersion 和 grantGeneration，并把每个 target 指向的管理者授权与当前持久化授权精确比较。不能用 proof 中历史 Admin 项代替这一检查。客户端持久化须保留完整原始 v2 证明、双签收据、精确本机设备绑定和已见检查点；重启从受保护收据重新验证，不能从服务器目录补 pin。

## 有界验证和本切片限制

路径最多 32 项，Admin 证据和目标分别最多 256 项，完整解码输入与规范证明编码分别最多 262,144 字节。输入解码拒绝未知字段和尾随 JSON；传输仍须限流和单次短时挑战。这里不声称已经增加 JSON 重复字段专用解析器。

本切片支持同环境、同 keyVersion 的根自授权→A 授 B Admin→B 授 C 链，以及继续包含既有 v2 双签节点的路径。根精确自签 Admin 可以作为对应环境/版本的无父来源，但仍不能单独证明服务端当前接受状态。非根创建新环境和跨 keyVersion 轮换需要精确的已签 `EnvironmentChange` 证据来建立新来源；此切片尚未实现该扩展，缺相应来源时保持拒绝。撤销后的历史公钥不能删除成无法验历史的目录条目，但也不能因为保留历史公钥恢复当前权限。

## 真实测试结果

2026-10-02 20:09 UTC，Go 1.26.4：`core-go/cryptox` 的 `mise run test-issuer-proof` 7 项、29 个负例子测通过，0 失败。公开向量中 HPKE/AEAD 由 Go 成熟原语真实生成；C 解开自己的封套，验证 A 的历史签名并解密历史值；额外正例验证含历史 v2 节点的 A→B→C→D 来源和 D 的真实 HPKE 绑定。期限、代际/幂等分叉、循环、换双公钥、跨环境扩权、未完成收据、未知字段、超限和降级均被拒绝。

`protocol` 的 `mise run test` 14/14 通过，其中新增 4 项使用 Node 标准 crypto 独立核对 Go 的固定数组、摘要、Ed25519 双签及证明篡改/域降级。向量的 transcript 为公开合成摘要，不证明真实 PAKE 成功。

2026-10-02 20:33 UTC 后，本组件完成 Go 正式接入：`NewEnrollmentV2/ResumeEnrollmentV2`、`EnrollmentReceiptV2`、`NewPinnedVerifierV2(IssuerPinnedTrust)`；受保护 `TrustContext` 显式保存证书版本 2、空 `Managers` 和完整回执。仅允许同一回执的 accepted 状态从 false 变为 true，不能更换证明或全局公钥集合。后台重启复验精确本机双公钥及完整双签来源；新 CLI 配对使用 v2，旧 v1 待完成回执使用原域恢复。

实际 `syncclient/mise run test-issuer` 6 项主测试、21 个子测通过，其中四个主测试和 17 个子测是新增 v2 边界；真实 AEAD/HPKE 读取 A/B 历史、过期与撤销移除当前环境、未知环境/版本/签发者拒绝、回执精确本机钥绑定和严格 JSON/降级拒绝均覆盖。`test-native-enrollment` 2 项、5 个子测通过，v1 原有 2 个子测保留；v2 3 个子测用本机固定 BoringSSL 实际完成 SPAKE2、TLS、HPKE、正确/错误短码、显式降级拒绝和接受后结果未知的原回执恢复。`test-native-enrollment-race` 通过。这些测试的历史 A→B 资料来自公开合成向量，真实当前 B↔C transcript 由本机 PAKE 取得。

受保护 CLI 的新增重启测试通过，包含 pending 禁止联网、原回执 accepted 后关闭/重开、证明替换/全局 Managers/本机公钥替换/v1 降级拒绝。`core-go/mise run test` 全包通过，三平台默认 CLI 交叉构建通过；完整 `test-race` 中本组件及 syncclient/cmd/localkeys 均通过，但该次 localipc 原有并发断线测试报告 `invalid IPC protocol` 失败，已交对应组件处理，不能将该次完整 race 标为通过。

父任务另外报告真实 TypeScript/SQLite 与 Go SPAKE2 的 A→B→C 请求闭环通过，结果和后台进程验收以 workspace 记录为准；本组件不把父任务报告扩展为真实手机界面或跨平台验收。非根新环境与跨 keyVersion 来源仍保持拒绝，不能把以上通过结果宣传为生产可用。
