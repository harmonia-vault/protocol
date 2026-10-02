# 环境来源证明与签发者证明 v2

这是实验性协议。本切片补足非初始管理设备创建环境、轮换密钥后的签名来源；当前实现和实测状态在本文末尾记录，不表示生产可用。

## 明确协商

新增能力 `issuer-origin-v1`，签发者证明 profile 为 `harmonia/issuer-proof/v2`，入网证书版本为字符串 `3`。新入网使用独立 `/v1/accounts/:id/pairings-v3`，创建/轮换使用独立 `/v1/accounts/:id/environment-changes-v2`。开始、状态与批准均必须明确证书版本 `3` 和能力 `['issuer-origin-v1']`，不能静默降级。旧 `issuer-proof/v1`、证书 v2 和旧路由仍按原 schema 严格解析，不接受新字段。

## 环境来源签名

`SignedEnvironmentOrigin = {origin,signature}`。origin 精确字段为 `accountId/accountGeneration/actorDeviceId/environmentId/operation/authorityEnvironmentId/authorityKeyVersion/authorityGrantGeneration/previousKeyVersion/keyVersion/expectedSequence/idempotencyKey/changeHash/authorityHash/before/after`。operation 仅 `create` 或 `rotate`。所有标量均为字符串，整数为无前导零十进制；摘要为小写 SHA256 十六进制，签名与公钥使用无 padding base64url。

标准 Ed25519 签名原文是 UTF-8 JSON 固定 17 项数组：

```
['harmonia/environment-origin/v1',accountId,accountGeneration,actorDeviceId,
 environmentId,operation,authorityEnvironmentId,authorityKeyVersion,
 authorityGrantGeneration,previousKeyVersion,keyVersion,expectedSequence,
 idempotencyKey,changeHash,authorityHash,beforeRows,afterRows]
```

`before/after` 是权限行对象数组，每行精确八字段 `subjectDeviceId/subjectSigningPublicKey/subjectReceivingPublicKey/keyVersion/grantGeneration/role/expiresAt/grantHash`；签名时转换为按相同顺序排列的八字符串数组。行必须按 ASCII subject ID 严格升序，重复或未排序拒绝。role 仅 `ro/rw/admin`，不是当前激活状态。每组最多 256 行。

`changeHash = SHA256(JSON(['harmonia/environment-change-ref/v1',base64url(originalChangeSigningBytes),originalChangeSignature]))`。`originHash` 同样引用完整精确原包，域为 `harmonia/environment-origin-ref/v1`。`authorityHash` 是接受操作前 actor 的精确 Admin 授权摘要，沿用 `IssuerAuthorityHash`。

来源证书只公开设备身份、权限、版本和来源摘要；绝不包含环境标签、变量名称、变量密文、恢复封套或环境钥。原环境操作仍单独签名，服务器同一事务验证两包关联并保存。

## 创建与轮换

创建要求 `previousKeyVersion='0'`、`keyVersion='1'`、before 为空、after 仅 actor 自己的 `Admin`，grantGeneration 为 `1`。接受前 actor 在 authorityEnvironment 中的 Admin 来源必须完整可证；新授权期限不得超过该来源。

轮换要求来源环境就是被轮换环境，authorityKeyVersion 等于 previousKeyVersion，keyVersion 加一。before 是接受前仍有效的精确接收者权限集合，after 是操作清单的精确集合；两组 subject、公钥、角色和期限逐项相等，每项 keyVersion 和 grantGeneration 分别加一。actor 的旧 Admin 必须在 before 中，其摘要等于 authorityHash。

验证新权限必须同时解析两条父边：actor 接受前 Admin，及该接收者的旧授权。旧接收者可能为 RO/RW，且原权限期限可以比临时 actor 更长；轮换保留该既有期限，不把旧永久授权收缩成 actor 的期限。普通新增委派仍要求 Admin 父授权，且期限受父授权约束。伪造 before、缺任一父边、跨账号或跨 generation、替换公钥、跨环境或版本均拒绝。历史证明不授予现在的权限；服务器每请求检查当前权限、撤销和到期。

## 证明图

`IssuerProofV2` 保留旧七字段 `profile/accountId/accountGeneration/trustRoot/path/authorities/targets`，新增 `origins/identityPaths`。authorities 节点精确 `{grant,parentHash,originHash,previousGrantHash}`。普通委派的最后两字段为空；创建节点引用 origin 且 previous 为空；轮换节点 parentHash 指向 actor 旧 Admin，previousGrantHash 指向 before 对应接收者授权。节点可存 RO/RW 历史前态，但只有 Admin 可签普通委派。

主 path 必须是根至本次已确认 PAKE approver 的归档双签证书链。identityPaths 每一分支也从相同已固定根出发，用归档双签精确绑定额外历史 actor 的 Ed/X 公钥，不采用服务器目录。证书节点可为明确的 v1/v2/v3；v3 使用域 `harmonia/device-enrollment/v3`，16 项字段与 v2 对应，最后一项冻结 proof v2 摘要。每个分支最多 32 节点，最多 16 分支，总归档节点最多 128；权限节点最多 512，origins 最多 128，总规范编码最多 1 MiB。重复分支、冲突身份、公钥重用、循环或缺证据拒绝；完全相同的归档证书可以作为不同分支的公共前缀。

规范 proof 数组为：

```
['harmonia/issuer-proof/v2',accountId,accountGeneration,
 [base64url(trustRootSigningBytes),trustRoot.signature],pathRows,
 authorityRows,targetRows,originRows,identityPathRows]
```

path 行沿用 `[certificateVersion,base64url(certificateBytes),approverSignature,initiatorSignature]`，authority 行为 `[environmentId,subjectDeviceId,grantGeneration,base64url(grantSigningBytes),signature,parentHash,originHash,previousGrantHash]`。authority 按 ASCII 环境、subject、数值 grantGeneration 排序；target 按环境排序。origin 行 `[originHash,base64url(originSigningBytes),signature]` 按 originHash 排序；分支按完整 pathRows JSON 字符串 ASCII 排序，各分支内顺序固定。外层证书的 PAKE 已确认 approver 签名先于接受其 root 声明；恢复公钥仅是元数据，不输出为恢复授权锚。

## 初始化锚与严格解析

空 parent 的根授权节点只能匹配受保护的原初始化授权签名包摘要集合：初始 KV=1、GG=1、永久 root self Admin 的结构检查还不够，root 在后来新建环境也能生成同结构签名。root 手机使用已接受原初始化 proposal 内的 InitialAuthorities；新入网设备在本次已确认 PAKE 的 approver 签名和设备自身双签完成回执核验后，才固定该回执明确承诺的原初始化集合。随后候选图不能增加任何新 genesis。仅传 root 公钥而没有精确初始化锚的公开图验证入口拒绝。

服务器也须与唯一已接受初始化记录核对，不能把当前 root self grant 猜作 genesis。原 root Ed/X 不变；图中的恢复公钥元数据不构成新的独立恢复锚。

所有五组 proof 数组以及来源 before/after 必须在 wire 中显式为数组；合法空组编码为 `[]`，字段遗漏和 `null` 拒绝。签名规范字节不依赖对象字段顺序，但入站 schema 仍拒绝未知字段、重复对象键（包括 Unicode escape 同名键）、无效 UTF-8、多 JSON 值、超深结构和超限材料。完整图不超过 1 MiB。

## 已有读者与持久化

入网回执始终不可变。来源增量保存在受保护证据账本；候选图必须从原受保护回执认证的根和精确本机双公钥重新验证，全部成功后才能原子接受并用于缓存。重启重新验图，不能通过 `Managers` 扩全局名单。服务器拉取可提供明确能力下的 `issuerEvidence` 控制面图；图中的 historical Admin 不能解释为当前有效 Admin。

暂停时只处理授权和来源证据，不接受变量值、不推进数据序号或 SeenMutations；已收到撤销仍执行。来源账本与授权/缓存检查点在同一 Engine 和受保护状态事务提交，失败不留下半个可信图。

v3 非空云缓存缺账本时拒绝启动/导出；旧 cert2 明确升级新能力后，缺账本缓存仅可匹配原受保护回执精确证明的本机 env/KV/GG/角色/期限和授权指纹，其它环境、新 KV 或指纹不符拒绝。无缓存的首次入网/初始化允许先在线拉取。CLI 后台和手机高层必须在读取离线缓存前执行该重验，不能只提供未调用的验证 API。旧 profile 缺来源证据仍拒绝，不把 newenv 的 self-signed grant 当作初始化来源。

## 拉取、管理者控制视图与幂等

新能力拉取为 `GET .../pull?after=N&capability=issuer-origin-v1`，授权专用流追加 `scope=authorizations`。返回可空的 `issuerEvidence` 候选；非空图以本机当前可读授权为 targets，依赖闭包不受 after 影响。普通数据流还须包含本次返回历史写入授权、历史写入者的精确归档双公钥和必要来源；不能因 writer 不是当前 approver 就信任目录，也不能漏该证据使合法历史无法验证。授权流不带普通 mutation 值，已有已验证历史账本可以保留。

轮换证书完整 before/after manifest 中每个授权摘要必须存在精确、可验证的 grant 节点，附相应身份归档；不能只保留当前接收者而漏其它永久 RO/RW 前态。闭包只增加上述控制材料，不增加其它环境标签、变量名、变量密文或恢复封套，超过图边界保持拒绝。

管理者预签使用 `GET .../issuer-evidence?environmentId=E&capability=issuer-origin-v1`，返回 `{sequence,grants,issuerEvidence}`。grants 是该环境全部当前有效接收者权限，targets 仅本机当前 Admin；账号/设备会话、撤销、期限和 Admin 每请求重查。生产者验证受保护根、精确初始化集合、完整图、当前自己双公钥/角色/版本后，才签完整来源包。

环境 v2 POST 精确为 `{change,signature,origin:{origin,signature}}`，其中 change/signature 是原环境操作，不把 origin 再嵌入原操作签名对象。拉取环境事件的 origin 位于事件外层，完整双包绑定须重新验证。提交内容摘要为 `SHA256(JSON(['harmonia/environment-submission/v2',base64url(changeSigningBytes),changeSignature,base64url(originSigningBytes),originSignature]))`。

`GET .../environment-changes-v2/{idempotencyKey}` 返回 `unknown` 或 `complete`，complete 附唯一接受 sequence 和上述 contentHash。断网先查原 ID 与原 hash，再重试同包；同 ID 内容变化或跨旧 profile 重放拒绝。仅服务器接受后经相同 pull/账本流更新本机，不能乐观写本地权威缓存。

## 实现与实测状态

2026-10-02 22:14 UTC，本组件 Go 1.26.4 与 Node 24.16.0：新增 crypto/严格解析 6 项主测试、34 个子测通过；syncclient 5 项主测试、27 个子测通过；crypto、syncclient、localkeys 和 CLI 普通测试全通过；protocol 全部 17 项通过。静态向量 `environment-origin-v1.json` 的 17 项来源、9 项 proof、16 项证书 v3 字节/摘要/Ed25519 由 Go 与 Node 独立核对。

2026-10-02 23:37 UTC，最终包含批量检查点共用校验的 core-go 全包 `mise run test-race` 通过；`go vet ./...` 经 mise 通过；macOS arm64、Linux amd64、Windows amd64 的 CGO=0 默认 CLI 构建通过。新增 crypto 6 主/34 子、syncclient 8 主/46 子测试通过；三个来源向量镜像相同，源码基础检查通过。初次静态检查发现旧配对函数跨包位置式初始化，已改为同字段 keyed 初始化，未改变配对 profile 或签名字节。

workspace 来源负责人实际报告：真实固定 SPAKE2/TLS/SQLite 的来源闭环普通测试 4.03 秒、race 5.58 秒通过，包含 temporary B 创建 Y、B 全量轮换 X 保留 A/D 永久权限、C 仅 Y 读取、原 sealed receipt 丢响应重启、编译后的 cert3 后台删除旧会话并重新 boot/IPC/export/RO 拒写/退出 0。普通 pull 缺重加密 inner event 时，在提交缓存前要求完整拉取；环境事务成功必须由共用 helper 核对头事件与每项原 ID/指纹/合法唯一序号范围，不以当前值猜结果。另有真实 Android 显式证书 v2 的 C/D 历史 writer 兼容测试由移动组件报告 59.634 秒通过；该组件只对实际构建 artifact 作此声明。手机通用管理高层负责人报告 A→B→Y→C/轮换/封存重启六场景通过，原生通用手机 UI 仍未由本组件验收。

### 暂停轮换的剩余边界

当前授权投影收到纯 KV 轮换时停止旧 KV 的缓存来源，Engine 随后恢复/移除对应托管配置；这是当前的安全停用策略，尚未完整满足“暂停保配置”。本轮只证明暂停不接受新值、不推进 DataSeq/Seen，不能把暂停完整语义标为通过。

下一切片须显式区分缓存数据源的 grant/KV/GG 与当前授权 target/checkpoint，仅在已签完整 origin 精确证明本机旧→新接收权限保留后继续旧已验证值；撤销、到期和删除仍立即清，恢复同步必须完整验新 KV/HPKE/批量值后原子换源，重启要重新核对两种来源。不能放宽现有账本/缓存同 KV 校验来临时满足界面。恢复后显式信任新管理手机的连续授权方案仅设计，见 [恢复授权草案](RECOVERY-AUTHORITY-DESIGN.md)。
