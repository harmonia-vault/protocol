# 密码学与协议测试证据

记录时间：2026-10-02 18:42 UTC。全部测试只使用公开合成账号、token、种子、环境钥和明文，不使用用户真实凭据或环境变量。

## M1 已验证基线

2026-10-02 17:16 UTC，本机使用 Go 1.26.4 和 Node 24.16.0；当时密码学依赖为 `golang.org/x/crypto v0.53.0`、`golang.org/x/sys v0.46.0`。

| 命令 | 实际结果 | 覆盖 |
| --- | --- | --- |
| core-go `mise run test-crypto` | 12 项通过，0 失败 | 精确 SHA256 密码派生、XChaCha 空值/最大值及每字节篡改、全部 AAD 绑定、HPKE 封套每字节篡改和上下文绑定、RFC 9180 A.2.1 接收已知答案、恢复用途/账号/代际分离、管理/设备签名有效替换与非规范输入拒绝、设备持钥会话、内部变量名保留 |
| protocol `mise run test` | 10 项通过，0 失败 | Go/Node 相同签名字节和 Ed25519 签名、管理/写操作域分离、逐字段篡改、设备持钥会话绑定、最大 65,576 字节数据包及超限拒绝、内部变量前缀大小写拒绝 |
| protocol / cryptox 三套静态向量字节比较 | 通过 | `signatures-v1.json`、`device-session-v1.json`、`max-packet-v1.json` |

首次 Go 测试中 SHA256 测试期望值录入错误，实际标准库结果经独立计算确认一致；修正期望后完整重跑通过，密码派生算法保持精确 SHA256(password)。

## M2 本组件实际验证

Go 1.26.4、Node 24.16.0；原生构建使用 CMake 3.31.8、Ninja 1.12.1、Apple Clang 21、macOS arm64、Debug 静态库。BoringSSL 固定提交 `fab96f87245d7c6b941515201843665122650b88`，符号前缀 `HARMONIA_BSSL`。当前 Go 依赖以 core-go 的版本锁定文件为准；其它组件后续依赖调整不修改本表已完成的测试记录。

| 目录与命令 | 实际结果 | 覆盖 |
| --- | --- | --- |
| core-go `mise run test-crypto` | 本组件扩展后 20 项通过，0 失败 | M1 基线；开机证明；根 manifest、初始化 proposal 与双签证明；设备入网双签及授权排序/重复拒绝；公共中继签名与短码长度拒绝；受限恢复证明、完整 13 字段轮换、新根保持、代际溢出和禁止去 manifest 降级 |
| core-go/pairing `mise run native-build /path/to/pinned-source` | 本机静态库构建成功，官方 6 项通过 | 正常 SPAKE2、旧端兼容、错误密码、错误身份、消息逐位篡改；实际从固定官方源码重新构建 |
| core-go/pairing `mise run test` | 3 项通过，0 失败 | 上下文规范/期限、公钥与角色、八位短码、默认关闭、应用层固定向量 |
| core-go/pairing `mise run test-native` | 11 项通过，0 失败，含 12 个上下文字段子测 | 真实双向 SPAKE2/HMAC 确认、未确认取钥拒绝、错误短码、公钥/账号/用途/挑战替换、反射、跨会话重放、单次状态、到期、确认篡改和已确认 transcriptHash 导出门槛 |
| core-go/pairing `mise run test-native-race` | 通过 | 本机包装器的 Go 状态通过 race detector；不代表 C 实现经过独立并发审计 |
| core-go/pairing `mise run test-vector-node` | 1 项通过，0 失败 | Node 标准 crypto 独立核对 Go 的上下文/身份/ordered transcript/HKDF/HMAC 向量 |
| core-go/pairing `mise run test-default-cross` | 三个目标构建通过 | `CGO_ENABLED=0` 的 darwin/arm64、linux/amd64、windows/amd64 包保持默认关闭；不是原生配对平台验收 |

本组件新增 `device-boot-v1.json`、`vault-initialization-v1.json`、`device-enrollment-v1.json`、`pairing-relay-v1.json`、`recovery-lifecycle-v1.json`、`pairing-application-v1.json`。初始化、入网和轮换向量中的 HPKE 封套由 Go 标准库真实生成，Go 测试使用对应合成私钥解回环境钥；确定签名与 hash 由独立 Node 标准 crypto 生成并与 Go 核对。新恢复封套不能由旧码解开。

`pairing-application-v1.json` 只校验应用层编码与标准 HKDF/HMAC，不是 SPAKE2 原语向量；入网与中继签名向量中的 synthetic transcript 不证明真实 PAKE 成功。固定 BoringSSL 官方测试仍没有固定 SPAKE2 已知答案向量，详见 [PAIRING.md](PAIRING.md)。没有修改随机源、复制群运算或把 SPAKE2+ 当成 SPAKE2。

`environment-lifecycle-v1.json` 由环境生命周期组件生成，仅作公开签名/编码夹具；其中填充字节封套不代表可解密的 HPKE 数据。其 Go/TypeScript 验证由该组件及 workspace 另记，不计入本表 20 项结果。更多服务器、客户端及真实 TLS 端到端测试由相应组件和 [workspace](https://github.com/harmonia-vault/workspace) 记录。

## 尚未由本组件验收

Linux 原生 SPAKE2、Windows cgo ABI、iOS 真机/模拟器配对均未跑。Android arm64 静态库和 Go 完整链接已经通过，Android 配对运行仍未跑。手机原生强认证和钥保护、完整客户端管理授权历史/检查点核验、邮箱重置流程、虚拟机无人登录系统服务、Workers Argon2 实际资源、生产持久化/部署及独立安全审计也未由本组件验收。服务器已有受限恢复、原子轮换与入网状态实现，不能据此把手机与三平台完整流程标为完成。

某个原语或本机流程测试通过，不能宣称 Harmonia 生产可用。

## Android arm64 新增编译记录

2026-10-02 18:58 UTC，本轮使用已安装并校验的 NDK 28.2.13676358、Clang 19.0.1、API 21、CMake 3.31.8 和 Ninja 1.12.1，保持 BoringSSL 固定提交与 SPAKE2 profile 不变：

| 验证 | 结果 |
| --- | --- |
| `mise run native-build-android <NDK目录> <固定源码目录>` | 通过，生成 PIC、`c++_static` 的 arm64-v8a 静态库 |
| `llvm-nm` 检查 SPAKE2 四个公共符号 | 通过，均为 `HARMONIA_BSSL_` 前缀 |
| 静态库对象头 | ELF64 / AArch64 / REL |
| `mise run test-android-compile <NDK目录>` | 通过，实际选中原生 cgo 包装器，Go 测试二进制完整链接 |
| Go 测试二进制头 | ELF64 / AArch64 / DYN |
| Android 上游原语测试、Go 配对测试运行、Flutter 桥接 | 未跑，不计为 Android 运行通过 |

产物仅在 `core-go/pairing` 的 Git 忽略目录保存，没有公开二进制或用户数据。该记录不改变 macOS 实测范围，也不补足 Android 运行、iOS、Windows 或生产安全验收。

## 多管理签发者证明新增切片

2026-10-02 20:09 UTC：Go `core-go/cryptox/mise run test-issuer-proof` 7 项、29 个子测通过；Node `protocol/mise run test` 共 14 项通过，新增 4 项独立互操作验证。真实 HPKE/AEAD 正例覆盖 C 验解 A 历史数据和含旧 v2 节点的 D 接收钥绑定。全部密钥和账号均为公开合成值。

本轮后续已接入独立 v2 Go 客户端、逐环境 verifier、完整受保护回执与后台重验；旧 v1 单 pin 不扩大信任。非根新环境和跨版本轮换来源仍未支持。完整编码、信任锚与已跑/未跑边界见 [ISSUER-PROOF.md](ISSUER-PROOF.md)。


### v2 Go 正式接入新增验证

2026-10-02 20:33 UTC 后，本机 Go 1.26.4，固定 BoringSSL profile 不变：

| 命令/测试 | 实际结果 |
| --- | --- |
| syncclient `mise run test-issuer` | 6 项主测试、21 个子测通过；其中新增 v2 为 4 项、17 个子测 |
| syncclient `mise run test-native-enrollment` | 2 项主测试、5 个子测通过；原 v1 2 个和新 v2 正确码/错误码/降级 3 个子测 |
| syncclient `mise run test-native-enrollment-race` | 通过 |
| cmd/harmonia `TestProtectedV2ReceiptRestartRejectsProofAndGlobalManagers` | 通过，含 4 个拒绝子测，真实临时加密目录重开 |
| localkeys `TestTrustV2FreezesScopedReceiptAndForbidsManagerExpansion` | 通过，含 4 个拒绝子测；证明不变，仅允许 accepted 前进 |
| core-go `mise run test` | 全包通过，v1 回归保留 |
| core-go `mise run cross-compile` | macOS arm64、Linux amd64、Windows amd64 默认 CLI 构建通过；不是平台运行验收 |
| core-go `mise run test-race` | 本组件、syncclient/cmd/localkeys 等通过，但该次 localipc 原有并发断线测试失败：`invalid IPC protocol`；已交对应组件，不能将该次全包标通过 |

首次新增过期测试误将已未授权的历史事件放入响应，正式 verifier 按预期拒绝；测试已改用服务器应返回的无未授权事件响应，验证环境被清除后通过。真实 PAKE 测试初次使用静态未来时间，超过本机挑战最大期限而正确拒绝；改为当前短时挑战后重跑通过，生产算法与期限检查未弱化。

父任务的 TypeScript/SQLite/Go 多管理真实配对及后台进程结果由 workspace 另记。本表不声称手机多管理界面、Android/iOS/Windows 全流程、非根新建环境与跨密钥版本来源或生产安全审计已经完成。


## 环境来源与证明 v2 新增验证

2026-10-02 22:14 UTC，本组件实际使用 Go 1.26.4、Node 24.16.0；全部为公开合成材料，未扫描宿主环境。

| 命令/范围 | 实际结果 |
| --- | --- |
| protocol `mise run test` | 17/17 通过；新增 3 项来源17项/proof9项/证书v3互操作与篡改拒绝 |
| core-go 定向 `TestEnvironmentOrigin|TestIssuerProofV2|TestIssuerOrigin|TestStrictJSON` | crypto 6 主/34 子、syncclient 5 主/27 子通过 |
| core-go `go test ./cryptox ./syncclient ./localkeys ./cmd/harmonia -count=1`（经 mise） | 四包全部通过 |
| core-go `git diff --check` | 通过 |

覆盖临时管理者轮换保留永久 Admin/RO 的双父来源、非根新建来源、公钥/代际/图冲突/缺证据拒绝、精确初始化锚、sealed save 失败不留下部分账本、重启重验、暂停撤销而数据序号/SeenMutations 不动、旧缓存扩权拒绝、重复键/未知字段/UTF-8/深度/大小/尾随 JSON 拒绝、空数组 `[]` 与 missing/null 区别。

此前本轮一次全包普通与 race 测试通过；此表不把随后新增的环境事件 outer origin 修改算入该次结果。最终稳定来源 slice 的全包 race 和三平台默认构建仍须重跑。真实 workspace 来源验收已走到 B 创建 Y、C 仅 Y RO、原回执丢响应重启；轮换拉取完整 manifest 依赖和旧 v2 手机第二设备历史 writer 闭包仍在联调，不能把阶段进度标为全闭环通过。Android/native 和其它组件的独立结果由对应文档记录。


### 最终来源与缓存回归

2026-10-02 23:37 UTC，包含父任务共用 `VerifyEnvironmentChangeCheckpoint` 及 normal pull 批量完整性修正后的实测：

| 命令/范围 | 实际结果 |
| --- | --- |
| core-go `mise run test-race` | 全部有测试 Go 包通过，0 失败；包含 CLI、crypto、IPC、localkeys、localstate、mobilebridge、mobileworkflow、pairing、platform、syncclient |
| core-go `mise exec -- go vet ./...` | 通过 |
| core-go `mise run cross-compile` | darwin/arm64、linux/amd64、windows/amd64 默认 CGO=0 CLI 构建通过，仅忽略目录产物 |
| 定向 crypto/来源/缓存/批量确认 | crypto 6 主/34 子、syncclient 8 主/46 子通过 |
| protocol `mise run test` | 17/17 通过 |
| 三份 `environment-origin-v1.json` | 字节相同；SHA256 `51b72e2f78e7cbedbb093194fb67f5db1f45b639f0d0a6d6538bee4ed3d9bfde` |
| workspace `mise run check-source` | 基础秘密/个人路径检查通过；仍由父任务人工审公开范围 |
| core-go / protocol `git diff --check` | 通过 |

新增缓存回归：有效账本加额外缓存 Y、KV/GG/role/expiry/checkpoint/fingerprint 不符均拒绝；授权专用投影保留较低角色/较短期限可重启；同序号首次 ledger-empty→nonempty 仅所有其它 Cloud 数据精确不变时允许，Store 失败不留部分账本；已有 ledger 同序号替换或值/权限/checkpoint 改动拒绝。批量确认要求事务头和事务尾准确，所有原 inner ID/指纹及唯一序号覆盖完整范围；遗漏/错 hash/重复序号/越界/错头尾拒绝，规范签名不绑定的合法数组顺序不影响精确集合确认。

workspace 来源负责人另外报告真实固定 SPAKE2/TLS/SQLite/已编译 cert3 daemon 联合测试普通 4.03 秒、race 5.58 秒通过；手机 Android 显式旧 v2 已构建 artifact 的 C/D 来源兼容 59.634 秒通过，由对应负责人记录。通用手机 Go 高层 A→B→Y→C/轮换/回执重启六场景通过，完整原生通用 UI 与新恢复来源连续链尚未由本组件运行。

暂停收到纯 KV 轮换目前安全停用旧缓存来源，会恢复/移除托管配置，未完整满足暂停保配置；本次不把此边界标为完成。具体剩余状态分离及不放宽门槛的设计见 [ENVIRONMENT-ORIGIN.md](ENVIRONMENT-ORIGIN.md)。


### 恢复连续授权密码学切片

2026-10-03，新独立 profile 的实测（没有把 crypto 单测写成手机完整恢复验收）：

| 命令/范围 | 实际结果 |
| --- | --- |
| core-go/cryptox `mise run test-recovery-authority` | 12 个主测试、130 个子测试通过；定向普通测试 0.616 秒 |
| protocol `mise run test` | 全部 23/23 通过，其中 6 个新增恢复互操作/来源主测试 |
| core-go `mise run test-race` | 全部有测试 Go 包通过，0 失败；新增恢复 crypto 所在包 6.709 秒 |
| core-go `mise exec -- go vet ./...` | 通过 |
| core-go `mise run cross-compile` | darwin/arm64、linux/amd64、windows/amd64 默认 CGO=0 CLI 构建通过；不是安装包、没有运行新 native 恢复流程 |
| workspace `mise run check-source` | 基础源码秘密/个人路径检查通过；合成 seed 与密文公开范围另经人工确认 |

Go/Node 独立重算 25 项恢复过渡、18 项恢复设备证书、12 项 proof3、16 项 v4 配对证书、完整集合引用摘要、标准 Ed25519 签名与 HKDF 用途派生。Go 还用成熟 HPKE 实际打开新设备全部封套，拒绝错误封套、旧公钥复用、原初始化替换、V1 断链凭当前码逃逸、缺全环境 Admin、待批准当完成、角色扩张、来源替换/回放和严格 JSON 歧义。来源图正例保留原 root，恢复设备仅选 Y Admin，再由它批准 F 仅 Y RO；该单测未运行 SPAKE transport。

静态向量 [`recovery-authority-v1.json`](../vectors/recovery-authority-v1.json)、[`issuer-recovery-v1.json`](../vectors/issuer-recovery-v1.json) 分别在 core-go/testdata 与 protocol/vectors 冻结相同内容。Node 从公开合成 seed 重新产生相同 Ed25519 签名，Go 实际复验冻结向量；没有用户真实码、私钥或凭据。

新 HTTP/SQLite 原子挑战/完成、原包断网重试、移动原生仅内存签钥句柄、完整新码回填、显式角色选择、相同 pull/AES 保存、真实手机恢复后管理 CLI 与普通客户端新 profile 接线，仍须由对应组件和联合验收证明。包内接受前 issuerEvidence 当前明确 V2，恢复设备后续 ALLAdmin 或它创建/轮换后的再次恢复所需 V3 union 尚未接；相关操作保持拒绝。详见 [恢复连续授权合同](RECOVERY-AUTHORITY-DESIGN.md)。
