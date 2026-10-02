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
