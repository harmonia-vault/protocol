# 设备配对协议与当前验收范围

配对实现位于 `core-go/pairing`，使用固定版本的 BoringSSL SPAKE2 原语和标准 HKDF-SHA256/HMAC-SHA256 密钥确认。当前是 macOS 原生验证内核。服务器已增加中继与原子证书入网实现，完整手机批准与客户端请求流程仍待共同验收，不能宣称生产可用。

## 实现选型

| 实现 | 一手来源中的依据 | 本阶段决定 |
| --- | --- | --- |
| BoringSSL SPAKE2 | 公共头文件明确使用 draft-irtf-cfrg-spake2-02；Android ADB 配对和 Chromium 远程桌面源码调用该 API；上游持续维护，但不保证第三方 API/ABI 稳定 | 固定提交，使用公共 C API 的薄包装器，继续平台验收 |
| niomon/spake2-go | README 说明未审计，并提示可能不是常数时间实现 | 不采用 |
| RustCrypto spake2 0.4.0 | 官方文档说明未独立审计，并提示常数时间方面的限制 | 不采用 |

BoringSSL 固定提交为 `fab96f87245d7c6b941515201843665122650b88`，配置保存在 `core-go/pairing/boringssl.lock.json`。Harmonia profile 固定为 `boringssl-spake2-edwards25519-draft02-v1`。这不是 RFC 9382 profile，也不是 SPAKE2+；不承诺与 RFC 9382 实现互操作。后续更换原语 profile 必须使用新 profile 标识并补互操作与安全测试，不能静默改变本版本。

上游库采用 Apache-2.0；构建任务保留其完整 `LICENSE`。Harmonia 源码采用 MIT 许可证。BoringSSL 不属于 Android NDK 的公共系统接口，不能依赖系统私有库。固定提交仍须跟踪上游安全变更；成熟库的使用经历不等于 Harmonia 配对流程经过独立审计。

依据：[BoringSSL 公共 SPAKE2 API](https://boringssl.googlesource.com/boringssl/+/fab96f87245d7c6b941515201843665122650b88/include/openssl/curve25519.h)、[上游维护说明](https://boringssl.googlesource.com/boringssl/+/fab96f87245d7c6b941515201843665122650b88/README.md)、[许可证](https://boringssl.googlesource.com/boringssl/+/fab96f87245d7c6b941515201843665122650b88/LICENSE)、[Android ADB 配对源码](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/pairing_auth/pairing_auth.cpp)、[Chromium 配对源码](https://chromium.googlesource.com/chromium/src/+/main/remoting/protocol/spake2_authenticator.cc)、[Go 候选 README](https://github.com/niomon/spake2-go)、[Rust 候选官方文档](https://docs.rs/spake2/0.4.0/spake2/)、[RFC 9382](https://www.rfc-editor.org/rfc/rfc9382.html)。

## 上下文和短码

新设备在本地产生独立 Ed25519 签名钥和 X25519 接收钥。`GenerateShortCode` 产生无偏随机八位数字短码，包含前导零。短码只在新设备本地显示，并由用户在可信管理手机输入；任何请求、日志、持久化对象和服务器数据库都不能包含短码。调用者在原生初始化之后应清理短码字节，不把 Go 或平台软件钥宣称为始终处于硬件内。

两端分别用自己的本地公钥、账号和已知配对挑战重建同一上下文。禁止直接接受中继给出的任意公钥、任意待签数组或未校验的上下文。`initiator` 对应新设备，BoringSSL 角色为 Alice；`approver` 对应既有管理手机，角色为 Bob。

确定编码为紧凑 UTF-8 JSON 固定字符串数组，整数使用规范正十进制字符串，公钥与 nonce 使用无 padding 的规范 base64url。公钥和 nonce 均为 32 字节；两个设备标识不同，每设备两种公钥独立。期限为 Unix 秒，初始化时最多允许未来 120 秒，并在每步检查到期。

```text
["harmonia/pairing-context/v1",profile,
 accountId,accountGeneration,purpose,sessionId,challengeNonce,expiresAt,
 initiatorDeviceId,initiatorSigningPublicKey,initiatorReceivingPublicKey,
 approverDeviceId,approverSigningPublicKey,approverReceivingPublicKey]
```

`purpose` 目前只允许 `enroll-device`。整段上下文编码的 base64url 与角色共同成为 BoringSSL 的 `my_name`/`their_name`，使原语输出同时绑定账号代际、用途、挑战、期限、两个精确设备身份和角色：

```text
["harmonia/pairing-identity/v1",role,base64url(contextBytes)]
```

服务器只中继公共上下文、32 字节 SPAKE2 消息和确认数据。服务器必须持久化单次 session/nonce 状态，原子消费最终批准，检查当前账号代际和管理权限，并按账号、设备及配对会话限制在线猜测；这些服务端机制不在此内核中完成。短码持有者的一个活动猜测不能被 PAKE 消除，因此必须限制失败次数和短时会话重建。

## 显式双向确认

`NewInitiator`/`NewApprover` 返回一次性 `Session` 和本端 SPAKE2 消息。`Complete` 只接受对端 32 字节消息，拒绝自身消息反射，调用公共 `SPAKE2_process_msg` 后立即关闭原生上下文。两端按发起方在前的顺序编码：

```text
transcript = ["harmonia/pairing-transcript/v1",base64url(contextBytes),
              base64url(initiatorMessage),base64url(approverMessage)]
transcriptHash = SHA256(UTF8(JSON(transcript)))
```

把 BoringSSL 的完整 64 字节输出作为 HKDF 输入，`transcriptHash` 为 salt。三种 info 固定为 `harmonia/pairing-confirm/initiator/v1`、`harmonia/pairing-confirm/approver/v1`、`harmonia/pairing-channel/v1`，分别得到 32 字节两端确认钥和通道钥。

每端的确认值使用自己的角色确认钥计算：

```text
HMAC-SHA256(roleKey,
  UTF8(JSON(["harmonia/pairing-confirmation/v1",role,base64url(transcriptHash)])))
```

`Complete` 只返回本端确认值。`VerifyPeerConfirmation` 成功之前，`SessionKey` 始终拒绝返回通道钥。错误短码、上下文或消息替换导致确认不一致；任何失败关闭该 Session，不能重复尝试。确认值反射、跨会话重放、重复步骤和过期会话均被拒绝。`Close` 清理 Go 保存的通道钥并释放原生状态，但运行时、内存副本和上游分配器不提供完整秘密擦除保证。

这个通道只证明两端持有同一短码和绑定的上下文。管理手机仍必须展示环境、`ro`/`rw`/`admin` 角色以及限时/永久期限，由用户显式确认后生成管理签名授权。授权必须绑定新设备的两把精确公钥、账号代际、环境、授权代际和 HPKE 封套，按 [WIRE.md](WIRE.md) 验证。当前包没有把配对成功自动变成可信设备。原生配对内核与手机/CLI 请求流程尚待端到端接入，完整接入前继续关闭生产入网入口。


## 中继、确认摘要与最终证书

公开中继数据需对应一端 Ed25519 签名，不允许携带短码字段。中继请求只包含 `{side,kind,payload,signature}`，其中 `kind` 仅为 `message` 或 `confirmation`，payload 为规范 base64url 的 32 字节。路由与冻结上下文重建完整签名数组：

```text
["harmonia/pairing-relay/v1",accountId,accountGeneration,sessionId,
 challengeNonce,side,kind,payload]
```

服务器限制每个角色的消息与确认各提交一次；内容完全相同的重试保留原状态。这个签名不代替 PAKE 密钥确认，服务器不能验证 HMAC 对应的秘密。客户端必须先调用 `VerifyPeerConfirmation`，再用 `Session.TranscriptHash()` 获取 lowercase hex 摘要；未确认、已关闭或到期均拒绝提供。

管理手机的 approve 请求为 `{grants,transcriptHash,signature}`，其中 signature 为管理手机对证书的签名。服务器返回并保存的批准对象使用 `{context,pairingProfile,transcriptHash,grants,approverSignature}`。新设备在验证已确认 transcript、精确公钥、管理授权与可信根后，签相同数组，以 `{signature}` 完成请求；服务器在批准对象保存为 `initiatorSignature`。确定签名数组为：

```text
["harmonia/device-enrollment/v1",pairingProfile,accountId,accountGeneration,
 sessionId,challengeNonce,expiresAt,initiatorDeviceId,initiatorSigningPublicKey,
 initiatorReceivingPublicKey,approverDeviceId,approverSigningPublicKey,
 approverReceivingPublicKey,transcriptHash,grantsHash]
```

`grantsHash` 对按环境 ID 的 ASCII 顺序排序的 `[[environmentId,base64url(canonicalGrantBytes),signature],...]` JSON 字节做 SHA256，小写 hex；环境不可重复。每个授权仍单独采用既有管理签域，批准 UI 所显示的环境、角色和期限必须来自将签名的精确授权。服务器最终在一个账号事务中重新检查管理者当前 Admin、各精确公钥、挑战/账号代际和两端证书签名，并原子登记设备及授权。

`cryptox.EnrollmentApproval.Certificate()` 将 HTTP 包装对象转换成待签字段；`SignedGrantWire` 为嵌套授权对象。`cryptox.EnrollmentCertificate` 是签名结构而非直接 HTTP 对象，不能把其 JSON 误发给中继 API。`protocol/vectors/device-enrollment-v1.json` 和 `pairing-relay-v1.json` 含标准 Ed25519 固定向量；合成 transcript 不证明真实 PAKE 成功。生产门槛仍取决于真实手机与客户端流程共同验收。

## 构建与测试

进入 `core-go/pairing` 后执行：

```sh
mise run test
mise run native-build
mise run test-native
mise run test-native-race
mise run test-vector-node
mise run test-default-cross
```

`native-build` 自动取得固定提交的官方源码，在 Git 忽略的 `.cache/` 构建目录内编译，使用 `HARMONIA_BSSL` 符号前缀隔离其它 BoringSSL 副本，运行官方 `SPAKE25519Test.*`，再把头文件、静态库和许可证放入忽略的 `native/`。已有上游目录提交不符或受跟踪源码有改动时停止，不重置目录。已有已核验源码可用 `mise run native-build /path/to/boringssl`。工具固定为 Go 1.26.4、CMake 3.31.8、Ninja 1.12.1。

默认构建及 `CGO_ENABLED=0` 返回 `ErrUnavailable`。只有显式 `harmonia_boringssl` 构建标签与已构建静态库才启用包装器。`NativeAvailable` 表示该构建包含原生实现，不代表完整平台或设备入网流程已经验收。

| 项目 | 实际结果 |
| --- | --- |
| macOS arm64、Apple Clang 21、固定 BoringSSL 官方测试 | 6/6 通过：正常交换、旧端兼容、错误密码、错误身份和消息逐位篡改 |
| Go 默认构建 | 3/3 通过：上下文、短码、默认关闭和应用层静态向量；三平台 CGO=0 包交叉构建通过 |
| macOS arm64 原生包装器 | 11/11 通过，含 12 个上下文字段子测：双向确认、取钥门槛、错误短码、反射、跨会话重放、过期、错误长度、确认篡改与已确认摘要导出门槛；Go race detector 通过 |
| Linux 原生、Windows、Android NDK、iOS 真机/模拟器 | 未跑；不能声明支持或验收通过 |
| 手机角色确认、Go/Flutter 桥接与完整请求流程 | 未联合本原生包完成端到端验收；服务器已有中继和原子批准状态实现 |

固定提交的[官方测试源码](https://boringssl.googlesource.com/boringssl/+/fab96f87245d7c6b941515201843665122650b88/crypto/curve25519/spake25519_test.cc) 仍有添加固定 SPAKE2 向量的 TODO。公共 API 无注入随机源的标准向量入口；本实现没有修改上游随机数或复制群运算来伪造标准测试。`protocol/vectors/pairing-application-v1.json` 是独立 Node 标准 crypto 生成、Go 验证的应用层编码、HKDF/HMAC 固定向量；其中原始钥和两条消息均为合成字节，不是有效 SPAKE2 交换或 RFC 9382 向量。这一原语固定向量缺口明确保留。

## 后续平台门槛

Go 与 Flutter 共用同一配对内核，Flutter 桥接只传递公开消息、输入的短码和最终授权操作，不重写 PAKE。Android 应针对 `arm64-v8a` 和需要的模拟器 ABI 自行编译固定 BoringSSL，静态链接并保留符号前缀及许可证，再验证 NDK C++ 运行时、cgo 指针生命周期和全套负向测试。iOS 分别构建设备与模拟器静态库，并验收系统认证后的本地钥解锁流程。

Windows 官方构建使用 MSVC/Windows SDK/NASM；Go cgo 的工具链和静态库 ABI 接入尚未完成。当前 Windows 包保持关闭，需要实际 Windows 适配和运行测试后才能开放。Android/iOS 在包装器中有候选链接布局，尚未验证 flags 或发布产物。上游[构建说明](https://boringssl.googlesource.com/boringssl/+/fab96f87245d7c6b941515201843665122650b88/BUILDING.md) 只能证明上游提供构建途径，不能代替 Harmonia 三平台验收。
