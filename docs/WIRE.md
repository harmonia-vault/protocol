# Harmonia v1 线协议与签名字节

状态：实验性首个可测试切片。以下是安全契约，不能据此认为配对、恢复、账号生命周期或平台保护已全部实现。成熟 SPAKE2 配对验证完成以前，新设备入网必须关闭；合成测试夹具不是生产信任入口。

## 基本表示

JSON 对象用于传输，Ed25519 签名覆盖固定顺序的 **全字符串 JSON 数组**。不对对象排序，也不签对象的原始 JSON。编码为无空格的 JSON 数组 UTF-8 字节；数组首项为操作专属版本域。字段仅允许下述 ASCII 范围，因此 Go `encoding/json` 与 JavaScript `JSON.stringify` 的输出完全一致。接收方应拒绝未知字段、缺失字段、非字符串字段和重复 JSON 对象键，不通过类型转换放宽验证。

| 类型 | 精确约束 |
| --- | --- |
| ID | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`，不含邮箱或个人资料 |
| 变量名 | `^[A-Za-z_][A-Za-z0-9_]{0,127}$`，大小写不敏感保留 `__HARMONIA_` 前缀并拒绝云端使用 |
| 版本、账号/授权代际 | 正 `uint64` 十进制字符串，不接受前导零、符号、小数或溢出 |
| 有效期 | `uint64` 十进制 Unix 秒字符串；`"0"` 表示直到撤销；不接受前导零 |
| 二进制 | RFC 4648 base64url，无 padding，拒绝非零尾位及非规范别名 |
| 公钥 | 独立 Ed25519 / X25519 原始公钥各 32 字节 |
| 签名 | Ed25519 原始签名 64 字节，以上述 base64url 表示 |

不要把数值字符串转换为 JavaScript `Number` 后比较大序号或代际，使用 `BigInt`。传输可以包含签名字段，但该字段不进入自身签名字节。

## 设备写操作

字段和顺序如下；所有数组项都是字符串：

```text
["harmonia/mutation/v1", accountId, accountGeneration, deviceId,
 environmentId, keyVersion, grantGeneration, operation,
 idempotencyKey, name, payload]
```

`operation` 仅为 `put` 或 `delete`。`put` 的 `payload` 为 `base64url(nonce24 || ciphertext || tag16)`，加密前变量值最多 65,536 字节，空值合法。`delete` 的 `payload` 必须为空串。签名覆盖变量名、密文和全部上下文，服务器不能因 AEAD 密文有效而准许写入。RO 设备也有对称钥，能制造合法密文。

数据使用 XChaCha20-Poly1305，每环境独立随机 32 字节钥，每次加密随机 24 字节 nonce。AAD 精确为：

```text
["harmonia/value/v1", accountId, accountGeneration,
 environmentId, keyVersion, name]
```

把密文移到另一账号、账号代际、环境、密钥版本或变量名会导致解密失败。AEAD 不代替设备身份、当前写权限或序号验证。

## 管理签名授权

```text
["harmonia/grant/v1", accountId, accountGeneration, issuerDeviceId,
 subjectDeviceId, subjectSigningPublicKey, subjectReceivingPublicKey,
 environmentId, keyVersion, grantGeneration, role, expiresAt,
 idempotencyKey, envelope]
```

`role` 为 `ro` / `rw` / `admin` / `none`。`none` 撤销访问，`envelope` 必须为空；其余角色的封套必须为 80 字节。每次授权、降权、升级或撤销都递增对应设备/环境的 `grantGeneration`。签名由该环境当前有效 Admin 设备的独立 Ed25519 私钥产生。接收设备的签名公钥和接收公钥都被绑定，变更不能覆盖已有可信设备身份。

HPKE 为 RFC 9180 基础模式，`kem_id=32`（DHKEM(X25519, HKDF-SHA256)）、`kdf_id=1`（HKDF-SHA256）、`aead_id=3`（ChaCha20Poly1305）。封套二进制为 `enc32 || ciphertext48`，明文固定为环境钥 32 字节。每个封套创建一个新 HPKE 上下文，只封装一次。HPKE `info` 为：

```text
["harmonia/envelope/v1", "32", "1", "3", accountId,
 accountGeneration, environmentId, keyVersion, recipientType,
 recipientId, recipientGeneration, recipientPublicKey]
```

`recipientType` 为 `device` 或 `recovery`。设备封套的 `recipientGeneration` 是授权代际；恢复封套的该字段是恢复代际。`recipientId` 分别为设备 ID 或固定 `recovery`。接收钥必须与 `recipientPublicKey` 一致。基础模式 HPKE 不证明发送者身份；管理签名覆盖封套后才提供身份及授权绑定。

客户端必须已有可信审批固定的 issuer/subject 公钥，不能信任服务器临时给出的公钥。`VerifyGrant` 的密码学成功不代表 issuer 当前拥有 Admin 权限，也不代表主体仍可读取。

## 当前权限、幂等与接受顺序

服务端在每一次写、删、授权、读取及通知订阅消息时，检查当前账号代际、设备状态、授权角色、有效期、密钥版本和授权代际。WebSocket 握手检查不能替代后续逐次检查。降权或撤销立即生效。

一次接受事务在同一个账号权威持久化域中完成：检查当前授权 → 检查 `idempotencyKey` → 验证签名及上下文 → 更新状态 → 分配持久化递增序号 → 保存结果。幂等表按账号和设备/发行者作用域保存精确规范内容摘要。重试内容相同返回最初结果/序号，内容不同返回 `idempotency_conflict`；重试不能成为新的 LWW 写入。已撤销设备的重试不能通过幂等缓存绕过当前授权检查。

LWW 只按服务器成功接受的序号排序，不用客户端时间戳。客户端提交成功后仍通过同一增量拉取流更新本地权威状态，不乐观直接修改。共享修改要求在线；本地 override 另存本机。

## 拉取、检查点及通知

账号持久化序号独立、单调递增，不跨账号比较。拉取请求指定 `afterSequence`（规范非负十进制字符串）和有上限的页大小。响应包含账号代际、当前持久化 `headSequence`、按序记录、分页游标、当前可见授权状态。签名原文、设备身份和授权证据必须保留，不能仅返回解密后的字典。重连从最后已验证、已持久化的检查点补拉；通知仅提示最新序号。

客户端固定账号代际和已见最高检查点。响应代际不匹配、`headSequence` 回退、重复序号内容改变、越权记录或签名失败必须关闭接受，不能用较低检查点替换缓存。账号破坏性重置只能经独立已确认的账号生命周期流程显式接受新代际；普通同步不能自动接受服务器声称的新代际。当前授权失效必须先停用相应环境，再处理剩余来源。通知可以遗漏，持久化拉取不能遗漏。

未授权的其他环境写入序号不能泄露密文；分页仍需能穿过被过滤记录，不形成无限循环。权限的当前状态是服务端立刻拒绝请求的依据；历史签名链负责客户端核验历史写者在接受当时的权限，不能仅用现任写者的公钥替代历史证据。

## 错误与传输边界

| 错误码 | 语义 |
| --- | --- |
| `invalid_request` | 非规范字段、编码、未知操作或尺寸超限 |
| `unauthenticated` | 会话失效或账号尚未验证 |
| `generation_mismatch` | 账号、授权或密钥版本不匹配 |
| `forbidden` | 当前设备或角色无权执行 |
| `expired` | 当前授权到期 |
| `invalid_signature` | 独立设备或管理签名失败 |
| `idempotency_conflict` | 相同幂等 ID 对应不同请求 |
| `checkpoint_conflict` | 序号、历史内容或代际回退 |
| `not_implemented` | 关键流程尚未完成，关闭入口 |

错误不得回显密码派生凭据、授权 token、环境明文、恢复种子或 SMTP 凭据。具体 HTTP 路由以 server 当前实现文档为准，本协议中的类型不意味着所有路由已实现。自托管正式入口只接受 HTTPS；本机集成测试可显式限定 loopback HTTP，不能把测试选项扩展到远端。

## 登录与恢复边界

密码客户端只执行 `SHA256(password UTF-8 bytes)`；这是密码等价凭据，HTTPS 传输，服务端使用独立随机盐加 Argon2id 验证。它不能作为 vault 密钥，不得被日志、监控或缓存泄露。

恢复种子独立随机 32 字节，完整无 padding base32 表示。标准 HKDF-SHA256、空 salt、32 字节输出的 `info` 为：

```text
["harmonia/recovery-kdf/v1", purpose, accountId,
 accountGeneration, recoveryGeneration]
```

`purpose` 分别为 `ed25519-signing` 和 `x25519-receiving`；前者输出 Ed25519 seed，后者输出 X25519 私钥输入。用途间不复用钥。完整恢复流程必须完成受限会话、用户完整重输新码、账号/操作/会话/恢复代际绑定的短时单次 nonce 证明、所有必要封套原子切换以及结果状态查询。仅有派生函数和封套并未完成该流程。

新设备审批必须使用成熟 SPAKE2 实现，短秘密码不传服务器；密码登录不能直接加入可信设备。当前切片不自创 SPAKE2 或提供生产绕过。

## 互操作证据

`vectors/signatures-v1.json` 包含公开合成种子、密钥、明文、完整签名对象和期望签名字节十六进制。Go cryptox 和 Node 协议测试都核对同一向量。它们只能用于测试。外部 HPKE 依据为 [RFC 9180 A.2.1](https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.2.1)。实现依赖 [Go HPKE 标准库](https://pkg.go.dev/crypto/hpke) 和 [Go XChaCha 官方库](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305)。
