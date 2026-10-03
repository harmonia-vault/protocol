# 恢复设备普通客户端接口

本切片只新增 `cryptox/issuer_recovery_access.go`、对应必要产品验证和独立 mise 任务；原连续授权 25 项、恢复设备 18 项、proof3 十二项及证书 v4 十六项规范字节不变。它提供恢复管理设备 E→批准 CLI F→正式 Boot/pull/写流程所需的已验证来源接口，不授会话或直接修改本机权威配置。

## 来源查询与事件验证

所有入口都要求先得到 `VerifyIssuerRecoveryEvidence` 或 `VerifyCompletedEnrollmentV4` 的不透明已验证对象；查询服务器目录不能代替这一过程。

| 方法 | 结果及边界 |
| --- | --- |
| `VerifiedIdentity(deviceID)` | 精确历史 Ed/X 双公钥绑定；不是当前可信状态、环境管理角色或持钥证明 |
| `Authority(hash)` / `VerifyTarget(...)` | 精确 signed grant 来源与目标匹配；当前权限还须沿服务器逐次检查和本机期限/撤销投影 |
| `VerifyHistoricalMutationSource(mutation,grant)` | source 已验、同账号/代际、writer/env/KV/GG 精确匹配且角色 RW/Admin，再验独立设备 Ed 签名；RO 即使有对称钥和合法密文也不能写 |
| `VerifyEnvironmentOriginEvent(change,origin,priorAdmin)` | 同 V2 成熟接口：图内 origin 摘要、原数据操作签包、旧 actor Admin 和完整 before/after 来源精确关联 |
| `RecoveryCheckpoint()` | 从已验证链得到公开代际、公钥、链尾及接受序号；不包含恢复种子或任何私钥 |
| `VerifyRecoveryCheckpointAdvance(prior,candidate)` | 使用 prior 私有原 pin 重验候选完整图，必须保留已见链尾摘要及同一接受序号，拒绝虽有有效历史签名的旧链回退 |

恢复链检查点不能取代 data/auth 序号、授权指纹、环境墓碑、cached source/current authorization、epoch 和 Store 原子保存检查。历史角色不能当 current Admin，后来的撤销也不能抹掉合法历史签名。普通客户端只能在已签来源范围内使用公钥，不导出或扩大全局 Managers。

## Boot 前已接受自登记的来源构造

```go
BuildRecoveredDeviceIssuerEvidence(
    pin PinnedIssuerRoot,
    original OriginalInitialization,
    transitions []AcceptedRecoveryTransition,
    accepted AcceptedRecoveredDevice,
) (IssuerRecoveryProof, error)
```

pin 必须来自恢复流程已经验证并受保护保存的原 root，不能由传入的 server originalInitialization 或目录自行复制。函数先验证原初始化双签、完整过渡及原 accepted 恢复设备双签；接受序号必须是签名 expectedSequence+1。然后复用接受前已验 V2 控制来源、转换旧 paired 归档，增加本机 recovered 首边和明确 selected own grant 来源/targets；不把新设备替换成 Root，不扩大环境或角色。最后深拷贝材料、严格解码并完整验证新 proof3。

这只给尚未获取服务器 proof3 的本机提供 Boot 前来源。客户端构造器还须核对 accepted device ID/双公钥与本机保护私钥精确相同；使用新设备 Ed 持钥 Boot 后走共同 full pull，验证当前权限、HPKE/AEAD、来源账本及检查点，再同一次保护保存。成功前不能标记本机可信或 apply 乐观配置。旧 session、未知接受状态、缺过渡和错误原 pin 均不能绕过。

## 必要产品验证与剩余接线

`core-go` 的 `mise run test-recovery-reader` 实际通过 4 个主测试、4 个子测试，race 包耗时 2.826 秒；crypto vet 通过。测试覆盖真实 E 写入密文由 F 通过其 HPKE/AEAD 解开、F 仅 RO 无法凭合法密文写入、writer/env/KV/GG 脱离来源拒绝、有效外层环境数据签名不能替换冻结 origin、合法旧图不能回退已见恢复链，以及 builder 的保护原 pin/接受序号/缺过渡/输入可变性边界。它没有运行 Android 强认证、正式 HTTP 挑战、SQL 接受或 CLI 进程。

正式 ReceiptV4、NewRecoveredDevicePinnedVerifier、PAKE V4 客户端、device-bound Boot、动态完整控制图、受保护重启及签名写的集成由对应客户端/服务端组件接入并单独验收；这里不把纯 constructor 当作产品闭环完成。

当前 accepted 恢复设备和过渡包内的旧 `issuerEvidence` 明确为 V2。恢复设备后续作为 ALL-env Admin 发起新过渡，或它新增/轮换环境后的二次恢复，需要显式 typed union：仅按完整 `profile` 区分 V2/V3，逐分支严格 schema、同一原 pin/原初始化和完整依赖验证，摘要继续绑定 profile 与精确规范字节。未知 profile、丢恢复节点或“转成 V2”截掉证据必须拒绝；不能从当前公钥/目录补锚。本接口没有静默启用该 union，也没有修改冻结 wire。
