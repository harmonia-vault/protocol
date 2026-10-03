# 平坦恢复依赖图：本批验证证据

本页记录 `RECOVERY-DAG.md` 合同对应的独立密码学内核。正式服务端路由、协议 major 协商、CLI 和手机重复恢复流程尚未接入；不能把本批结果宣传为产品闭环或生产可用。

## 实际执行的路径

使用合成账号、种子、公钥与服务器序号，实际执行原初始化 → 第一次连续恢复 → E 显式恢复登记 → E 创建 Z 环境并签 origin → 第二次连续恢复 → G 显式登记三环境 Admin → G 以完整三环境 Admin 来源继续轮换 → G 双签批准 H 的三环境 RO。Z 的合成密文实际经设备 HPKE 开封和 XChaCha20Poly1305 解密。cert5 绑定已确认配对端的精确 Ed/X 公钥、会话、用途、授权及完整 Proof4 摘要；此内核测试没有运行 SPAKE2 transport。

接受表是五个平坦记录，最后恢复代际为 4，签名绑定的接受序号为 42。原初始化、原 root 双公钥不移动。签包使用既有成熟 Ed25519、HPKE 和数据 AEAD；没有增加密码原语。

## 验证结果

| 范围 | 结果 |
| --- | --- |
| 新 DAG 定向 Go 测试 | 9 个主测试、39 个子测试通过，2.791 秒 |
| 独立公开基线候选：全部 cryptox race | 62 个主测试、242 个子测试通过，41.997 秒 |
| 同一独立候选 `go vet ./cryptox` | 通过 |
| 同一独立候选三平台 CLI 编译 | macOS arm64、Linux amd64、Windows amd64 通过；不是三平台运行验收 |
| protocol 全量 Node 测试 | 25/25 通过，97.9 毫秒；包括 Go/Node 新固定字节与 Ed 双签互操作 2 项 |
| 基础秘密、个人路径检查 | 通过；另人工确认公开范围为源码、文档和显式合成向量 |

Go 新负例包括缺失、错误 kind、向前依赖、原根/初始化替换、权限变更、部分 ALL Admin、当前 Admin 到期、缺封套、回退已见链头、旧签名域、严格 JSON 和对象隔离。一个额外真实双签登记可独立通过接受表验证，但未被最终来源闭包引用，外层 Proof4 明确拒绝。并发用途签名经 race 检查；调用者修改输入不能改变已验 origin 或恢复链头。

没有把并行工作树的结果当作本批公开快照结果。另有一次历史工作树默认全包 race 通过（cryptox 42.630 秒），它包含其它代理当时未提交的变更，不能用于证明本批公开快照整体状态。上表密码学候选由已公开 core 基线加以下精确 overlay 构成。

## 固定候选

core 基线提交：`006450dfb1a338b20c182c5cf5c16debf4ff102b`。

| core 相对路径 | SHA256 |
| --- | --- |
| `cryptox/issuer_recovery_proof.go` | `db90793f628a0e6140e6718ff5765a1145f1139d91eba1df920d97a5a8e3573a` |
| `cryptox/issuer_recovery_graph.go` | `af188154e4cb04f14a9fe9426ebad7320e46f34285c788baa44090d154c4b649` |
| `cryptox/recovery_dag.go` | `36ddf8ec4c694a105a226bdc44c8578d9a236e9b8d14ae5d26eaf9a466343500` |
| `cryptox/recovery_dag_canonical.go` | `f1cf55f6e6990524c3282f2174ddef97e206dd5274ad27d1b263584fe4975533` |
| `cryptox/recovery_dag_decode.go` | `0abb9e335c61d1e4a26c42ec886447dec545d3739058d1bf670df0846faaa5c6` |
| `cryptox/recovery_dag_enrollment.go` | `62e324faaace3ccc18df92a653c30fa8c14c7ea7096c817435eadf17efaec741` |
| `cryptox/recovery_dag_enrollment_test.go` | `4530dba99d88c6caba2df7c038c5881fdaa28f9e188a63595cc89187150c4842` |
| `cryptox/recovery_dag_test.go` | `824e12c2fd640e3fce5b49dd56297e70a25ca2627b63b77b3c6e26d18cd0cfc6` |
| `cryptox/recovery_dag_validation.go` | `ab3220fa5c264d787ba068d228a42ab569e896f6cc4814994dcf8b5f027fdac8` |
| `cryptox/recovery_dag_wire.go` | `5a028091f1964124324bd0684de8bd3c6cf496bac681d4cb645018679be5a2ac` |
| `cryptox/testdata/recovery-dag-v1.json` | `22f82f175fcd940c04e6745150e9399f747bc9954fee3cad0e4af614e0697287` |
| `.mise/tasks/test-recovery-dag` | `ea35dbbb3559849a5096e176703bf9b6533e2f846fa5203c9af572aeb737179a` |
| `.mise/tasks/check-recovery-dag` | `9114a6983767fd70da3be1f52fa165b0b8bc043525e23588bebe7444ddcffa9e` |

公开合成向量 `vectors/recovery-dag-v1.json` 与 core 镜像逐字节相同，SHA256 为 `22f82f175fcd940c04e6745150e9399f747bc9954fee3cad0e4af614e0697287`。`syntheticSeedsHex` 是明确公开的固定测试种子，用于复现测试签名；没有部署或用户凭据。Go 标准库与 Node 标准库独立核对 6/12/25/18/16 项固定编码与各域签名，旧 v1 的标量同形包仍须由原域验签，新 Source/Proof4/cert5 不通过旧入口。

唯一旧文件变更是把成熟 Proof3 控制图验证块移到独立 helper，仅将 archive 编码函数和已验恢复 grants 参数化。旧 parser、canonical、域和向量不改变。

## 调用边界

`VerifyRecoveryDependencyBundle` 验完整原初始化和按签名序号排序的记录；`VerifyIssuerRecoveryDAG` 额外验最终精确来源与无多余节点闭包。`VerifyRecoveryDAGAdvance` 保留原 pin、原初始化和已见恢复链头，不从候选 root 或目录建立信任。`RecoverySourceFromProof3` 只把已经验证的旧 Proof3 转成有界叶与平坦表。

新用途签名入口是 `SignOldRecoveryTransitionV2`、`SignAllAdminRecoveryTransitionV2`、`SignNewRecoveryTransitionV2`、`SignRecoveredDeviceByRecoveryV2` 和 `SignRecoveredDeviceAfterHPKEV2`；新命令 decoder 拒重复、未知、null/缺必填、非法 UTF-8、尾随及超限 JSON。cert5 的审批/完成核验需要 `ConfirmedEnrollmentAnchor`，不能以服务器返回的管理者目录代替已确认 PAKE。

这些方法证明公开签名与来源连续性，不能单独证明当前在线授权或服务器绝对最新。产品仍须逐次重查当前完整环境/权限集合、期限、撤销、设备状态、generation、接受历史、请求幂等、pull 序号/检查点和本机 epoch，并在原保护状态事务中提交。major2 与新 routes 仍是接入合同；本批库不发送请求、不创建会话、不激活环境、不保存任何恢复私钥。

原恢复 Ed 用途钥只允许原生/Go 进程内受限句柄；HPKE 接收私钥在 Begin 后清除。App 中断或必要 KV 改变要求重新开始恢复；本批没有改变这项生命周期。
