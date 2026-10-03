# P4 来源的环境控制与 CRUD

本切片供已经可信入网、持本机钥匙的 P4 设备使用。它复用现有环境签名域、HPKE 封套、环境来源双签和账号幂等库，不增加恢复状态或新的密码学原语。P4 客户端请求与响应使用 `Harmonia-Protocol-Major: 2`；DAG 控制与 V4 路由强制要求 major2，原 rename/delete 路由保留旧 header 兼容并校验当前 DAG 权源。来源能力为 `issuer-recovery-dag-v1`。P4 客户端不能回退到 P2/P3 parser。账号的原初始化、受保护 pin 与已接受 DAG 历史保持原身份。

账号路由前缀为 `/v1/accounts/{accountId}`：

| 路由 | 请求 | 响应 |
| --- | --- | --- |
| `/issuer-evidence?environmentId=E&capability=issuer-recovery-dag-v1` | GET，当前 E Admin 的绑定设备会话 | `{sequence,grants,issuerEvidence}`；`issuerEvidence` 必须为 `harmonia/issuer-proof/v4` |
| `/environment-changes-v4` | POST，完整 `{change,signature,origin}`；禁 query | `{sequence,replayed}` |
| `/environment-changes-v4/{originalId}` | GET，禁 query | `{state:'unknown'}` 或 `{state:'complete',sequence,contentHash}` |
| `/environment-changes` | POST，仅重命名或删除时沿原 `{change,signature}` | 原接受收据；后续仍须验签 Pull |

控制响应只包括该环境当前有效、当前 KeyVersion 的完整接收者 grants，以及其已接受权源闭包和唯一 actor Admin target。它不授予新权限：服务端事务仍逐次检查账号代际、设备与绑定会话、当前 Admin/期限/KeyVersion/GrantGeneration、恢复代际和 expectedSequence。客户端使用本机原 pin 验完整 DAG、历史双钥身份和来源，保留已见恢复头与接受序号下界；缺初始化、缺祖先、候选回退、混合 profile、未来记录或未来环境 origin 都拒绝。历史控制重验仅用于受保护业务 journal，不能替代发送前的当前授权。

创建与轮换分别使用现有 `harmonia/environment-change/v1` 与 `harmonia/environment-origin/v1`。原包内容 hash 继续按 `harmonia/environment-submission/v2` 计算，与旧 V2/V3 路由一致。轮换必须覆盖全部当前有效接收者、全部当前 live 变量、标签和当前恢复封套；角色与期限精确保留，环境 KeyVersion 和各接收者 GrantGeneration 按原规则递增。接受尾序号为 expectedSequence + 1 + 变量包数量。服务器只在完整验证后原子接受，不能先切换版本再补封套。

V2/V3/V4 路由共享同一 issuer/原 ID 的不可变收据。跨路由同包只返回原序号和 hash，不产生新写；同 ID 不同包冲突。重提交先查当前设备会话和 Admin，已降权只能查原收据。进入 DAG 后的新 create/rotate 不能走旧路由；旧已接受包仍可查询，但客户端不因此自动升级来源 parser。rename/delete 的签名域不变，服务端在 DAG 账号上核验当前完整 DAG 权源。

网络结果未知时保存并查询原 ID、原 hash、原 packet，不另造钥匙、封套或 ID。环境业务 journal 与 `recovery-dag-v1` 分开；后者的 checked journal 只接受恢复 transition/device-enrollment。成功响应仍不代表本机已应用：按相同验签 Pull 验原环境 checkpoint、每个轮换变量 ID/hash/序号和已接受 origin，再成功保存本机保护状态，才返回 Applied。保存失败必须返回 accepted-not-applied，之后只确认同一原收据。

暂停时不申请新业务写入。签名删除墓碑通过授权投影清除该环境缓存与 override，并重算其他来源；数据序号和 SeenMutations 不随授权投影推进。正在运行的 shell/进程仍遵守既有 provider 边界，不能从外部强改进程已有 env。

这是实验性接口。P4 授权管理、其他设备撤销控制、旧 source 显式升级和 manager-reanchor 不属于本切片。Go 原生加密 Vault/testadapter 联合证据不等于 Android/iOS 保护状态 Save 或 SDK 已验收；移动环境业务 journal/UI 尚未接通该 P4 路径。
