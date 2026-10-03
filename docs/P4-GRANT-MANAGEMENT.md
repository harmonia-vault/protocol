# P4 来源的每环境授权管理

本切片仅对已可信入网、持本机钥匙的 P4 设备开放每环境角色和期限修改。复用原 `harmonia/grant/v1` SignedGrant、HPKE、账号事务、幂等 ID 与来源 DAG，不新增原语、恢复状态或外部见证。旧 P2/P3 不自动升级；P4 不允许 parser fallback。

账号路由前缀为 `/v1/accounts/{accountId}`：

| 路由 | 合同 |
| --- | --- |
| GET `/grant-management?environmentId=E&capability=issuer-recovery-dag-v1` | 强制 major2 与明确 capability；原七字段 DTO 的 issuerEvidence 必须 P4 |
| POST `/grants` | 原 SignedGrant；P4 客户端 major2，raw header 保持旧兼容，服务端在 DAG 账号上逐次核完整当前来源 |
| GET `/grant-status?idempotencyKey=K` | 原本人不可变 `{idempotencyKey,accepted,sequence?,contentHash?}`；不返回值或封套 |

控制字段为 accountId、accountGeneration、environmentId、sequence、keyVersion、subjects、issuerEvidence。每个 subject 含 deviceId、signingPublicKey、receivingPublicKey、currentGrant 或 null、highestGrantGeneration。只有已有受签接受身份归档的设备可作为目标；完整 DAG 以本机原初始化/pin 核验，不从服务器目录建立信任。唯一权限 target 是本次环境的当前有效 actor Admin。其余行只提供经签名核验的历史身份/授权来源，不授予当前权限。

发送前在线检查绑定设备会话、账号代际、当前 Admin/期限/KV/GG、完整 DAG 和目标双公钥。目标新 GG 必须最高已接受 GG+1，当前 KV；临时 Admin 不得授予超过自身的期限。none 使用空封套，过期/none/旧 KV 的最高代际不可重置；重新授权必须用户明确角色/期限并生成当前 KV HPKE 封套。客户端保留每个已见目标 GG 和完整签包 fingerprint，拒绝回退及同 GG 异包，不能因 null 或省略行删除下界。

SignedGrant 的内容 hash 沿原 `SHA256(base64url(signingBytes)+'.'+signature)`。原 ID 同包重试只得原接受序号；同 ID 异包冲突。新包没有 expectedSequence/CAS 字段，仍是原 GrantGeneration 事务检查与服务器接受顺序，不擅增协议字段。结果未知只查或重试原不可变 packet，不能以当前角色恰好相同猜成功。

P4 保护业务 record 使用 Version2 与必需 DAG capability，绑定 endpoint/account/generation/device/owner epoch。提交前 native barrier 成功保存原包与 Attempted；失败零 POST。恢复只按原 ID/hash/seq，再通过同一完整验证 Pull 和原 grant checkpoint，成功本地保存才 Applied；已接受未保存返回 accepted-not-applied。环境授权 journal 属于业务状态，不能塞入恢复 transition/device-enrollment 的 checked journal。历史来源复验不替代当前写权限。

暂停拒绝管理写；当前 signed none/expiry 通过授权投影清缓存和 override、逐 key 恢复其他合法来源或原值，不推进数据序号与 SeenMutations。恢复授权后再完整 Pull 新版本数据。

本批不开放 P4 全局设备撤销、旧来源升级或 manager-reanchor；共用管理控制不会解除其门槛。移动 SDK/业务 Save/UI 仍须独立接线。Node/workerd 签包事务证据与真实 Go HTTPS/HPKE/BoringSSL PAKE/nativeVault adapter 证据必须分别报告；不能宣称生产可用。
