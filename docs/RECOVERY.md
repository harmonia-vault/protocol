# 恢复会话与恢复码原子轮换

恢复码是随机离线保存的 256 位种子，客户端用 HKDF-SHA256 按用途、账号代际和恢复代际分别派生 Ed25519 签名钥及 X25519 接收钥。恢复码不是数据备份；丢失所有可信设备和恢复码后无法找回旧 vault。历史旧码与旧密文已被取得时，后续轮换不能追回这些副本。

本切片实现账号内的持钥恢复、受限会话和原子轮换状态服务。手机完整恢复 UI、系统强认证和后续可信设备审批须独立完成，不能把局部测试描述为生产安全验收。

## 当前状态与单次恢复证明

账号持久化当前 `recoveryGeneration`、两把恢复公钥，以及每个当前环境/密钥版本的 HPKE 恢复封套。新增环境或环境钥轮换必须同时更新对应恢复封套及其代际/密钥版本，账号存储拒绝缺少、长度错误或过时代际的封套。服务器只能检查结构和签名，不能解密封套证明其内容确实是该环境钥。

`POST /v1/accounts/{id}/recovery-challenges` 的 JSON 为 `{accountGeneration}`。返回 `{challengeId,nonce,expiresAt,recoveryGeneration,signingPayload}`。挑战 ID 同时标识待建立的受限恢复会话；随机 nonce、当前公钥和两个代际保存在该账号唯一权威状态中。120 秒单次挑战的签名数组为：

```text
["harmonia/recovery-proof/v1",accountId,accountGeneration,
 recoveryGeneration,challengeId,nonce,expiresAt]
```

所有数组字段为字符串。`expiresAt` 为规范 Unix 秒字符串，HTTP 响应则用整数。签名采用恢复 Ed25519 私钥。用途由固定域隔离；会话 ID、nonce 和代际不能由客户端自报替换。客户端用输入恢复码派生的公钥验证自己的预期用途，不能盲签返回数组。

`POST .../recovery-sessions` 的 JSON 为 `{accountGeneration,challengeId,signature}`。服务器重新检查当前恢复公钥、账号/恢复代际与期限，原子消费挑战并建立 900 秒的受限 bearer，会话带 `rotationRequired:true`。该 bearer 只能取恢复材料、发起轮换和查询自己发起的轮换；普通 pull、变量写入、授权入口拒绝它。

## 恢复材料与可信根

受限会话使用 `Authorization: Bearer ...` 和 `X-Harmonia-Account-Generation` 请求 `GET .../recovery-vault`。已绑定的管理设备也可访问，但必须对所有当前环境具备有效 Admin；其请求还带 `X-Harmonia-Device-Id`。

返回账号/恢复代际、当前两恢复公钥、`rotationRequired`、账号序号、完整恢复封套、当前密钥版本的密文事件，以及 `trustRoot`、`publicDevices`、`currentGrants` 和 `grantHistory`。事件附写入时的签名授权快照；授权历史项含 `{sequence,grant,authorization}`，其中 `authorization` 是接受该授权时签发者的管理签授权。初始化可信根自签项的授权为空，只能从已验证可信根开始核验。

公钥材料由服务器返回本身不能建立信任。真实初始化账号保存恢复码签名的 `trustRoot` 对象：

```text
{rootDeviceId,rootSigningPublicKey,rootReceivingPublicKey,
 recoveryGeneration,recoverySigningPublicKey,recoveryReceivingPublicKey,signature}
```

其签名数组为：

```text
["harmonia/trust-root/v1",accountId,accountGeneration,
 rootDeviceId,rootSigningPublicKey,rootReceivingPublicKey,
 recoveryGeneration,recoverySigningPublicKey,recoveryReceivingPublicKey]
```

恢复客户端先由输入恢复码、本地预期账号及代际派生恢复公钥，精确匹配 manifest 两恢复公钥/代际并验证签名，再固定根设备 ID/两公钥。之后沿管理签授权历史核对账号、环境、密钥版本、授权代际、签发者 Admin 权限、期限约束、精确设备公钥及每次写入设备签名，最后按接受序号重建密文。不能只解密后接受值，也不能把服务器给出的新公钥直接当根。

当前客户端的完整授权历史核验、签名检查点持久化与历史接受时间证据仍需继续实现和验收；当前序号和历史材料不提供外部见证或服务器不可作恶保证。内部旧版合成夹具允许没有 manifest，跨语言测试必须显式预先固定合成根；公开初始化流程不能省略 manifest。

## 新码重输与轮换挑战

发起者必须是当前可信、会话绑定且对全部当前环境有 Admin 的设备，或当前有效受限恢复会话。对单个环境的 Admin 不能轮换整个账号恢复根。

客户端生成新种子并让用户重新输入完整新码，从重输种子派生新两公钥。它为所有当前环境的当前密钥版本生成 HPKE 恢复封套，并用新 Ed25519 重签相同根设备 ID/两公钥的 `newTrustRoot`。轮换不能趁机替换根设备。HPKE context 使用恢复用途、账号/账号代际、`recipientId:accountId`、新恢复代际、环境与密钥版本，依协议 v1 封套规则编码。

`POST .../recovery-rotations` 接收：

```text
{idempotencyKey,newRecoveryGeneration,newRecoverySigningPublicKey,
 newRecoveryReceivingPublicKey,envelopes,newTrustRoot}
```

`envelopes` 的每项为 `{environmentId,keyVersion,envelope}`。必须覆盖全部当前环境，拒绝重复、缺少、多余和过期密钥版本；封套是无 padding base64url 的 80 字节 HPKE 包。新恢复代际必须恰好旧值加一，两公钥都必须更新。只有未包含可信根的内部旧夹具省略 `newTrustRoot`。

`envelopesHash` 是按环境 ID 的 ASCII 字节顺序排列后，`[[environmentId,keyVersion,envelope],...]` 固定字符串数组 JSON 的 UTF-8 SHA256 小写 hex。`trustRootHash` 是上述可信根签名数组末尾追加其 `signature` 字符串后，JSON UTF-8 SHA256 小写 hex。对象字段顺序不影响这两个 hash。

返回状态、挑战 ID、nonce、120 秒期限、两恢复代际、两个 hash 及以下 `signingPayload`：

```text
["harmonia/recovery-rotation/v1",accountId,accountGeneration,sessionHash,
 recoveryGeneration,challengeId,nonce,expiresAt,newRecoveryGeneration,
 newRecoverySigningPublicKey,newRecoveryReceivingPublicKey,envelopesHash,trustRootHash]
```

`sessionHash` 是当前发起者 bearer token 原始 UTF-8 字节 SHA256 的小写 hex。新码重输派生的签名钥签该挑战。内部无 manifest 的旧夹具使用不带末字段的数组；真实账号必须使用完整数组，不能降级。

## 原子完成、断网和旧码失效

`POST .../recovery-rotations/{idempotencyKey}/complete` 的 JSON 为 `{challengeId,signature}`，认证头须与发起者一致。服务器检查当前账号、会话/设备权限、旧恢复代际、nonce、期限、仍完整且版本一致的封套集合、新可信根签名及固定根，再验证新恢复钥签名。一个账号事务内切换新两公钥、新恢复代际、全部恢复封套和新码重签的可信根，并仅分配一次接受序号。

只有该事务成功后旧恢复码才失效。其他恢复会话失效；若由受限恢复会话发起，该原 bearer 升为 `rotationRequired:false` 的可管理恢复会话，但仍不代表任何设备已登记，也不是普通设备会话。新的设备信任必须另走配对和管理批准。可信设备发起则保持其既有设备身份。

完成响应含 `{state:"complete",sequence,replayed,...}`。同一会话、同一幂等 ID 和完全相同结果重试返回原序号；更换内容或签名拒绝。断网结果不明先用 `GET .../recovery-rotations/{idempotencyKey}` 查询 `absent/pending/expired/superseded/complete`。查询不能跨发起会话。期限只是附加边界；持久化一次消费、操作/会话/代际绑定和原子事务才防回放，不能用时间戳替代。

服务器证明新签名私钥持有，无法证明用户真实备份了新码、两钥由同一重输种子派生，或所有封套解密后正确。客户端必须承担完整重输、生成和本地校验流程。测试包括旧码拒绝、受限权限、封套遗漏、字段替换、SQL 写失败全部回滚、数据库重开、幂等查询与单次并发证明；实际手机流程仍须单独验收。
