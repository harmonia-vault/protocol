# 既有可信设备的开机会话

后台系统服务需要在重启、尚无人登录时重新验证已获授权的设备。该过程不缓存或重发密码等价凭据；软件设备 Ed25519 私钥的本地保护、最小权限与磁盘解锁边界由平台服务实现。这里的协议只证明既有可信设备持钥，不登记新设备，也不能绕过管理手机的配对审批。

## 挑战与签名

`POST /v1/accounts/{accountId}/boot-challenges` 的 JSON 为 `{deviceId,accountGeneration}`，无需登录 bearer。服务器在账号同一权威事务中核对设备没有撤销，且至少一个当前环境授权尚有效，再生成随机 32 字节 nonce 和 120 秒单次挑战。挑战记录固定账号代际、设备 ID、已登记的签名公钥及接收公钥。

返回 `{challengeId,nonce,expiresAt,signingPayload}`；`expiresAt` 在 HTTP 响应中是 Unix 秒整数。签名使用固定全字符串数组的 UTF-8 JSON：

```text
["harmonia/device-boot/v1",accountId,accountGeneration,deviceId,
 signingPublicKey,receivingPublicKey,challengeId,nonce,expiresAt]
```

数组中的 `expiresAt` 为规范正十进制字符串。nonce、公钥和签名均使用无 padding 的规范 base64url；公钥各 32 字节，Ed25519 签名 64 字节。账号、设备及挑战 ID 使用协议 v1 的 ID 格式。客户端根据本地固定的账号、代际、设备及两把公钥重建数组，精确核对返回值，不能直接盲签服务器提供的任意用途数组。

`POST .../boot-sessions` 的 JSON 为 `{deviceId,accountGeneration,challengeId,signature}`。服务器重新检查当前设备状态、全部绑定字段、两把精确登记公钥、授权和挑战期限，严格验证 Ed25519 后，原子消费挑战并创建设备绑定随机 bearer 会话。正常会话最长 3600 秒。并发或重放同一挑战只有一次成功；失败签名不消费有效挑战。

## 后续请求与限制

后续 pull、写入、授权入口继续逐次检查账号代际、会话、设备、授权和期限。已有授权被撤销或降权后，旧会话不能继续读取或写入受影响环境；客户端检测到到期后即使离线也应停止环境生效。会话到期时重新走开机挑战流程，需要联网。

服务端只保存 bearer 的 SHA256，不记录 token 或设备私钥。bearer 仍是可重放凭据，必须使用 HTTPS、禁止日志和缓存泄露，并保护本地存储；本方案不声称抵抗有效会话被盗。设备签名钥必须与 HPKE 接收钥独立。平台软件保护不等于始终硬件内密钥。

本地密钥保护不得绕过启动前磁盘解锁。不能依赖只有用户登录后才解锁的钥匙串来完成无人登录启动；相应的软件密钥保护风险与服务安装权限必须由平台实现说明。当前服务端协议通过合成测试，不代表三平台后台服务安装与无人登录启动已全部验收。

`vectors/device-boot-v1.json` 为公开合成 Go 签名向量，TypeScript 核对完全相同字节与签名。服务端另测错误设备、两把公钥变化、撤销、到期、账号重置、并发单次消费和 SQLite 重开后的回放拒绝。
