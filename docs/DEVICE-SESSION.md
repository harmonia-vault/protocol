# 登录与既有设备持钥会话

账号登录证明密码等价凭据持有，不等于设备可信。仅有登录 token、账号代际和 `deviceId` 不能读取或修改 vault。

当前切片采用一次设备持钥挑战后发行新的设备绑定会话，不另行支持每次请求证明 profile。服务器为已登录会话中的既有设备生成短时单次挑战；设备使用已获信任的独立 Ed25519 签名钥签下述固定全字符串数组：

```text
["harmonia/device-session/v1", accountId, accountGeneration,
 deviceId, loginTokenHash, challengeId, nonce, expiresAt]
```

`loginTokenHash` 是登录 bearer token 原始 UTF-8 字节 SHA256 的小写 64 位 hex。`challengeId` 使用规范 ID 格式；`nonce` 为随机 32 字节、无 padding base64url；`expiresAt` 为规范正十进制 Unix 秒字符串。它们与登录会话、账号代际和精确设备绑定，短时有效且一次消费。服务器核对固定设备公钥、当前状态、有效期和签名后，在账号同一权威事务中消费挑战并发行新的随机设备绑定 token；并发成功不得重复发行，失败或超时不得进入业务授权。

路由通过 `POST .../device-challenges` 和 `POST .../device-sessions` 实现，以 server 路由文档为准。后者请求含 `challengeId` 和签名，登录 bearer 用于定位会话。登录 token 必须被读取、写入、授权和通知入口拒绝，只有新设备绑定 token 才可访问这些入口；每次仍重新检查当前设备、账号代际和授权。只在 WebSocket 握手检查不够。

客户端从自己已知的账号、代际、设备和登录 token 重建证明，核对挑战字段。不能直接对服务器返回的任意 `signingPayload` 盲签。证明不能跨账号、代际、设备、登录会话、挑战、nonce 或有效期重放；单次消费由服务端持久化状态保障，不能仅靠时间戳。它只证明既有可信设备持钥，不能绕过成熟 SPAKE2 新设备审批、公钥固定和手机确认。

设备绑定 token 仍是 bearer 凭据，必须经 HTTPS 传输、保护本地存储、禁止日志/缓存泄露。该方案不承诺抵抗有效设备会话 token 被盗后的使用；当前撤销和账号重置必须使其失效。

`vectors/device-session-v1.json` 是公开合成测试向量。Go 和 Node 核对相同字节、签名及全部字段绑定。服务器另测挑战一次性、过期、当前授权、账号重置和并发行为。密码登录、设备持钥证明、可信设备审批是三个独立检查。
