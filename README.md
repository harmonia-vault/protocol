# Harmonia / 和弦 — protocol

Harmonia 的版本化线协议、确定签名编码、威胁模型及 Go/TypeScript 互操作向量。采用 MIT 许可证。

目前是实验性实现，安全流程仍在开发，不能宣称生产可用。完整技术设计和里程碑状态见 [workspace](https://github.com/harmonia-vault/workspace)。

- [线协议](docs/WIRE.md)：写操作、管理授权、环境封套、当前权限、持久化序号和幂等。
- [威胁模型](docs/THREAT-MODEL.md)：安全边界与未完成门槛。
- [设备持钥会话](docs/DEVICE-SESSION.md)：登录凭据与既有可信设备签名钥的单次挑战绑定。
- [开机会话](docs/BOOT-SESSION.md)：既有可信设备在重启后的持钥验证。
- [设备配对](docs/PAIRING.md)：固定 BoringSSL draft02 profile、双向密钥确认、中继及入网证书。
- [恢复与轮换](docs/RECOVERY.md)：受限恢复会话、新码重输证明、完整封套和可信根原子切换。
- [环境来源证明](docs/ENVIRONMENT-ORIGIN.md)：创建/轮换并列权限来源、证书 v3 与受保护证据账本。
- [恢复授权连续链草案](docs/RECOVERY-AUTHORITY-DESIGN.md)：原初始化锚、两种轮换授权与显式恢复设备登记，尚未实现。
- [实际测试证据](docs/TEST-EVIDENCE.md)：已通过测试及未跑门槛。
- `typescript/wire.ts`：无依赖、可供 Node/Workers 使用的规范编码器。
- `vectors/`：公开合成测试数据；包含管理/写操作、设备持钥、初始化、入网、恢复与环境生命周期签名编码。

运行 `mise run test` 验证本仓库 Node 互操作与拒绝篡改；原生配对及新增 Go 签名流程的测试入口与真实结果见测试证据。完整手机与三平台配对、管理授权历史核验、平台钥保护和生产资源验收仍未完成。

多管理设备的可验证签发者来源见 [ISSUER-PROOF.md](docs/ISSUER-PROOF.md)；证书 v2 已接入真实配对、受保护回执与后台重验，结果由 workspace 记录。新增非初始环境/轮换来源切片见 [ENVIRONMENT-ORIGIN.md](docs/ENVIRONMENT-ORIGIN.md)，Go/服务端来源闭环和后台已通过真实联合测试；通用手机原生接线及暂停 KV 轮换保配置边界仍在继续，详见该文档。
