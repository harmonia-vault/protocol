# Harmonia / 和弦 — protocol

Harmonia 的版本化线协议、确定签名编码、威胁模型及 Go/TypeScript 互操作向量。采用 MIT 许可证。

目前是实验性实现，安全流程仍在开发，不能宣称生产可用。完整技术设计和里程碑状态见 [workspace](https://github.com/harmonia-vault/workspace)。

- [线协议](docs/WIRE.md)：写操作、管理授权、环境封套、当前权限、持久化序号和幂等。
- [威胁模型](docs/THREAT-MODEL.md)：安全边界与未完成门槛。
- [设备持钥会话](docs/DEVICE-SESSION.md)：登录凭据与既有可信设备签名钥的单次挑战绑定。
- [实际测试证据](docs/TEST-EVIDENCE.md)：已通过测试及未跑门槛。
- `typescript/wire.ts`：无依赖、可供 Node/Workers 使用的规范编码器。
- `vectors/signatures-v1.json`：公开合成测试数据；Go 和 Node 核对相同字节及 Ed25519 签名。

运行 `mise run test` 验证 Node 互操作与拒绝篡改。完整 SPAKE2 配对、恢复轮换、平台钥保护及生产资源验收尚未完成。
