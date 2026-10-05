# Harmonia Protocol

Harmonia 客户端与服务端共用的数据格式和签名编码，用于设备授权、环境变量同步和账号恢复。

普通使用者无需单独安装此仓库，请从 [Harmonia](https://github.com/harmonia-vault/workspace)开始。

## 使用方式

需要接入 Harmonia 协议时：

1. 从 [TypeScript 编码器](typescript/wire.ts)读取对应消息类型与确定性编码。
2. 使用 [互操作向量](vectors/)核对不同语言生成的字节和签名。
3. 根据服务返回的协议版本与能力选择兼容消息；不兼容时停止操作，不自动降级。

签名校验不能代替设备授权。接入方仍需检查账号、设备、环境权限及有效期，并保护本地密钥和恢复码。

## 许可证

[MIT](LICENSE)
