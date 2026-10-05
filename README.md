# Harmonia Protocol

Harmonia（和弦）是一个自托管的环境变量同步工具：在手机上集中管理环境变量，按设备授权，同步到电脑和运行环境中使用。

本仓库定义 Harmonia 客户端与服务端共用的消息格式和签名编码，用于开发兼容的客户端或服务端。普通用户无需使用本仓库，请从 [Harmonia](https://github.com/harmonia-vault/workspace) 开始。

## 内容

| 路径 | 说明 |
| --- | --- |
| [`typescript/wire.ts`](typescript/wire.ts) | 各类消息的结构定义与确定性编码 |
| [`vectors/`](vectors/) | 互操作测试向量，用于核对各语言实现的编码结果和签名 |

## 接入

1. 参照 `wire.ts` 实现所需的消息类型与编码。
2. 使用 `vectors/` 中的测试向量，核对实现生成的字节和签名完全一致。
3. 所有业务请求使用 `Harmonia-Protocol-Major: 2` 和 DAG 消息；不接受旧版协议。

签名校验通过不代表操作已获授权，实现方仍需检查账号、设备、环境权限和有效期。

## 许可证

[MIT](LICENSE)
