# tests/interop — 协议互通矩阵（M0 验收门）

验证每个 P0/P1 协议与 sing-box 官方实现**双向**互通：

| 方向 | 服务端 | 客户端 |
|---|---|---|
| A | sing-box | Aegis |
| B | Aegis | sing-box |

覆盖协议（P0）：shadowsocks-2022 / trojan / vless+reality / http / socks5 / wireguard；
P1 补充：hysteria2 / tuic。

规划内容（M0 中实现）：
- `compose.yml`：起 sing-box 服务端容器 + Aegis 二进制
- `cases/`：每协议一个用例（连接建立、吞吐、UDP、断线重连）
- 断言脚本进 CI（`.github/workflows/ci.yml` 的 interop job）