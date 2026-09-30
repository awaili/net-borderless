# 02 · 系统架构设计

版本 v0.1（草案） · 2026-09-30 · 对应 PRD v0.1

---

## 1. 总体架构

```
┌─────────┬─────────┬─────────┬─────────┬─────────┐
│ iOS App │ macOS UI│ Win UI  │ Android │ CLI/TUI  │   ← 原生 UI，薄壳
├─────────┴─────────┴─────────┴─────────┴─────────┤
│  平台适配层                                      │
│  NetworkExtension(tun) / SystemExt / WinTUN /    │
│  VpnService(tun) / mixed+socks inbound          │
├─────────────────────────────────────────────────┤
│  aegis-core  （Rust，单二进制，跨平台）            │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐  │
│  │ inbound │ │ router │ │outbound│ │ observe  │  │
│  │ tun/mix│→│dns+嗅探│→│ 协议栈  │→│ 连接表/统计│  │
│  │         │ │规则编译 │ │        │ │ 诊断     │  │
│  └────────┘ └────────┘ └────────┘ └──────────┘  │
│                    aegis-api (HTTP + WS)        │
└─────────────────────────────────────────────────┘
```

**核心思想：UI 只是核心引擎的一个客户端。** 引擎以本地 HTTP/WS API（127.0.0.1 随机端口 + token，Unix socket 优先）暴露全部能力，UI、CLI、甚至第三方工具都走同一 API。这保证：

- 桌面端可以无 UI 运行（服务模式），路由器/家庭服务器可复用
- iOS 上 App 与 Network Extension 进程间通信走同一契约，减少双实现
- 诊断、统计逻辑只有一份实现

## 2. Crate 划分（Rust Workspace）

| Crate | 职责 | 关键依赖 |
|---|---|---|
| `aegis-config` | YAML schema、校验、热重载、sing-box/Clash 导入 | serde, jsonschema |
| `aegis-rules` | 规则编译器（域名 trie、LPM、逻辑表达式 AST）、规则集加载与签名校验 | ipnet, regex-automata |
| `aegis-dns` | DNS 服务器（TUN 下应答解析）、DoH/DoT/DoQ 上游、fake-ip、split-DNS | hickory, rustls |
| `aegis-outbound` | 协议实现：ss2022 / trojan / vless+reality / wg / hysteria2 / tuic / http / socks / 链式 | quinn, boringtun(boring), rustls |
| `aegis-router` | 连接编排：嗅探（SNI/协议探测）、策略组（select/url-test/fallback/smart）、探活调度 | tokio |
| `aegis-inbound` | TUN 设备抽象 + mixed/http/socks 入站 | — |
| `aegis-observe` | 连接表、流量聚合（SQLite）、指标 EWMA | rusqlite |
| `aegis-diag` | 诊断流水线（8 项 checklist）、健康分 | — |
| `aegis-api` | 本地 API（REST + WS），token 鉴权 | axum |
| `aegis-tun-{apple,windows,linux,android}` | 平台 TUN/服务 glue，`cfg` 按平台编译 | wintun, utun |

选型理由（ADR 摘要）：

1. **Rust 而非 Go/Swift**：iOS NE 50MB 硬上限 + 无 GC 抖动，是移动代理核心的生死线；Swift 会让桌面/移动双端逻辑双实现。
2. **tokio** 全异步栈，quinn 提供 QUIC（hysteria2/tuic/doq 共用）。
3. **自有配置 schema 为源，sing-box/Clash 为导入格式**（而非兼容超集）：避免被外部 schema 绑架演化节奏，同时导入路径保住迁移成本为零。
4. **HTTP+WS 而非 gRPC**：iOS 进程间通信、桌面 UI、测试脚本三场景下更薄。
5. **SQLite 做本地存储**：连接统计、诊断报告、学习数据同一介质，桌面移动共用实现。

## 3. 数据流（单连接生命周期）

```
TUN 包 → NAT 表还原五元组
  → [UDP:53] aegis-dns 应答（fake-ip 或上游转发）
  → [其余] 嗅探（首包 SNI/HTTP host/quic SNI，预算 3KB/3 个包）
  → 规则匹配（编译期生成的 trie + LPM + 表达式树）
  → 策略组选择（含探活状态过滤、smart 组打分）
  → outbound 建立（连接池复用 / mux 复用）
  → 双向拷贝 + observe 记录（命中规则、节点、字节、RTT）
```

性能预算：嗅探缓存 + 规则匹配在热路径上**零堆分配**（预分配 arena）；连接表用 slab 存储，上限可配（默认 10k，iOS 5k）。

## 4. 探活与自适应（对应 PRD F3）

- 探活调度器：每策略组独立定时器（url-test 默认 300s，故障组加速到 30s）。
- 双探针：TCP 握手 RTT（成本低，高频）+ HTTP 首字节（真实负载，低频）。
- 摘除/回融：连续 3 次失败摘除；摘除后探活间隔退避（30s/60s/120s）；恢复需连续 2 次成功。
- smart 组打分：`score = ewma_rtt × (1 + 5 × fail_rate) × burst_penalty`，参数随版本调整，写入诊断报告便于解释。

## 5. 平台集成要点

### iOS（最难，单列）
- Packet Tunnel Provider，内存预算分解（目标 < 40MB）：

| 项 | 预算 |
|---|---|
| Rust 核心常驻 | ~12MB |
| TUN 缓冲 + 连接表（5k 条） | ~8MB |
| tokio 运行时 + 协议栈峰值 | ~15MB |
| 余量 | ~5MB |

- 超预算防线：连接数上限、嗅探缓存 LRU、无活动 5 分钟释放连接池。
- App ↔ NE 通信：App Group + 本地 API over XPC/Unix domain socket。
- Kill switch：默认路由指向 TUN + `includeAllNetworks`；NE 崩溃时 iOS 自身不回退直连（行为写入文档与诊断说明）。

### macOS / Windows / Linux
- 核心以**系统服务**运行（Windows Service / launchd / systemd），UI 是客户端——UI 崩溃不影响网络。
- macOS：System Extension + Developer ID 分发（不走 MAS，避免沙盒限制 NE 能力）。
- Windows：WinTUN + 服务进程，UI 托盘常驻。

### Android
- VpnService + 前台服务；配置加密走 Keystore。

## 6. 存储设计

- SQLite 单库（桌面/移动路径经平台抽象）：
  - `connections`（实时，内存 slab + 落库采样）
  - `traffic_daily`（域名/节点/规则三维聚合，90 天滚动）
  - `rtt_history`（节点延迟曲线，7 天明细 + 降采样保留 90 天）
  - `diag_reports` / `suggestions`
- 凭据永不入库：节点密钥、订阅 URL → OS Keychain / Credential Manager，库里只存引用 ID。

## 7. 安全设计

- 本地 API：绑定 127.0.0.1/Unix socket + 每次启动随机 token；桌面多用户下 socket 权限 0600。
- 规则集签名：Ed25519，密钥随版本内置 + 支持用户自定义信任锚（`minisign` 风格）。
- 崩溃安全：核心 panic → TUN 默认路由仍在 → 流量黑洞（fail-closed）而非裸奔；watchdog 重拉核心，恢复后补发诊断报告。
- fuzz：规则匹配器、协议解析器（入站方向）进 CI。

## 8. 测试策略

1. **协议互通矩阵**：`Aegis client ↔ sing-box server`、`sing-box client ↔ Aegis server` × 全部 P0/P1 协议，CI 容器化跑。
2. **故障注入**：节点挂 / DNS 污染 / 随机丢包（tc netem）/ 半开连接，验证摘除回融与诊断结论。
3. **性能基线**：每 release 跑 iperf3 + 1 万连接压测，回归超 10% 阻塞发布。
4. **泄露测试**：自动化 DNS leak / IPv6 leak 用例。