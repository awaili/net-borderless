# 05 · 源代码目录结构设计

版本 v0.1（草案） · 2026-09-30 · 对应架构文档 02

---

## 1. 总览

```
shadowrocket-copy/                # Aegis monorepo
├── Cargo.toml                   # Rust workspace 根（members = crates/*）
├── rustfmt.toml                 # 格式化规范
├── deny.toml                    # cargo-deny：许可证 + 依赖审计
├── justfile                     # 常用命令入口（check/test/lint/fmt）
├── .github/workflows/ci.yml     # CI：fmt + clippy + test
│
├── docs/                        # 产品与设计文档（01–05）
│
├── crates/                      # ── 核心引擎（全平台共享，Rust）──
│   ├── aegis-config             # 配置 schema、校验、热重载、生态导入
│   ├── aegis-rules              # 规则编译器：域名 trie / LPM / 表达式 AST / 规则集签名
│   ├── aegis-dns                # DNS 服务器、DoH/DoT/DoQ 上游、fake-ip、split-DNS
│   ├── aegis-outbound           # 协议栈：ss2022/trojan/vless+reality/wg/hy2/tuic/http/socks
│   ├── aegis-inbound            # 入站：mixed/http/socks 监听
│   ├── aegis-tun                # TUN 设备抽象（cfg 按平台：apple/windows/linux/android）
│   ├── aegis-router             # 连接编排：嗅探、策略组、探活调度、自动摘除回融
│   ├── aegis-observe            # 连接表、流量聚合（SQLite）、指标 EWMA
│   ├── aegis-diag               # 一键诊断流水线（8 项 checklist）、健康分
│   ├── aegis-api                # 本地 API：REST + WS，token 鉴权（axum）
│   └── aegis                    # 二进制：CLI + 无头守护进程（聚合上述全部）
│
├── apps/                        # ── 平台 UI 壳（薄，仅做展示与交互）──
│   ├── android/                 # M1：VpnService + uni-FFI（首个移动端交付，移动 UX 定型场）
│   ├── ios/                     # M2：App + Packet Tunnel Provider
│   └── desktop/                 # 1.x 可选：Tauri（macOS + Windows）；1.0 桌面仅交付 CLI
│
├── presets/                     # 示例配置 / 规则模板（首次向导用）
│
└── tests/                       # ── 跨 crate 测试 ──
    ├── interop/                 # 协议互通矩阵：Aegis ↔ sing-box（docker-compose 编排）
    └── e2e/                     # 端到端：故障注入、泄露检测（M1 起）
```

**与架构文档 02 的一处偏差**：文档中 `aegis-tun-{apple,windows,...}` 四个 crate 合并为单个 `aegis-tun`，平台差异用 `cfg(target_os)` 模块切分。理由：每个平台 glue 都很薄（<2k 行），拆 crate 增加的工作区噪声大于收益；单人 review 边界更清晰。

## 2. 依赖分层（必须保持无环）

```
L0  aegis-config   aegis-inbound   aegis-tun        （叶子，不依赖其他业务 crate）
L1  aegis-rules    aegis-dns       aegis-outbound   aegis-observe
L2  aegis-router   aegis-diag                        （编排层）
L3  aegis-api                                        （对外契约）
L4  aegis (bin)                                       （组装）
```

硬规则（CI 强制，用 `cargo-deny` bans + 脚本检查）：

1. `aegis-api` 不被任何 crate 依赖（它是终点）。
2. `aegis-observe` 不依赖 `aegis-router`——方向反过来：router 通过 observe 暴露的 **sink trait** 推送事件（避免可观测性反向绑架核心）。
3. `aegis-outbound` 各协议模块互不依赖，只共享 crate 内的 `Connector` trait 与传输层工具。
4. 任何 crate 禁止依赖 `apps/`，UI 只通过本地 API 消费核心。

```
路由数据流向（运行期）：
inbound/tun ─→ dns(嗅探) ─→ rules ─→ router(策略组) ─→ outbound
                    │           │          │
                    └────→ observe.sink ←──┘     （单向事件流）
```

## 3. Crate 职责与关键接口（规划）

| Crate | 对应 PRD | 关键公开项（M0 目标签名示意） |
|---|---|---|
| `aegis-config` | F7 | `struct Profile`；`load(yaml) -> Result<Profile>`；`import_singbox/Clash`；热重载 diff 事件 |
| `aegis-rules` | F2 | `CompiledRules::build(&[Rule])`；`match_(ctx: &ConnCtx) -> Decision`；rule-set 加载与 Ed25519 签名校验 |
| `aegis-dns` | F4 | DNS server（TUN 下应答）；`enum Upstream { DoH, DoT, DoQ }`；fake-ip 池；split-DNS 联动规则引擎 |
| `aegis-outbound` | F1 | `#[async_trait] trait Connector { async fn connect(...) }`；每协议一个模块（`ss2022/ trojan/ vless/ wg/ hy2/ tuic/ http/ socks/`） |
| `aegis-inbound` | — | mixed/http/socks 监听器，产出统一的入站连接事件给 router |
| `aegis-tun` | — | `trait TunDevice`；`#[cfg(target_os)]` 模块：apple(utun)/windows(wintun)/linux/android；读写包循环 |
| `aegis-router` | F3 | 策略组 `select/url-test/fallback/load-balance/smart`；探活调度器（摘除/回融）；连接编排主循环 |
| `aegis-observe` | F5 | `trait EventSink`；连接表（slab，上限可配）；SQLite 聚合（traffic_daily/rtt_history/diag_reports/suggestions） |
| `aegis-diag` | F6 | `Diagnostic::run(checklist) -> DiagReport`；泄露检测；流媒体解锁检测（P1）；健康分 |
| `aegis-api` | 全部 | REST（配置/节点/规则 CRUD）+ WS（连接表、状态推送）；token 鉴权；OpenAPI schema 导出 |
| `aegis` (bin) | — | `aegis run`（无头守护）、`aegis status`、`aegis diag`、`aegis import <file>` |

## 4. 平台壳（apps/）

- **apps/android**（M1，首个移动端交付）：`VpnService` + 前台服务，核心编译为 `aarch64-linux-android` 动态库经 uni-FFI 绑定；凭据走 Keystore。分发 GitHub Releases 侧载内测。移动端 UX（信息架构/向导/诊断交互）在此定型，iOS 继承。
- **apps/ios**（M2）：Xcode 工程内嵌 `aegis-tun`（apple 模块编译出的 staticlib）为 Packet Tunnel Provider 扩展；主 App 与扩展通过 App Group + 本地 API 通信。Rust 静态库走 `cargo build --target aarch64-apple-ios` + `cbindgen` 生成 FFI 头。
- **apps/desktop**（1.x 可选）：Tauri 壳，仅通过 `aegis-api`（127.0.0.1 + token）与核心通信。核心以系统服务运行，UI 退出网络不断（PRD/架构约定）。1.0 阶段桌面仅交付 CLI。

## 5. 约定

**命名**
- crate：`aegis-<领域>`；模块：单数小写（`rule/`、`node/`）；类型不加 `Aegis` 前缀。
- 错误：各 crate 自有 `Error`（thiserror），跨层用 `anyhow`，FFI 边界永不泄漏 panic。

**测试布局**
- 单元测试：与实现同文件 `#[cfg(test)]`。
- crate 集成测试：`crates/<x>/tests/`。
- 协议互通矩阵：`tests/interop/`——每协议两个方向（Aegis client ↔ sing-box server、反向），docker-compose 起 sing-box，CI 跑（M0 验收门）。
- 故障注入：`tests/e2e/`（tc netem、进程杀停脚本），M1 起。

**配置 schema**
- 源格式为本仓库自有 YAML（`presets/example.yaml` 是活样例，schema 变更必须同步改它）；sing-box/Clash 是导入格式，进 `aegis-config/src/import/`。

**工具链**
- `cargo fmt` / `cargo clippy -- -D warnings`（CI 阻塞）；`cargo-deny check`（许可证：GPL-3.0/MIT/Apache-2.0/BSD/ISC 兼容集合）。
- 常用命令见 `justfile`：`just check` / `just test` / `just lint`。

## 6. 当前骨架状态

本目录已按上述结构落地**零依赖可编译骨架**（各 crate 目前只有 `lib.rs` 文档桩，不含任何外部依赖——保证离线 `cargo check` 通过）。第一个引入真实依赖的 crate 应从 `aegis-rules` 与 `aegis-config` 开始（它们是 L1 以下，且不依赖异步运行时）。