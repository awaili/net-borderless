# 04 · 路线图与里程碑

版本 v0.2 · 2026-09-30 · 工作代号 **Aegis** · 仓库 `github.com/awaili/net-borderless`

> **v0.2 变更**：产品需求变更为**移动优先**——Android 与 iOS 同为 1.0 硬性交付物。
> 桌面端降级为 CLI（开发/测试载体），桌面 GUI 移入 1.x 可选项。

---

## 0. 总体策略

**核心一份，移动双端先行。**

交付顺序及其理由：

1. **M0 先写核心引擎**（不变）：手机端只是核心的"壳"，核心不稳，双端都白做；
2. **M1 先 Android 后 iOS**：Android 没有 App Store 式审核门槛（可 GitHub Releases 直接分发内测包）、设备矩阵可用真机自测——**移动端 UX（信息架构、向导、诊断交互）先在 Android 上定型**，iOS 直接继承验证过的交互，降低双端返工；
3. **M2 攻坚 iOS**：NE 内存上限与 VPN 类目审核是全项目最大工程风险，投入时 Android 已在公测回血经验；
4. **M3 双端同时发 1.0**。

人力假设：2 名全职工程师（1 核心/协议、1 平台/移动 UI）+ 1 名兼职设计。Android（M1）与 iOS（M2）串行；若补到 3 名工程师，可让 iOS 提前 6 周介入（`aegis-tun` apple 模块与 M1 并行）。

## 1. 里程碑

### M0 · 核心引擎验证（第 1–3 月）——不变

**目标**：证明"Rust 核心 + 自适应策略"技术路线成立；产出手机端可嵌入的静态库。

- 交付：`aegis-core` 静态库 + CLI 验证载体
  - P0 协议全量：ss2022 / trojan / vless+reality / http / socks / wireguard
  - 规则引擎 v1（trie + LPM + 逻辑表达式）+ sing-box 规则集加载
  - url-test / fallback 策略组 + 探活摘除回融
  - DNS：直连 + DoH 上游 + split-DNS；本地 API v1
  - **移动前置项**：`cargo build --target aarch64-linux-android / aarch64-apple-ios` 交叉编译链路打通，FFI 边界（cbindgen + uni-FFI）定型
- **验收门**：
  - [ ] sing-box 互通测试 5 协议全绿（双向）
  - [ ] iperf3 单核 ≥ 1Gbps；1 万连接 24h 稳定
  - [ ] 故障注入：节点宕机 → 30s 内自动切换
  - [ ] 规则匹配 p99 < 50µs，fuzz 通过
  - [ ] Android/iOS 交叉编译产物可在真机 demo 中完成一次代理转发

### M1 · Android 公测（第 4–6 月）

**目标**：第一个有真实用户的版本；移动端 UX 在此定型。

- 交付：Android App（VpnService + 前台服务）
  - 核心以静态库嵌入（uni-FFI/JNI 绑定），Keystore 存凭据
  - 信息架构 v1：状态/连接/规则三 Tab + 首次配置向导（docs/03 §2–3）
  - 一键诊断 v1（8 项 checklist）+ 规则建议卡片 v1
  - 订阅 URL 导入；sing-box / Clash 配置导入
  - Kill switch（默认路由接管 + 崩溃 fail-closed）
- 分发：GitHub Releases 侧载内测（免审核，快速迭代）→ Play 内部测试轨道
- **验收门**：
  - [ ] 公测 500 用户，周留存 > 60%
  - [ ] 诊断故障注入用例正确率 > 90%；泄露测试零泄露
  - [ ] 真机矩阵（Android 10–16，≥ 6 机型）崩溃率 < 0.5% 会话
  - [ ] 连续使用 1h 额外耗电 < 5%（中端机型）

### M2 · iOS 内测（第 7–10 月）

**目标**：攻克 NE，达到可提交审核品质；交互直接继承 M1 定型结果。

- 交付：iOS App + Packet Tunnel Provider
  - 核心复用（`aegis-tun` apple 模块，staticlib + cbindgen）
  - M1 的移动 UX 迁移（iOS 版信息架构 + 向导 + 诊断）
  - App ↔ NE：App Group + 本地 API；凭据 Keychain 化
- **验收门**：
  - [ ] NE 常驻 < 40MB、24h 后台不重启（真机矩阵：新旧机型各 2 台）
  - [ ] 开启到可用 < 2s；连续使用 1h 额外耗电 < 5%
  - [ ] TestFlight 300 人，崩溃率 < 1%

### M3 · 1.0 双端正式发布（第 11–12 月）

- 交付：
  - **Android**：GitHub Releases + Google Play 全球同步（不含中国大陆区）
  - **iOS**：全球 App Store 上架（不含中国大陆区）+ TestFlight 常态化
  - 双端同版本同功能对齐：签名订阅、Hysteria2/TUIC、流媒体解锁检测、smart 组
  - 桌面 CLI（macOS/Windows/Linux，开发与重度用户载体）
- **验收门**：1.0 后 30 天内：双端评分 ≥ 4.5；诊断建议采纳率 ≥ 40%；零 P0 安全事件。

### 1.x / 2.0 方向（第 13 月起）

- 桌面 GUI（若用户需求成立：M1 公测人群向桌面迁移的信号）
- 个人 Mesh（WireGuard，家庭共享）→ 云端 E2E 加密同步（Pro）
- 链式代理 / 多跳

## 2. 风险清单

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| iOS NE 内存超标被系统杀 | 中 | 致命 | M0 就建立内存预算分解与压测门；连接上限/缓存 LRU 兜底 |
| App Store VPN 审核被拒（5.4） | 中 | 高 | 材料完备；同类先例（Surge/Stash）申诉路径；TestFlight 先行验证 |
| **Android 厂商杀后台**（MIUI/EMUI 等激进省电） | 高 | 中 | 前台服务 + 引导用户加白名单；Doze 下的探活降频策略；真机矩阵覆盖国产 ROM |
| **Android 生态碎片**（VpnService 各版本差异） | 中 | 中 | M1 真机矩阵（≥ 6 机型，Android 10–16）进验收门 |
| 移动 UI 工期（双端串行）超期 | 中 | 高 | UX 在 Android 一次定型、iOS 只做平台化适配；uni-FFI/cbindgen 边界 M0 冻结 |
| 协议矩阵维护跟不上生态 | 高 | 中 | 协议 crate 化隔离 + 社区贡献；只承诺 P0 稳定接口 |
| sing-box/Clash 导入兼容长尾 | 高 | 低 | 导入失败给 diff 级报告；不阻塞主流程 |
| 桌面开源版被闭源商用 | 低 | 中 | 核心 GPL-3.0 |
| 法律与合规（发行地区） | 低 | 高 | 工具中立、不内置资源、不进中国区 |

## 3. 开放问题（需拍板）

1. Android 收费形态：Play 买断同 iOS（$4.99）+ GitHub Releases 侧载是否免费？（建议：侧载同样收费或功能受限，避免分发渠道互相拆台）
2. iOS/macOS 首发是否同时做 MAS 版（沙盒限制 NE 能力，建议首发不做）——随移动优先降级为 1.x 再议
3. smart 组打分参数初始值（M0 末离线回放定参）
4. 诊断报告脱敏上报粒度（原则已定 opt-in）