//! # aegis-observe
//!
//! 可观测性（PRD F5 / 架构 L1）。
//!
//! 规划模块：
//! - `sink/`：`EventSink` trait——router/dns 等通过它单向推送事件（本 crate 不依赖任何上层）
//! - `conntable/`：实时连接表（slab，上限可配：桌面 10k / iOS 5k，常驻 < 8MB）
//! - `store/`：SQLite 单库（凭据永不入库，只存 Keychain 引用 ID）：
//!   - `traffic_daily`（域名/节点/规则三维聚合，90 天滚动）
//!   - `rtt_history`（7 天明细 + 降采样 90 天）
//!   - `diag_reports` / `suggestions`
//! - `metrics/`：延迟 EWMA、失败率
//!
//! 硬指标：1 万并发连接下 UI 刷新（经 aegis-api WS）延迟 < 500ms。
