//! # aegis-router
//!
//! 连接编排层（PRD F3 / 架构 L2）——核心引擎的心脏。
//!
//! 规划模块：
//! - `sniffer/`：首包嗅探（SNI / HTTP host / QUIC SNI），预算 3KB / 3 包
//! - `group/`：策略组 select / url-test / fallback / load-balance / smart
//!   （smart 打分：`ewma_rtt × (1 + 5×fail_rate) × burst_penalty`，参数写入诊断报告可解释）
//! - `prober/`：探活调度器——TCP 握手 RTT（高频）+ HTTP 首字节（低频）双探针；
//!   连续 3 次失败摘除，回融探活退避 30s/60s/120s，恢复需连续 2 次成功
//! - `session/`：连接生命周期、连接池与 mux 复用
//!
//! 事件流向：router 通过 aegis-observe 的 `EventSink` 单向推送（observe 不得反向依赖 router）。
//!
//! 硬指标：单节点故障 → 组内自动切换 < 30s 且用户无感（故障注入测试，M0 验收门）。
