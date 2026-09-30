//! # aegis-dns
//!
//! DNS 层（PRD F4 / 架构 L1）：
//! - TUN 模式下的 DNS 应答服务器（直连 / fake-ip 两模式）
//! - 上游：DoH / DoT / DoQ，bootstrap IP 可配置，缓存
//! - Split-DNS：与 aegis-rules 联动（域名命中 PROXY → 解析走代理通道）
//! - 防泄露：所有 DNS 出站必须走显式声明的通道；未配置则拒绝解析并产生诊断警告，
//!   绝不静默回退系统 DNS（验收：dnsleaktest 零泄露）
