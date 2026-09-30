//! # aegis-outbound
//!
//! 出站协议栈（PRD F1 / 架构 L1）。
//!
//! 统一抽象：
//! ```text
//! Connector: async fn connect(target, creds) -> ProxyStream
//! ```
//!
//! 规划模块（每协议一个，互不依赖；P0：ss2022/trojan/vless/wg/http/socks，P1：hy2/tuic/ssh）：
//! - `ss2022/`：Shadowsocks-2022（blake3 AEAD，抗重放）
//! - `trojan/`
//! - `vless/`：含 REALITY（无域名/证书，抗主动探测）
//! - `wg/`：WireGuard（Mesh 地基）
//! - `hy2/`、`tuic/`：QUIC 系（共享 quinn 传输层）
//! - `http/`、`socks/`：基础出站与级联
//! - `chain/`（P2）：链式代理
//!
//! 验收：每协议与 sing-box 双向互通测试进 CI（tests/interop）。
