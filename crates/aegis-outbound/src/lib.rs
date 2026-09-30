//! # aegis-outbound
//!
//! 出站协议栈（PRD F1 / 架构 L1）。
//!
//! 已实现（M0 第三批）：
//! - [`Outbound::Direct`]：直连
//! - [`Outbound::Socks5`]：SOCKS5 出站（支持用户名/密码认证）
//! - [`Outbound::Http`]：HTTP CONNECT 出站（认证暂未实现，见 TODO）
//! - 全部接口对 `AsyncRead + AsyncWrite` 泛型化（真实 TcpStream 与测试 duplex 通用）
//!
//! 待办（后续迭代）：
//! - ss2022 / trojan / vless+reality / wg（P0 协议矩阵剩余项）
//! - hysteria2 / tuic（P1，quinn QUIC）
//! - HTTP 代理认证（Basic）；链式代理（P2）
//!
//! 互通验收：每协议与 sing-box 双向互通测试进 CI（tests/interop，docs/02 §8）。

pub mod http;
pub mod socks5;

use std::net::IpAddr;

use tokio::net::TcpStream;

/// 连接目标（域名或 IP + 端口）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// 目标主机是否为字面量 IP（影响规则引擎的 dst_ip / domain 两个匹配维度）
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
}

/// 代理认证凭据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub user: String,
    pub pass: String,
}

/// 出站连接器。M0 阶段用枚举分发；协议增多后再评估 vtable/trait object。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Direct,
    Http { proxy: Endpoint, auth: Option<Auth> },
    Socks5 { proxy: Endpoint, auth: Option<Auth> },
}

impl Outbound {
    pub async fn connect(&self, target: &Endpoint) -> Result<TcpStream, OutboundError> {
        match self {
            Outbound::Direct => TcpStream::connect((target.host.as_str(), target.port))
                .await
                .map_err(OutboundError::Connect),
            Outbound::Http { proxy, auth } => http::connect(proxy, auth.as_ref(), target).await,
            Outbound::Socks5 { proxy, auth } => socks5::connect(proxy, auth.as_ref(), target).await,
        }
    }

    /// 人类可读描述（连接报告与日志用）。
    pub fn describe(&self) -> String {
        match self {
            Outbound::Direct => "DIRECT".into(),
            Outbound::Http { proxy, .. } => format!("http://{proxy}"),
            Outbound::Socks5 { proxy, .. } => format!("socks5://{proxy}"),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    #[error("连接失败: {0}")]
    Connect(#[source] std::io::Error),
    #[error("{proto} 握手失败: {reason}")]
    Handshake { proto: &'static str, reason: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
