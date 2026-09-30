//! # aegis-outbound
//!
//! 出站协议栈（PRD F1 / 架构 L1）。
//!
//! 已实现（M0 第五批）：
//! - [`Outbound::Direct`]：直连
//! - [`Outbound::Socks5`]：SOCKS5 出站（支持用户名/密码认证）
//! - [`Outbound::Http`]：HTTP CONNECT 出站（认证暂未实现，见 TODO）
//! - [`Outbound::Ss2022`]：Shadowsocks 2022（SIP022）TCP 出站——
//!   2022-blake3-aes-128-gcm / aes-256 / chacha20 三 AEAD，blake3 子密钥，
//!   时间戳防重放；连接返回**加密流**（[`Transport`]）而非裸 TCP
//! - [`Outbound::Trojan`]：Trojan（TLS 承载 + SHA224 密码哈希；rustls）
//! - 全部接口对 `AsyncRead + AsyncWrite` 泛型化（真实 TcpStream 与测试 duplex 通用）
//!
//! 待办（后续迭代）：
//! - vless+reality / wg（P0 协议矩阵剩余项，同样以 [`Transport`] 返回）
//! - SS2022 UDP（会话式，随 UDP 转发批次）
//! - hysteria2 / tuic（P1，quinn QUIC）
//! - HTTP 代理认证（Basic）；链式代理（P2）
//!
//! 互通验收：每协议与 sing-box 双向互通测试进 CI（tests/interop，docs/02 §8）。

pub mod http;
pub mod socks5;
pub mod ss2022;
pub mod trojan;

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncWrite};
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

/// 出站建立后的双向流抽象：裸 TCP 或协议加密流（ss2022 / 未来的 trojan）。
///
/// `Box<dyn ProxyStream + Send + Unpin>` 让 router 的连接编排对所有协议统一；
/// copy_bidirectional 直接可用（tokio 为 `Box<T: ?Sized + AsyncRead + Unpin>`
/// 实现了 AsyncRead/AsyncWrite）。
pub trait ProxyStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + Unpin + ?Sized> ProxyStream for T {}

/// 已就绪的出站流（类型抹除）。
pub type Transport = Box<dyn ProxyStream + Send + Unpin>;

fn tcp_transport(s: TcpStream) -> Transport {
    Box::new(s)
}

/// 出站连接器。M0 阶段用枚举分发；协议增多后再评估 vtable/trait object。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Direct,
    Http {
        proxy: Endpoint,
        auth: Option<Auth>,
    },
    Socks5 {
        proxy: Endpoint,
        auth: Option<Auth>,
    },
    Ss2022 {
        proxy: Endpoint,
        method: ss2022::Ss2022Method,
        /// 主密钥（base64 解码后的原始字节，长度由方法决定）。
        /// 只在内存中存续：配置文件里只有 key-ref，值运行期注入。
        key: Vec<u8>,
    },
    Trojan {
        proxy: Endpoint,
        /// 明文密码（仅内存：SHA224 哈希后才上 TLS）
        password: String,
        tls: trojan::TlsParams,
    },
}

impl Outbound {
    pub async fn connect(&self, target: &Endpoint) -> Result<Transport, OutboundError> {
        match self {
            Outbound::Direct => TcpStream::connect((target.host.as_str(), target.port))
                .await
                .map(tcp_transport)
                .map_err(OutboundError::Connect),
            Outbound::Http { proxy, auth } => http::connect(proxy, auth.as_ref(), target)
                .await
                .map(|s| Box::new(s) as Transport),
            Outbound::Socks5 { proxy, auth } => socks5::connect(proxy, auth.as_ref(), target)
                .await
                .map(|s| Box::new(s) as Transport),
            Outbound::Ss2022 { proxy, method, key } => ss2022::connect(proxy, *method, key, target)
                .await
                .map(|s| Box::new(s) as Transport),
            Outbound::Trojan {
                proxy,
                password,
                tls,
            } => trojan::connect(proxy, password, tls, target)
                .await
                .map(|s| Box::new(s) as Transport),
        }
    }

    /// 人类可读描述（连接报告与日志用）。
    pub fn describe(&self) -> String {
        match self {
            Outbound::Direct => "DIRECT".into(),
            Outbound::Http { proxy, .. } => format!("http://{proxy}"),
            Outbound::Socks5 { proxy, .. } => format!("socks5://{proxy}"),
            Outbound::Ss2022 { proxy, method, .. } => {
                format!("ss2022({method})://{proxy}")
            }
            Outbound::Trojan { proxy, .. } => format!("trojan://{proxy}"),
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
