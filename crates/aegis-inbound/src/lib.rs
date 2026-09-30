//! # aegis-inbound
//!
//! 入站层（架构 L0）：mixed（http + socks5）本地监听的协议解析部分。
//!
//! 已实现（M0 第三批）：
//! - SOCKS5 服务端握手（无认证 / 用户名密码回绝；CONNECT 命令）
//! - HTTP CONNECT 服务端握手
//! - 泛型化 `AsyncRead + AsyncWrite`：真实 TcpStream 与测试 duplex 通用
//!
//! 未实现（后续迭代）：
//! - SOCKS5 用户名密码认证的服务端（本地监听一般不需要）
//! - HTTP 绝对 URI 形式的普通请求代理（P1，目前明确报错而非静默支持一半）
//! - UDP ASSOCIATE（随 UDP 转发一起做）
//!
//! 职责边界：本 crate 只做**协议握手与地址解析**，拿到 `Endpoint` 后交给
//! aegis-router 编排（连接生命周期不在这里）。

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use aegis_outbound::Endpoint;

/// 客户端使用的入站协议（决定成功/失败应答的格式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Socks5,
    HttpConnect,
}

/// 解析完成的一条入站请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRequest {
    pub target: Endpoint,
    pub via: Via,
}

#[derive(Debug, thiserror::Error)]
pub enum InboundError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("不支持的请求: {0}")]
    Unsupported(String),
    #[error("握手数据非法: {0}")]
    BadHandshake(String),
}

/// 从入站流读取一条请求（SOCKS5 或 HTTP CONNECT，按首字节自动判定）。
pub async fn read_request<S>(stream: &mut S) -> Result<InboundRequest, InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut peek = [0u8; 1];
    stream.read_exact(&mut peek).await?;
    match peek[0] {
        0x05 => socks5_read(stream).await,
        b'H' | b'C' | b'G' | b'P' | b'D' | b'O' | b'T' => http_read(stream, peek[0]).await,
        other => Err(InboundError::BadHandshake(format!(
            "无法识别的协议首字节 0x{other:02x}（应为 SOCKS5 的 0x05 或 HTTP 请求方法）"
        ))),
    }
}

/// 通知客户端隧道已建立。
pub async fn reply_ok<S>(stream: &mut S, via: Via) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match via {
        Via::Socks5 => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
        }
        Via::HttpConnect => {
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
        }
    }
}

/// 通知客户端隧道建立失败（在能回复协议语义的范围内尽量回复）。
pub async fn reply_err<S>(stream: &mut S, via: Via) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match via {
        Via::Socks5 => {
            stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
        }
        Via::HttpConnect => stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await,
    }
}

// ── SOCKS5 ──────────────────────────────────────────────

async fn socks5_read<S>(stream: &mut S) -> Result<InboundRequest, InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut b = [0u8; 1];
    stream.read_exact(&mut b).await?; // nmethods
    if b[0] == 0 {
        return Err(InboundError::BadHandshake("nmethods 为 0".into()));
    }
    let mut methods = vec![0u8; b[0] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        // 本地监听不需要认证；直接回绝并指明原因
        stream.write_all(&[0x05, 0xFF]).await?;
        return Err(InboundError::Unsupported(
            "客户端要求认证，本地 mixed 入站不支持（无认证即可连接）".into(),
        ));
    }
    stream.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4]; // ver cmd rsv atyp
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(InboundError::BadHandshake("请求版本号不是 5".into()));
    }
    if req[1] != 0x01 {
        return Err(InboundError::Unsupported(format!(
            "仅支持 CONNECT（收到命令 0x{:02x}；UDP 转发随 M0 后续批次）",
            req[1]
        )));
    }
    let host = match req[3] {
        0x01 => {
            let mut o = [0u8; 4];
            stream.read_exact(&mut o).await?;
            o.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(".")
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).trim().to_ascii_lowercase()
        }
        0x04 => {
            let mut o = [0u8; 16];
            stream.read_exact(&mut o).await?;
            std::net::Ipv6Addr::from(o).to_string()
        }
        other => {
            return Err(InboundError::BadHandshake(format!(
                "未知地址类型 0x{other:02x}"
            )))
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    if host.is_empty() {
        return Err(InboundError::BadHandshake("目标域名为空".into()));
    }
    Ok(InboundRequest {
        target: Endpoint::new(host, u16::from_be_bytes(port)),
        via: Via::Socks5,
    })
}

// ── HTTP CONNECT ────────────────────────────────────────

const MAX_HEADER: usize = 16 * 1024;

async fn http_read<S>(stream: &mut S, first: u8) -> Result<InboundRequest, InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![first];
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEADER {
            return Err(InboundError::BadHandshake("请求头超过 16KB".into()));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(InboundError::BadHandshake(
                "连接在请求头结束前被关闭".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();

    if !method.eq_ignore_ascii_case("connect") {
        return Err(InboundError::Unsupported(format!(
            "仅支持 CONNECT，收到 {method}（普通 HTTP 代理为 P1）"
        )));
    }
    // host[:port]
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| InboundError::BadHandshake(format!("端口非法: {p}")))?,
        ),
        None => (target, 80),
    };
    if host.is_empty() {
        return Err(InboundError::BadHandshake("CONNECT 目标为空".into()));
    }
    Ok(InboundRequest {
        target: Endpoint::new(host.to_ascii_lowercase(), port),
        via: Via::HttpConnect,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn parse(input: &[u8]) -> Result<InboundRequest, InboundError> {
        let (mut client, mut server) = duplex(4096);
        client.write_all(input).await.unwrap();
        // duplex 没有写结束语义，读到数据即可解析——read_request 会在读完
        // 必要字段后返回，无需 EOF
        let req = read_request(&mut server).await;
        req
    }

    #[tokio::test]
    async fn socks5_domain_request() {
        // greeting + CONNECT example.com:443
        let req = parse(&[
            0x05, 0x01, 0x00, // greeting
            0x05, 0x01, 0x00, 0x03, 0x0b, // ver cmd rsv atyp len
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
            0xbb, // 443
        ])
        .await
        .unwrap();
        assert_eq!(req.target, Endpoint::new("example.com", 443));
        assert_eq!(req.via, Via::Socks5);
    }

    #[tokio::test]
    async fn http_connect_request() {
        let req = parse(b"CONNECT Example.COM:8443 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(req.target, Endpoint::new("example.com", 8443));
        assert_eq!(req.via, Via::HttpConnect);
    }

    #[tokio::test]
    async fn plain_get_rejected_loudly() {
        let err = parse(b"GET http://example.com/ HTTP/1.1\r\n\r\n")
            .await
            .unwrap_err();
        assert!(matches!(err, InboundError::Unsupported(_)));
        assert!(err.to_string().contains("仅支持 CONNECT"));
    }

    #[tokio::test]
    async fn reply_roundtrip() {
        let (mut client, mut server) = duplex(4096);
        reply_ok(&mut server, Via::HttpConnect).await.unwrap();
        let mut buf = [0u8; 40];
        let n = client.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));

        reply_err(&mut server, Via::Socks5).await.unwrap();
        client.read_exact(&mut buf[..10]).await.unwrap();
        assert_eq!(buf[1], 0x01); // 一般性失败
    }
}
