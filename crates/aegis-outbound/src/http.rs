//! HTTP CONNECT 出站。

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{Auth, Endpoint, OutboundError};

/// 响应头上限，防御恶意/异常代理
const MAX_HEADER: usize = 16 * 1024;

/// 经由 HTTP 代理以 CONNECT 方式连接 `target`。
///
/// TODO(M0): 代理认证（Proxy-Authorization: Basic）——当前配置了凭据会直接报错，
/// 而不是静默忽略（静默会让用户以为认证生效了）。
pub async fn connect(
    proxy: &Endpoint,
    auth: Option<&Auth>,
    target: &Endpoint,
) -> Result<TcpStream, OutboundError> {
    if auth.is_some() {
        return Err(OutboundError::Handshake {
            proto: "http",
            reason: "HTTP 代理认证暂未实现（M0）".into(),
        });
    }
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(OutboundError::Connect)?;

    let req = format!(
        "CONNECT {target} HTTP/1.1\r\n\
         Host: {target}\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes()).await?;

    // 读完整个响应头，确认 2xx
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEADER {
            return Err(bad("响应头超过 16KB"));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(bad("连接在响应完成前被关闭"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or_default();
    // "HTTP/1.1 200 Connection established"
    let ok = status_line
        .split_ascii_whitespace()
        .nth(1)
        .is_some_and(|code| code.starts_with('2'));
    if !ok {
        return Err(bad(&format!("代理返回非 2xx: {status_line}")));
    }
    Ok(stream)
}

fn bad(reason: &str) -> OutboundError {
    OutboundError::Handshake {
        proto: "http",
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Outbound;

    #[tokio::test]
    async fn connect_then_echo() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 256];
            loop {
                let n = c.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf).into_owned();
            assert!(
                head.starts_with("CONNECT example.com:443 HTTP/1.1"),
                "请求行错误: {head}"
            );
            c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let (mut r, mut w) = c.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
        });

        let out = Outbound::Http {
            proxy: Endpoint::new("127.0.0.1", addr.port()),
            auth: None,
        };
        let mut s = out
            .connect(&Endpoint::new("example.com", 443))
            .await
            .unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        // 先关写半边，让假代理的 copy 读到 EOF 退出，再 join（否则死锁）
        s.shutdown().await.unwrap();
        drop(s);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn non_2xx_is_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 256];
            loop {
                let n = c.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });

        let out = Outbound::Http {
            proxy: Endpoint::new("127.0.0.1", addr.port()),
            auth: None,
        };
        let err = match out.connect(&Endpoint::new("example.com", 443)).await {
            Ok(_) => panic!("407 应当报错"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("非 2xx"));
        server.await.unwrap();
    }
}
