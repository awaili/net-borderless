//! SOCKS5 出站（RFC 1928 / RFC 1929 用户名密码认证）。

use std::net::IpAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{Auth, Endpoint, OutboundError};

const NO_AUTH: u8 = 0x00;
const USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// 经由 SOCKS5 代理连接 `target`，成功后返回已就绪的双向流。
pub async fn connect(
    proxy: &Endpoint,
    auth: Option<&Auth>,
    target: &Endpoint,
) -> Result<TcpStream, OutboundError> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(OutboundError::Connect)?;

    // 1) 方法协商
    let greet: &[u8] = if auth.is_some() {
        &[0x05, 0x02, NO_AUTH, USER_PASS]
    } else {
        &[0x05, 0x01, NO_AUTH]
    };
    stream.write_all(greet).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method[0] != 0x05 {
        return Err(bad("版本号不是 5"));
    }
    match method[1] {
        NO_AUTH => {}
        USER_PASS => {
            let auth = auth.ok_or_else(|| bad("服务器要求认证但未配置凭据"))?;
            let mut req = Vec::with_capacity(3 + auth.user.len() + auth.pass.len());
            req.push(0x01);
            req.push(auth.user.len() as u8);
            req.extend_from_slice(auth.user.as_bytes());
            req.push(auth.pass.len() as u8);
            req.extend_from_slice(auth.pass.as_bytes());
            stream.write_all(&req).await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[1] != 0x00 {
                return Err(bad("用户名/密码认证被拒绝"));
            }
        }
        other => return Err(bad(&format!("服务器选择了不支持的认证方式 0x{other:02x}"))),
    }

    // 2) CONNECT 请求
    let mut req = Vec::with_capacity(7 + target.host.len());
    req.extend_from_slice(&[0x05, CMD_CONNECT, 0x00]);
    match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            req.push(ATYP_V4);
            req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            req.push(ATYP_V6);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            if target.host.len() > 255 {
                return Err(bad("域名超过 255 字节"));
            }
            req.push(ATYP_DOMAIN);
            req.push(target.host.len() as u8);
            req.extend_from_slice(target.host.as_bytes());
        }
    }
    req.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&req).await?;

    // 3) 应答：跳过绑定地址
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(bad("应答版本号不是 5"));
    }
    if hdr[1] != 0x00 {
        return Err(bad(&format!("代理拒绝连接（状态码 0x{:02x}）", hdr[1])));
    }
    match hdr[3] {
        ATYP_V4 => skip(&mut stream, 4 + 2).await?,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            skip(&mut stream, len[0] as usize + 2).await?;
        }
        ATYP_V6 => skip(&mut stream, 16 + 2).await?,
        other => return Err(bad(&format!("未知地址类型 0x{other:02x}"))),
    }
    Ok(stream)
}

async fn skip(stream: &mut TcpStream, n: usize) -> Result<(), OutboundError> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(())
}

fn bad(reason: &str) -> OutboundError {
    OutboundError::Handshake {
        proto: "socks5",
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Outbound;

    /// 本地假 SOCKS5 代理：完成握手后把数据原样回显。
    async fn fake_proxy() -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 2];
            c.read_exact(&mut b).await.unwrap(); // ver + nmethods
            let mut methods = vec![0u8; b[1] as usize];
            c.read_exact(&mut methods).await.unwrap();
            assert_eq!(b[0], 5);
            assert!(methods.contains(&NO_AUTH));
            c.write_all(&[5, 0]).await.unwrap();

            let mut h = [0u8; 5]; // ver cmd rsv atyp domain-len
            c.read_exact(&mut h).await.unwrap();
            assert_eq!(h[1], CMD_CONNECT);
            let mut rest = vec![0u8; h[4] as usize + 2];
            c.read_exact(&mut rest).await.unwrap();
            let domain = String::from_utf8_lossy(&rest[..h[4] as usize]).into_owned();
            assert_eq!(domain, "example.com");
            assert_eq!(&rest[rest.len() - 2..], &443u16.to_be_bytes());
            c.write_all(&[5, 0, 0, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            let (mut r, mut w) = c.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
        });
        Ok((addr, handle))
    }

    #[tokio::test]
    async fn handshake_then_echo() {
        let (addr, proxy) = fake_proxy().await.unwrap();
        let out = Outbound::Socks5 {
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
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn v4_target_uses_atyp1() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 2];
            c.read_exact(&mut b).await.unwrap();
            let mut m = vec![0u8; b[1] as usize];
            c.read_exact(&mut m).await.unwrap();
            c.write_all(&[5, 0]).await.unwrap();
            // ver cmd rsv atyp + 4 字节 IP + 2 字节端口
            let mut h = [0u8; 10];
            c.read_exact(&mut h).await.unwrap();
            assert_eq!(h[3], ATYP_V4);
            assert_eq!(&h[4..8], &[127, 0, 0, 1]);
            c.write_all(&[5, 0, 0, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let out = Outbound::Socks5 {
            proxy: Endpoint::new("127.0.0.1", addr.port()),
            auth: None,
        };
        out.connect(&Endpoint::new("127.0.0.1", 80)).await.unwrap();
        server.await.unwrap();
    }
}
