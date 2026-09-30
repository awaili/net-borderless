//! Trojan 出站（trojan-gfw 规范）。
//!
//! 请求：`HEX(SHA224(password)) CRLF | CMD=0x01 | ATYP addr port CRLF | payload…`
//! 响应（trojan-gfw 原版）：`ATYP addr port CRLF | payload…`
//!
//! 生态差异：trojan-gfw 服务端回显响应头（= 请求地址块 + CRLF），而
//! xray / sing-box 服务端**不发头**直接透传。客户端采用自适应嗅探：
//! 首读若以「请求地址块 + CRLF」开头则丢弃之，否则按无头模式透传。
//! 以请求地址比对，误判（payload 恰以自身代理目标开头）概率可忽略。
//!
//! 承载：TLS 1.2/1.3（rustls，ring 后端）。默认严格校验证书（webpki 内置根），
//! `skip-cert-verify` 仅应在前端 UI 明确二次确认后开启。
//!
//! M0 范围：TCP CONNECT 流（trojan 的 UDP ASSOCIATE 随 UDP 转发批次）。

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::{Endpoint, OutboundError};

/// TLS 建连参数。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsParams {
    /// SNI（缺省用代理地址本身）
    pub sni: Option<String>,
    /// 跳过证书校验（自签/中间人场景；默认 false）
    pub skip_verify: bool,
}

/// SHA224(password) 小写十六进制（trojan 规范的线上形态——明文密码不出网）。
fn password_hex(password: &str) -> String {
    let d = Sha224::digest(password.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// 跳过证书校验的 Verifier（仅在 skip_verify=true 时挂载）。
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn handshake_err(reason: String) -> OutboundError {
    OutboundError::Handshake {
        proto: "trojan",
        reason,
    }
}

/// SNI / IP 服务器名（IP 字面量时 rustls 要求 ServerName::IpAddress）。
fn server_name(host: &str) -> Result<rustls::pki_types::ServerName<'static>, OutboundError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.into());
    }
    rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| handshake_err(format!("无效服务器名 {host}: {e}")))
}

fn tls_connector(params: &TlsParams) -> Result<tokio_rustls::TlsConnector, OutboundError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| handshake_err(format!("TLS 初始化失败: {e}")))?;
    let config = if params.skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots)
    }
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// 经 Trojan 代理连接 `target`：TCP → TLS → trojan 请求头。
/// 响应头（ATYP addr port CRLF）在读路径惰性消费。
pub async fn connect(
    proxy: &Endpoint,
    password: &str,
    tls: &TlsParams,
    target: &Endpoint,
) -> Result<TrojanStream, OutboundError> {
    let tcp = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(OutboundError::Connect)?;
    let name = server_name(tls.sni.as_deref().unwrap_or(&proxy.host))?;
    let mut stream = tls_connector(tls)?
        .connect(name, tcp)
        .await
        .map_err(|e| handshake_err(format!("TLS 握手失败: {e}")))?;

    let mut req = password_hex(password).into_bytes();
    req.extend_from_slice(b"\r\n\x01");
    let req_addr = crate::ss2022::encode_addr(target);
    req.extend_from_slice(&req_addr);
    req.extend_from_slice(b"\r\n");
    stream.write_all(&req).await.map_err(OutboundError::Io)?;

    Ok(TrojanStream {
        tls: stream,
        buf: Vec::new(),
        hdr_done: false,
        req_addr,
    })
}

/// Trojan 流：自适应消费响应头（见模块文档），其余透传。
pub struct TrojanStream {
    tls: TlsStream<TcpStream>,
    buf: Vec<u8>,
    hdr_done: bool,
    /// 请求地址块（atyp+addr+port）：响应头嗅探的比对基准
    req_addr: Vec<u8>,
}

impl TrojanStream {
    /// 响应头嗅探：返回 Some(消费字节数) = 匹配到响应头。
    fn sniff_response_header(&self) -> Option<usize> {
        let n = self.req_addr.len() + 2; // addr 块 + CRLF
        if self.buf.len() < n {
            return None;
        }
        (self.buf.starts_with(&self.req_addr)
            && self.buf[n - 2] == b'\r'
            && self.buf[n - 1] == b'\n')
            .then_some(n)
    }
}

impl AsyncRead for TrojanStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // 1) 首读：嗅探响应头（trojan-gfw 服务端回显请求地址块 + CRLF；
        //    xray/sing-box 不发头。首字节不同即可立即判为无头模式）
        if !this.hdr_done {
            let need = this.req_addr.len() + 2;
            loop {
                if this.buf.len() >= need {
                    if let Some(n) = this.sniff_response_header() {
                        this.buf.drain(..n);
                    }
                    this.hdr_done = true;
                    break;
                }
                // 首字节已排除响应头：无头模式，透传
                if !this.buf.is_empty() && this.buf[0] != this.req_addr[0] {
                    this.hdr_done = true;
                    break;
                }
                let mut tmp = [0u8; 4096];
                let mut rb = ReadBuf::new(&mut tmp);
                ready!(Pin::new(&mut this.tls).poll_read(cx, &mut rb))?;
                if rb.filled().is_empty() {
                    // 头未收满就断开：已有字节按 payload 交付，EOF 由后续读给出
                    this.hdr_done = true;
                    break;
                }
                this.buf.extend_from_slice(rb.filled());
            }
        }
        // 2) 消费头部时多读的 payload 先出队
        if !this.buf.is_empty() {
            let n = buf.remaining().min(this.buf.len());
            buf.put_slice(&this.buf[..n]);
            this.buf.drain(..n);
            return Poll::Ready(Ok(()));
        }
        // 3) 透传
        Pin::new(&mut this.tls).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrojanStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().tls).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().tls).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().tls).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 测试用 Trojan TLS 服务器：校验请求头（密码哈希 / CMD / 目标），
    /// 回写响应头后回显。返回监听地址与任务句柄。
    async fn spawn_tls_server(
        password: &str,
    ) -> std::io::Result<(
        std::net::SocketAddr,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
                .map_err(|_| std::io::Error::other("私钥格式"))?,
        )
        .map_err(|e| std::io::Error::other(e.to_string()))?;
        cfg.alpn_protocols = Vec::new();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let expected = password_hex(password);
        let task = tokio::spawn(async move {
            let (c, _) = l.accept().await?;
            let mut tls = acceptor.accept(c).await?;
            // 请求头 = 哈希(56) CRLF CMD(1) 地址块 CRLF
            let mut hdr = vec![0u8; 56];
            tls.read_exact(&mut hdr).await?;
            assert_eq!(String::from_utf8(hdr).unwrap(), expected, "密码哈希不匹配");
            let mut crlf = [0u8; 2];
            tls.read_exact(&mut crlf).await?;
            assert_eq!(&crlf, b"\r\n");
            let mut cmd = [0u8; 1];
            tls.read_exact(&mut cmd).await?;
            assert_eq!(cmd[0], 0x01, "CMD 应为 0x01（CONNECT）");
            let mut addr = [0u8; 15]; // \x03\x0b example.com \x01\xbb
            tls.read_exact(&mut addr).await?;
            assert_eq!(&addr, b"\x03\x0bexample.com\x01\xbb");
            let mut crlf = [0u8; 2];
            tls.read_exact(&mut crlf).await?;
            assert_eq!(&crlf, b"\r\n");

            // 响应头 + 回显
            let resp = b"\x03\x0bexample.com\x01\xbb\r\n";
            tls.write_all(resp).await?;
            let mut s = tls;
            let mut b = vec![0u8; 8192];
            loop {
                let n = s.read(&mut b).await?;
                if n == 0 {
                    return Ok(());
                }
                s.write_all(&b[..n]).await?;
            }
        });
        Ok((addr, task))
    }

    #[tokio::test]
    async fn roundtrip_skip_verify() {
        let (addr, server) = spawn_tls_server("passw0rd!").await.unwrap();
        let out = crate::Outbound::Trojan {
            proxy: Endpoint::new("127.0.0.1", addr.port()),
            password: "passw0rd!".into(),
            tls: TlsParams {
                sni: Some("localhost".into()),
                skip_verify: true,
            },
        };
        let mut s = out
            .connect(&Endpoint::new("example.com", 443))
            .await
            .unwrap();
        // 写超过单次 TLS 记录的量，验证透传分块
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        s.write_all(&big).await.unwrap();
        let mut echoed = vec![0u8; big.len()];
        s.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, big, "trojan 回显不一致");
        s.shutdown().await.unwrap();
        server.await.unwrap().unwrap();
    }

    #[test]
    fn sha224_known_vector() {
        // SHA-224("abc") 标准向量
        assert_eq!(
            password_hex("abc"),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }
}
