//! Shadowsocks 2022（SIP022）TCP 出站。
//!
//! 帧结构（请求方向）：
//! ```text
//! salt(16/32) || AEAD[ type=0x00 | timestamp(8) | length(2) ]          ← 计数 0
//!            || AEAD[ address | padding-len(2) | padding ]              ← 计数 1（length 字节）
//!            || AEAD[ chunk-len(2) ] AEAD[ payload ≤ 0xFFFF ] …        ← 每个 AEAD 操作计数 +1
//! ```
//! 响应方向（§3.1.2）：salt → 固定头 `type=0x01 | timestamp | request-salt(16/32) | length`
//! → 首个 payload 块（length 字段即其长度，响应无 padding）→ length 块/payload 块交替。
//! 客户端 MUST 校验 request-salt 与请求盐一致。0 长度块 = 流结束标记。
//!
//! 子密钥：`blake3-derive-key("shadowsocks 2022 session subkey", identity_key || salt)`，
//! 上下行各自的 salt 派生各自的子密钥。AEAD nonce = 12 字节小端计数（§2.4）。
//!
//! 时间戳防重放由服务器校验（±30s）；客户端只负责按当前时间写入。
//!
//! M0 范围：TCP（CONNECT 型）流。UDP（会话式）随 UDP 转发批次。

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::{Endpoint, OutboundError};

/// 单个明文块上限（SIP022）
pub const MAX_CHUNK: usize = 0xFFFF;

/// SS2022 加密方法（决定密钥/盐长度）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ss2022Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20,
}

impl Ss2022Method {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "2022-blake3-aes-128-gcm" => Ok(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(Self::Aes256Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::Chacha20),
            other => Err(format!(
                "未知 shadowsocks-2022 方法 {other}（支持 2022-blake3-aes-128-gcm / \
                 2022-blake3-aes-256-gcm / 2022-blake3-chacha20-poly1305）"
            )),
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            _ => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }
}

impl std::fmt::Display for Ss2022Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20 => "chacha20",
        })
    }
}

/// AEAD 实例（枚举而非 trait object：`aead::Aead` 带 `Sized` 与泛型参数，
/// 不适合 dyn；枚举也免一次虚表跳转）。装箱：内联 AEAD 状态近 1KB，
/// 不装箱会让流结构体膨胀（clippy large_enum_variant）。
enum AeadBox {
    A128(Box<aes_gcm::Aes128Gcm>),
    A256(Box<aes_gcm::Aes256Gcm>),
    C20(Box<chacha20poly1305::ChaCha20Poly1305>),
}

impl AeadBox {
    fn new(method: Ss2022Method, key: &[u8]) -> Self {
        // 密钥长度在 decode_key 时已校验；这里防御性处理
        match method {
            Ss2022Method::Aes128Gcm => Self::A128(Box::new(
                aes_gcm::Aes128Gcm::new_from_slice(key).expect("密钥长度 16"),
            )),
            Ss2022Method::Aes256Gcm => Self::A256(Box::new(
                aes_gcm::Aes256Gcm::new_from_slice(key).expect("密钥长度 32"),
            )),
            Ss2022Method::Chacha20 => Self::C20(Box::new(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("密钥长度 32"),
            )),
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], pt: &[u8]) -> Vec<u8> {
        let n = Nonce12::from_slice(nonce);
        match self {
            Self::A128(a) => a.encrypt(n, pt),
            Self::A256(a) => a.encrypt(n, pt),
            Self::C20(a) => a.encrypt(n, pt),
        }
        .expect("AEAD 加密（Vec 输出）不会失败")
    }

    fn decrypt(&self, nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>, ()> {
        let n = Nonce12::from_slice(nonce);
        match self {
            Self::A128(a) => a.decrypt(n, ct),
            Self::A256(a) => a.decrypt(n, ct),
            Self::C20(a) => a.decrypt(n, ct),
        }
        .map_err(|_| ())
    }
}

type Nonce12 = GenericArray<u8, aes_gcm::aead::consts::U12>;

fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

/// blake3 子密钥派生（SIP022 §2.4：context "shadowsocks 2022 session subkey"，
/// 输入 identity_key || salt）。
fn derive_subkey(method: Ss2022Method, key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
    hasher.update(key);
    hasher.update(salt);
    let mut subkey = vec![0u8; method.key_len()];
    hasher.finalize_xof().fill(&mut subkey);
    subkey
}

/// 解码 base64 主密钥并校验长度（方法决定长度，错配是配置错误）。
pub fn decode_key(method: Ss2022Method, b64: &str) -> Result<Vec<u8>, String> {
    let key = B64
        .decode(b64.trim())
        .map_err(|e| format!("密钥 base64 解码失败: {e}"))?;
    if key.len() != method.key_len() {
        return Err(format!(
            "密钥 {} 字节，{} 需要 {} 字节",
            key.len(),
            method,
            method.key_len()
        ));
    }
    Ok(key)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("系统时间早于 1970")
        .as_secs()
}

/// 目标地址（SOCKS5 地址格式：atyp + addr + port）。trojan 同用此格式。
pub(crate) fn encode_addr(target: &Endpoint) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 255 + 2);
    match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v.push(0x01);
            v.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            v.push(0x04);
            v.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            v.push(0x03);
            v.push(
                u8::try_from(target.host.len()).expect("目标域名超过 255 字节（SIP022 地址上限）"),
            );
            v.extend_from_slice(target.host.as_bytes());
        }
    }
    v.extend_from_slice(&target.port.to_be_bytes());
    v
}

fn bad(reason: &str) -> OutboundError {
    OutboundError::Handshake {
        proto: "ss2022",
        reason: reason.into(),
    }
}

fn invalid_data(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// 经 SS2022 代理连接 `target`：完成 TCP 连接 + 请求头（盐 + 固定头 + 地址块），
/// 返回加密流。响应头（服务器盐 + 固定头）在读路径惰性处理。
pub async fn connect(
    proxy: &Endpoint,
    method: Ss2022Method,
    key: &[u8],
    target: &Endpoint,
) -> Result<Ss2022Stream, OutboundError> {
    if key.len() != method.key_len() {
        return Err(bad(&format!(
            "密钥 {} 字节，{} 需要 {} 字节",
            key.len(),
            method,
            method.key_len()
        )));
    }
    let mut socket = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(OutboundError::Connect)?;

    // 请求盐 + 上行子密钥
    let mut salt = vec![0u8; method.salt_len()];
    rand::thread_rng().fill_bytes(&mut salt);
    let up_aead = AeadBox::new(method, &derive_subkey(method, key, &salt));

    // 固定头：type=0x00（流式请求）| timestamp | 变长头长度
    // 变长头 = 地址 | padding 长度 | padding。SIP022 规定 initial payload 与
    // padding 至少有一样——地址块先行、无 initial payload 时必须带 padding
    //（否则服务器 MUST 拒绝）。M0 固定 16 字节随机 padding。
    let padding = 16usize;
    let mut block = encode_addr(target);
    block.extend_from_slice(&(padding as u16).to_be_bytes());
    let pad_at = block.len();
    block.resize(pad_at + padding, 0);
    rand::thread_rng().fill_bytes(&mut block[pad_at..]);
    let mut fixed = Vec::with_capacity(11 + padding);
    fixed.push(0x00);
    fixed.extend_from_slice(&unix_now().to_be_bytes());
    fixed.extend_from_slice(&(block.len() as u16).to_be_bytes());

    let mut hello = salt.clone();
    hello.extend_from_slice(&up_aead.encrypt(&nonce(0), &fixed));
    hello.extend_from_slice(&up_aead.encrypt(&nonce(1), &block));
    tokio::io::AsyncWriteExt::write_all(&mut socket, &hello).await?;

    Ok(Ss2022Stream {
        socket,
        method,
        identity_key: key.to_vec(),
        up_aead,
        up_nonce: 2,
        down_aead: None,
        down_nonce: 0,
        down_stage: DownStage::SaltFixed,
        request_salt: salt,
        cipher_in: Vec::new(),
        plain: Vec::new(),
        pending_out: Vec::new(),
        out_pos: 0,
        eof: false,
        shutdown_sent: false,
    })
}

enum DownStage {
    /// 等待响应盐 + 固定头（type=1 | ts | request salt | 首块长度）
    SaltFixed,
    /// 等待块长（2 字节）
    ChunkLen,
    /// 等待数据块
    Chunk(usize),
    /// 读到 0 长度块（流结束标记）或对端关闭
    Done,
}

/// SS2022 加密流：上行在 `poll_write` 里分块加密，下行状态机在 `poll_read`
/// 里解密——两个方向各自的盐、子密钥、nonce 计数互不影响。
pub struct Ss2022Stream {
    socket: TcpStream,
    method: Ss2022Method,
    identity_key: Vec<u8>,
    // 上行
    up_aead: AeadBox,
    up_nonce: u64,
    // 下行（读到服务器盐后建立）
    down_aead: Option<AeadBox>,
    down_nonce: u64,
    down_stage: DownStage,
    // 本端请求盐：SIP022 规定客户端 MUST 校验响应头中的 request salt 与之一致
    request_salt: Vec<u8>,
    // 下行密文缓冲与明文积压
    cipher_in: Vec<u8>,
    plain: Vec<u8>,
    // 上行待写缓冲（poll_write 帧化后尽力写，写不完由 poll_flush 续传）
    pending_out: Vec<u8>,
    out_pos: usize,
    eof: bool,
    shutdown_sent: bool,
}

impl Ss2022Stream {
    fn encrypt_up(&mut self, pt: &[u8]) -> Vec<u8> {
        let ct = self.up_aead.encrypt(&nonce(self.up_nonce), pt);
        self.up_nonce += 1;
        ct
    }

    fn decrypt_down(&mut self, ct: &[u8]) -> io::Result<Vec<u8>> {
        let Some(aead) = self.down_aead.as_ref() else {
            return Err(invalid_data("下行 AEAD 未初始化（内部状态错误）"));
        };
        let pt = aead.decrypt(&nonce(self.down_nonce), ct).map_err(|_| {
            invalid_data("ss2022 下行解密失败（认证标签不匹配，连接被篡改或密钥/盐不匹配）")
        })?;
        self.down_nonce += 1;
        Ok(pt)
    }

    /// 下行状态机：能推进多少推进多少。返回是否推进了（调用方决定是否继续）。
    fn try_parse(&mut self) -> io::Result<bool> {
        let mut progressed = false;
        loop {
            match self.down_stage {
                DownStage::SaltFixed => {
                    // 响应盐 + 固定头密文：明文 = type1 + ts8 + request_salt(salt_len) + len2，
                    // 加 16 字节认证标签 = salt_len + 27 + salt_len + 16
                    let salt_len = self.method.salt_len();
                    let need = 2 * salt_len + 27;
                    if self.cipher_in.len() < need {
                        return Ok(progressed);
                    }
                    let data: Vec<u8> = self.cipher_in.drain(..need).collect();
                    let salt = data[..salt_len].to_vec();
                    self.down_aead = Some(AeadBox::new(
                        self.method,
                        &derive_subkey(self.method, &self.identity_key, &salt),
                    ));
                    let hdr = self.decrypt_down(&data[salt_len..])?;
                    if hdr[0] != 0x01 {
                        return Err(invalid_data(&format!(
                            "ss2022 响应类型 0x{:02x}（应为 0x01）",
                            hdr[0]
                        )));
                    }
                    // SIP022：客户端 MUST 校验响应头中的 request salt 与请求盐一致
                    let req_salt = &hdr[9..9 + salt_len];
                    if req_salt != self.request_salt.as_slice() {
                        return Err(invalid_data(
                            "ss2022 响应头 request salt 与请求盐不匹配（会话被映射到错误请求）",
                        ));
                    }
                    // 响应头长度字段 = 紧随其后的首个 payload 块长度（响应无 padding）
                    let len =
                        u16::from_be_bytes(hdr[9 + salt_len..11 + salt_len].try_into().unwrap())
                            as usize;
                    self.down_stage = if len > 0 {
                        DownStage::Chunk(len)
                    } else {
                        DownStage::ChunkLen
                    };
                    progressed = true;
                }
                DownStage::ChunkLen => {
                    if self.cipher_in.len() < 18 {
                        return Ok(progressed);
                    }
                    let ct: Vec<u8> = self.cipher_in.drain(..18).collect();
                    let pt = self.decrypt_down(&ct)?;
                    let len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
                    if len == 0 {
                        // 0 长度块 = 流结束标记（SIP022）
                        self.down_stage = DownStage::Done;
                        self.eof = true;
                        return Ok(true);
                    }
                    self.down_stage = DownStage::Chunk(len);
                    progressed = true;
                }
                DownStage::Chunk(len) => {
                    if self.cipher_in.len() < len + 16 {
                        return Ok(progressed);
                    }
                    let ct: Vec<u8> = self.cipher_in.drain(..len + 16).collect();
                    let pt = self.decrypt_down(&ct)?;
                    self.plain.extend_from_slice(&pt);
                    self.down_stage = DownStage::ChunkLen;
                    return Ok(true);
                }
                DownStage::Done => return Ok(progressed),
            }
        }
    }

    /// 把 pending_out 全部写出（Pending 时已注册 waker）。
    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.pending_out.len() {
            let n = ready!(
                Pin::new(&mut self.socket).poll_write(cx, &self.pending_out[self.out_pos..])
            )?;
            self.out_pos += n;
        }
        self.pending_out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Ss2022Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1) 明文积压先出队
            if !this.plain.is_empty() {
                let n = buf.remaining().min(this.plain.len());
                buf.put_slice(&this.plain[..n]);
                this.plain.drain(..n);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(())); // 流结束
            }
            // 2) 推进下行状态机
            if this.try_parse()? {
                continue; // 有推进（可能产出明文，也可能只是消费了头部）
            }
            // 3) 状态机等更多密文：从 TCP 读
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.socket).poll_read(cx, &mut rb)? {
                Poll::Ready(()) => {
                    if rb.filled().is_empty() {
                        // 对端在块边界外断开：按 EOF 处理（与主流实现一致，不硬错）
                        this.eof = true;
                    } else {
                        this.cipher_in.extend_from_slice(rb.filled());
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Ss2022Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 积压未清前不接受新数据（背压：帧化缓冲不无限膨胀）
        if this.out_pos < this.pending_out.len() {
            ready!(this.poll_flush_out(cx))?;
        }
        // 帧化：每个 ≤0xFFFF 的块 = AEAD(len) + AEAD(payload)，nonce 各 +1
        for chunk in buf.chunks(MAX_CHUNK) {
            let len_ct = this.encrypt_up(&(chunk.len() as u16).to_be_bytes());
            let data_ct = this.encrypt_up(chunk);
            this.pending_out.extend_from_slice(&len_ct);
            this.pending_out.extend_from_slice(&data_ct);
        }
        // 尽力写出；写不完由 poll_flush 续传
        if let Err(e) = ready!(this.poll_flush_out(cx)) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_out(cx))?;
        Pin::new(&mut this.socket).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // SIP022 EOF 标记：0 长度块
        if !this.shutdown_sent {
            let ct = this.encrypt_up(&0u16.to_be_bytes());
            this.pending_out.extend_from_slice(&ct);
            this.shutdown_sent = true;
        }
        ready!(this.poll_flush_out(cx))?;
        Pin::new(&mut this.socket).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 测试用 SS2022 服务器：解请求头 + 断言目标地址 + 回显（重新加密下行）。
    /// 与客户端共用帧化原语（encrypt/decrypt/derive），保证语义对齐；
    /// 与 sing-box 的互通测试进 tests/interop（docs/02 §8）后才算协议级验收。
    async fn spawn_server(
        key: &[u8],
        method: Ss2022Method,
    ) -> std::io::Result<(
        std::net::SocketAddr,
        tokio::task::JoinHandle<std::io::Result<()>>,
    )> {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let key = key.to_vec();
        let task = tokio::spawn(async move {
            let (mut c, _) = l.accept().await?;
            // 请求盐 + 固定头
            let mut salt = vec![0u8; method.salt_len()];
            c.read_exact(&mut salt).await?;
            let up = AeadBox::new(method, &derive_subkey(method, &key, &salt));
            // 固定头密文 = (type1 + ts8 + len2) + 16 字节认证标签
            let mut ct = vec![0u8; 27];
            c.read_exact(&mut ct).await?;
            let hdr = up
                .decrypt(&nonce(0), &ct)
                .map_err(|_| invalid_data("固定头解密失败"))?;
            assert_eq!(hdr[0], 0x00, "请求类型应为 0x00");
            assert!(
                unix_now().abs_sub(u64::from_be_bytes(hdr[1..9].try_into().unwrap())) <= 30,
                "时间戳偏移超 30s"
            );
            let var_len = u16::from_be_bytes([hdr[9], hdr[10]]) as usize;
            // 地址块（address || padding 长度=0）
            let mut ct = vec![0u8; var_len + 16];
            c.read_exact(&mut ct).await?;
            let block = up
                .decrypt(&nonce(1), &ct)
                .map_err(|_| invalid_data("地址块解密失败"))?;
            let (addr_part, padding_len_bytes) = block.split_at(15);
            assert_eq!(addr_part, b"\x03\x0bexample.com\x01\xbb");
            let padding_len =
                u16::from_be_bytes(padding_len_bytes[..2].try_into().unwrap()) as usize;
            // SIP022：initial payload 与 padding 至少有一样
            assert!(
                padding_len > 0,
                "地址块必须带 padding（无 initial payload 时）"
            );
            assert_eq!(padding_len, padding_len_bytes.len() - 2);

            // 响应头 = type=0x01 | ts | 请求盐 | 首块长度（SIP022 §3.1.2）。
            // 规范要求响应头总与 payload 同发（无 padding），故先收首个上游块
            // 再一次性写出：盐 + 头块 + 首个 payload 块。
            let mut up_nonce: u64 = 2;
            let mut ct = vec![0u8; 18];
            c.read_exact(&mut ct).await?;
            let pt = up
                .decrypt(&nonce(up_nonce), &ct)
                .map_err(|_| invalid_data("块长解密失败"))?;
            up_nonce += 1;
            let len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
            if len == 0 {
                return Ok(()); // 客户端在收到响应前就关了（无数据可回）
            }
            let mut ct = vec![0u8; len + 16];
            c.read_exact(&mut ct).await?;
            let first = up
                .decrypt(&nonce(up_nonce), &ct)
                .map_err(|_| invalid_data("块解密失败"))?;
            up_nonce += 1;

            let mut rsalt = vec![0u8; method.salt_len()];
            rand::thread_rng().fill_bytes(&mut rsalt);
            let down = AeadBox::new(method, &derive_subkey(method, &key, &rsalt));
            let mut rfixed = vec![0x01];
            rfixed.extend_from_slice(&unix_now().to_be_bytes());
            rfixed.extend_from_slice(&salt); // 请求盐回带
            rfixed.extend_from_slice(&(first.len() as u16).to_be_bytes());
            let mut hello = rsalt.clone();
            hello.extend_from_slice(&down.encrypt(&nonce(0), &rfixed));
            hello.extend_from_slice(&down.encrypt(&nonce(1), &first));
            c.write_all(&hello).await?;

            // 回显循环：上游块 → 明文 → 下游块（下行 nonce 逐 AEAD 操作递增）
            let mut down_nonce: u64 = 2;
            loop {
                let mut ct = vec![0u8; 18];
                c.read_exact(&mut ct).await?;
                let pt = up
                    .decrypt(&nonce(up_nonce), &ct)
                    .map_err(|_| invalid_data("块长解密失败"))?;
                up_nonce += 1;
                let len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
                if len == 0 {
                    return Ok(()); // 客户端 EOF
                }
                let mut ct = vec![0u8; len + 16];
                c.read_exact(&mut ct).await?;
                let pt = up
                    .decrypt(&nonce(up_nonce), &ct)
                    .map_err(|_| invalid_data("块解密失败"))?;
                up_nonce += 1;
                let mut out = down.encrypt(&nonce(down_nonce), &(len as u16).to_be_bytes());
                down_nonce += 1;
                out.extend_from_slice(&down.encrypt(&nonce(down_nonce), &pt));
                down_nonce += 1;
                c.write_all(&out).await?;
            }
        });
        Ok((addr, task))
    }

    #[test]
    fn method_parse_and_key_len() {
        assert_eq!(
            Ss2022Method::parse("2022-blake3-aes-128-gcm").unwrap(),
            Ss2022Method::Aes128Gcm
        );
        assert!(Ss2022Method::parse("xx").is_err());
        // 密钥长度校验
        let short = Ss2022Method::Aes128Gcm;
        assert!(decode_key(short, "AAAA").is_err());
        let key16 = B64.encode([7u8; 16]);
        assert_eq!(decode_key(short, &key16).unwrap().len(), 16);
    }

    #[tokio::test]
    async fn roundtrip_all_three_methods() {
        for (method, key_bytes) in [
            (Ss2022Method::Aes128Gcm, [1u8; 16].as_slice()),
            (Ss2022Method::Aes256Gcm, [2u8; 32].as_slice()),
            (Ss2022Method::Chacha20, [3u8; 32].as_slice()),
        ] {
            let key = B64.encode(key_bytes);
            let (addr, server) = spawn_server(key_bytes, method).await.unwrap();
            let out = crate::Outbound::Ss2022 {
                proxy: Endpoint::new("127.0.0.1", addr.port()),
                method,
                key: decode_key(method, &key).unwrap(),
            };
            let mut s = out
                .connect(&Endpoint::new("example.com", 443))
                .await
                .unwrap();
            // 写超过一个块（0xFFFF）验证分块
            let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
            s.write_all(&big).await.unwrap();
            let mut echoed = vec![0u8; big.len()];
            s.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, big, "{method} 回显不一致");
            // EOF 标记 → 服务器退出
            s.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
        }
    }

    /// u64 绝对差（时间戳偏移断言用）
    trait AbsSub {
        fn abs_sub(self, other: u64) -> u64;
    }
    impl AbsSub for u64 {
        fn abs_sub(self, other: u64) -> u64 {
            self.max(other) - self.min(other)
        }
    }
}
