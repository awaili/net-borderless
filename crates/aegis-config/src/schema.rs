//! 配置 schema（PRD F7）——serde 类型，与 `presets/example.yaml` 一一对应。
//!
//! 约定：**任何 schema 变更必须同步修改 example.yaml**（docs/05 §5），
//! `lib.rs` 的测试会加载它作为活样例。
//!
//! 设计要点：
//! - `deny_unknown_fields`：配置拼错字段名立即报错，而不是静默忽略
//! - 凭据不落盘：节点密钥/订阅 URL 只存 `key-ref`/`url` 引用，
//!   运行期由平台 Keychain 注入真实值（docs/02 §6）
//! - `final`（兜底目标）缺失是**软警告**（默认 REJECT）而非硬错误，
//!   与 PRD F2"未声明兜底时默认 REJECT 并产生诊断建议"一致

use std::net::IpAddr;
use std::time::Duration;

use serde::de::{Deserializer, Visitor};
use serde::Deserialize;

/// 人性化时长：`"300s"` / `"50ms"` / `"2m"` / `"1h"`；裸数字按秒。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dur(pub Duration);

impl Dur {
    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    pub fn as_millis(&self) -> u64 {
        self.0.as_millis() as u64
    }
}

impl<'de> Deserialize<'de> for Dur {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;
        impl Visitor<'_> for V {
            type Value = Dur;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "时长字符串如 '300s'/'50ms'/'2m'/'1h'，或裸秒数")
            }

            fn visit_u64<E>(self, v: u64) -> Result<Dur, E>
            where
                E: serde::de::Error,
            {
                Ok(Dur(Duration::from_secs(v)))
            }

            fn visit_str<E>(self, v: &str) -> Result<Dur, E>
            where
                E: serde::de::Error,
            {
                let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
                let (num, unit) = v.split_at(split);
                let n: u64 = num
                    .parse()
                    .map_err(|_| E::custom(format!("时长数字非法: {v:?}")))?;
                let d = match unit {
                    "" | "s" => Duration::from_secs(n),
                    "ms" => Duration::from_millis(n),
                    "m" => Duration::from_secs(n * 60),
                    "h" => Duration::from_secs(n * 3600),
                    _ => {
                        return Err(E::custom(format!(
                            "未知时长单位: {unit:?}（支持 s/ms/m/h）"
                        )))
                    }
                };
                Ok(Dur(d))
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// 配置根。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// 当前唯一合法值：1
    pub version: u32,
    #[serde(default)]
    pub inbound: Inbound,
    #[serde(default)]
    pub dns: Dns,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default, rename = "rule-sets")]
    pub rule_sets: Vec<RuleSet>,
    /// 规则行（aegis-rules DSL），按序求值
    #[serde(default)]
    pub rules: Vec<String>,
    /// 兜底目标（`final` 是 Rust 关键字）。缺省 = REJECT + 加载警告。
    #[serde(rename = "final")]
    pub fallback: Option<String>,
    /// 校验产生的软警告（加载期填充，`lib.rs`）
    #[serde(skip)]
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    #[serde(default)]
    pub tun: Tun,
    #[serde(default)]
    pub mixed: Mixed,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Tun {
    #[serde(default)]
    pub enabled: bool,
    /// 把发往 :53 的流量全部劫持到 aegis-dns
    #[serde(default)]
    pub dns_hijack: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mixed {
    #[serde(default)]
    pub enabled: bool,
    /// http+socks5 监听地址，如 `127.0.0.1:7890`
    #[serde(default)]
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    #[serde(default)]
    pub mode: DnsMode,
    /// 上游，如 `doh://1.1.1.1/dns-query`。**未配置时运行期拒绝解析**（PRD F4 防泄露）
    #[serde(default)]
    pub default: Option<String>,
    /// DoH 域名解析的引导 IP
    #[serde(default)]
    pub bootstrap: Option<IpAddr>,
    #[serde(default)]
    pub split: Vec<SplitDns>,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            mode: DnsMode::Direct,
            default: None,
            bootstrap: None,
            split: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    #[default]
    Direct,
    FakeIp,
}

/// 与规则引擎联动的分裂 DNS：命中 `rule` 指向的规则集/域名走 `upstream`。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitDns {
    pub rule: String,
    pub upstream: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub protocol: Protocol,
    pub server: String,
    pub port: u16,
    /// 协议参数：如 shadowsocks-2022 的加密方法（2022-blake3-aes-128-gcm 等）
    #[serde(default)]
    pub method: Option<String>,
    /// TLS SNI（trojan / vless 等 TLS 承载协议；缺省用 server 地址）
    #[serde(default)]
    pub sni: Option<String>,
    /// 跳过证书校验（自签场景；默认 false，UI 需二次确认）
    #[serde(rename = "skip-cert-verify", default)]
    pub skip_cert_verify: bool,
    /// 凭据引用（如 `keychain://nodes/tokyo-01`），真实值运行期由平台 Keychain 注入
    #[serde(rename = "key-ref")]
    pub key_ref: String,
}

/// 出站协议（与 aegis-outbound 的实现矩阵对应，PRD F1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    #[serde(rename = "shadowsocks-2022")]
    Shadowsocks2022,
    Trojan,
    VlessReality,
    Wireguard,
    Hysteria2,
    Tuic,
    Http,
    Socks5,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subscription {
    pub id: String,
    /// 订阅 URL 引用；凭据运行期由 Keychain 注入
    pub url: String,
    /// P1：签名清单（minisign/Ed25519），防篡改
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    #[serde(rename = "type")]
    pub group_type: GroupType,
    /// 节点 id / 其他组 id / DIRECT / REJECT
    pub members: Vec<String>,
    /// url-test 探活间隔，默认 300s
    #[serde(default)]
    pub interval: Option<Dur>,
    /// url-test 容忍度（组内延迟差小于此值不切换，防抖动），默认 50ms
    #[serde(default)]
    pub tolerance: Option<Dur>,
    /// 探活 URL（http:// 即 TCP+HTTP 首字节双探针；https:// 仅 TCP 连接探针，
    /// M0 无 TLS 探活）。缺省 http://www.gstatic.com/generate_204
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupType {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    /// P1（PRD F3 smart 组）
    Smart,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub id: String,
    pub url: String,
    /// P1：Ed25519 签名
    #[serde(default)]
    pub signature: Option<String>,
}

/// 加载期软警告：不阻塞启动，但会出现在诊断与配置 UI 里。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub kind: WarningKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningKind {
    /// 未声明 `final:`，已默认 REJECT（PRD F2）
    DefaultFallback,
    /// 引用了规则集：规则集展开（aegis-config ruleset 模块）尚未实现，该条暂不生效
    RuleSetStub,
    /// 节点未被任何策略组引用
    UnusedNode,
    /// 未配置 DNS 上游：运行期将拒绝解析并发诊断警告（PRD F4 防泄露）
    NoDnsUpstream,
}
