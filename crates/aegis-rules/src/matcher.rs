//! 匹配器与匹配上下文（PRD F2）。

use std::net::IpAddr;

use crate::cidr::IpCidr;
use crate::ParseError;

/// 嗅探得到的协议类型（由 aegis-router 的 sniffer 产出）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Tls,
    Quic,
    Dtls,
    Stun,
}

impl Protocol {
    pub(crate) fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Some(Protocol::Http),
            "tls" => Some(Protocol::Tls),
            "quic" => Some(Protocol::Quic),
            "dtls" => Some(Protocol::Dtls),
            "stun" => Some(Protocol::Stun),
            _ => None,
        }
    }
}

/// 匹配上下文：一次连接在规则求值时刻的已知信息。
///
/// 字段都是"尽力而为"的：嗅探可能失败（`domain`/`protocol` 为 `None`），
/// 进程名仅桌面端可得；GeoIP 国家码由调用方查库后填入——引擎自身不内置地理库，
/// 也不在匹配路径上做任何网络/磁盘操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnCtx<'a> {
    pub dst_ip: Option<IpAddr>,
    pub dst_port: u16,
    /// 已知域名：嗅探到的 SNI / HTTP Host，或 fake-ip 反查结果
    pub domain: Option<&'a str>,
    pub protocol: Option<Protocol>,
    pub process: Option<&'a str>,
    /// GeoIP 国家码（ISO 3166-1 alpha-2）
    pub geoip_country: Option<&'a str>,
}

impl<'a> ConnCtx<'a> {
    pub fn new(dst_ip: Option<IpAddr>, dst_port: u16) -> Self {
        Self {
            dst_ip,
            dst_port,
            domain: None,
            protocol: None,
            process: None,
            geoip_country: None,
        }
    }
}

/// 单个匹配条件。全部匹配器大小写不敏感；域名不区分大小写是 DNS 的天然属性。
#[derive(Debug, Clone)]
pub enum Matcher {
    /// 精确域名
    DomainExact(String),
    /// 域名后缀（含整域）：`netflix.com` 匹配 `netflix.com` 与 `www.netflix.com`，
    /// 不匹配 `mynetflix.com`
    DomainSuffix(String),
    /// 域名包含关键字（编译期小写化，匹配零分配）
    DomainKeyword(String),
    DomainRegex(regex::Regex),
    IpCidr(IpCidr),
    /// 端口区间（含两端）
    Port {
        lo: u16,
        hi: u16,
    },
    Protocol(Protocol),
    Process(String),
    /// GeoIP 国家码（大写归一）
    GeoIp(String),
    Logical(Logical),
    /// 规则集引用桩：由 aegis-config 在加载期展开为具体规则，运行期不再出现。
    /// 展开完成前恒为 false（TODO(M0): aegis-config ruleset 模块）。
    RuleSetRef(String),
}

/// 嵌套逻辑组合。
#[derive(Debug, Clone)]
pub enum Logical {
    And(Vec<Matcher>),
    Or(Vec<Matcher>),
    Not(Box<Matcher>),
}

impl Matcher {
    pub fn matches(&self, ctx: &ConnCtx) -> bool {
        match self {
            Matcher::DomainExact(d) => ctx.domain.is_some_and(|x| x.eq_ignore_ascii_case(d)),
            Matcher::DomainSuffix(s) => ctx.domain.is_some_and(|x| is_domain_suffix(x, s)),
            Matcher::DomainKeyword(k) => {
                ctx.domain.is_some_and(|x| contains_ignore_ascii_case(x, k))
            }
            Matcher::DomainRegex(re) => ctx.domain.is_some_and(|x| re.is_match(x)),
            Matcher::IpCidr(c) => ctx.dst_ip.is_some_and(|ip| c.contains(ip)),
            Matcher::Port { lo, hi } => ctx.dst_port >= *lo && ctx.dst_port <= *hi,
            Matcher::Protocol(p) => ctx.protocol == Some(*p),
            Matcher::Process(p) => ctx.process.is_some_and(|x| x.eq_ignore_ascii_case(p)),
            Matcher::GeoIp(c) => ctx.geoip_country.is_some_and(|x| x.eq_ignore_ascii_case(c)),
            Matcher::Logical(l) => match l {
                Logical::And(ms) => ms.iter().all(|m| m.matches(ctx)),
                Logical::Or(ms) => ms.iter().any(|m| m.matches(ctx)),
                Logical::Not(m) => !m.matches(ctx),
            },
            Matcher::RuleSetRef(_) => false,
        }
    }
}

/// 后缀匹配按 DNS 标签边界判定：`d` 必须等于 `s`，或以 `.s` 结尾。
fn is_domain_suffix(domain: &str, suffix: &str) -> bool {
    let d = domain.as_bytes();
    let s = suffix.as_bytes();
    d.len() >= s.len()
        && d[d.len() - s.len()..].eq_ignore_ascii_case(s)
        && (d.len() == s.len() || d[d.len() - s.len() - 1] == b'.')
}

/// 子串包含（大小写不敏感，零分配线性扫描；关键词较短，足够快）。
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    !n.is_empty()
        && h.len() >= n.len()
        && (0..=h.len() - n.len()).any(|i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// 从 DSL 参数构造匹配器（expr::primary 使用）。
pub(crate) fn from_args(name: &str, args: &[&str]) -> Result<Matcher, ParseError> {
    let single = |matcher: &'static str| -> Result<&str, ParseError> {
        match args {
            [a] if !a.is_empty() => Ok(a),
            [] | [_] => Err(ParseError::TooFewArgs {
                matcher,
                expected: 1,
            }),
            _ => Err(ParseError::TooManyArgs {
                matcher,
                expected: 1,
            }),
        }
    };
    match name {
        "DOMAIN" => Ok(Matcher::DomainExact(single("DOMAIN")?.to_string())),
        "DOMAIN-SUFFIX" => Ok(Matcher::DomainSuffix(single("DOMAIN-SUFFIX")?.to_string())),
        "DOMAIN-KEYWORD" => Ok(Matcher::DomainKeyword(
            single("DOMAIN-KEYWORD")?.to_ascii_lowercase(),
        )),
        "DOMAIN-REGEX" => {
            let a = single("DOMAIN-REGEX")?;
            let re = regex::Regex::new(&format!("(?i){a}"))
                .map_err(|_| ParseError::BadRegex(a.into()))?;
            Ok(Matcher::DomainRegex(re))
        }
        "IP-CIDR" | "IP-CIDR6" => Ok(Matcher::IpCidr(IpCidr::parse(single("IP-CIDR")?)?)),
        "GEOIP" => Ok(Matcher::GeoIp(single("GEOIP")?.to_ascii_uppercase())),
        "PORT" => {
            let a = single("PORT")?;
            let (lo, hi) = match a.split_once('-') {
                Some((lo, hi)) => (parse_port(lo)?, parse_port(hi)?),
                None => {
                    let p = parse_port(a)?;
                    (p, p)
                }
            };
            Ok(Matcher::Port { lo, hi })
        }
        "PROTOCOL" => {
            let a = single("PROTOCOL")?;
            Protocol::from_name(a)
                .map(Matcher::Protocol)
                .ok_or_else(|| ParseError::BadProtocol(a.into()))
        }
        "PROCESS" => Ok(Matcher::Process(single("PROCESS")?.to_string())),
        "RULE-SET" => Ok(Matcher::RuleSetRef(single("RULE-SET")?.to_string())),
        _ => Err(ParseError::UnknownMatcher(name.to_string())),
    }
}

fn parse_port(s: &str) -> Result<u16, ParseError> {
    s.parse::<u16>().map_err(|_| ParseError::BadPort(s.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_boundary() {
        assert!(is_domain_suffix("netflix.com", "netflix.com"));
        assert!(is_domain_suffix("WWW.NETFLIX.COM", "netflix.com"));
        assert!(is_domain_suffix("www.netflix.com", "netflix.com"));
        assert!(!is_domain_suffix("mynetflix.com", "netflix.com"));
        assert!(!is_domain_suffix("netflix.com.evil.org", "netflix.com"));
    }

    #[test]
    fn keyword_case_insensitive() {
        assert!(contains_ignore_ascii_case("accounts.Google.com", "google"));
        assert!(contains_ignore_ascii_case("google.com", "GOOGLE"));
        assert!(!contains_ignore_ascii_case("example.com", "google"));
        assert!(!contains_ignore_ascii_case("gg", "google"));
    }
}
