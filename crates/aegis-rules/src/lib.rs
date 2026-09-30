//! # aegis-rules
//!
//! 规则引擎（PRD F2 / 架构 L1）。
//!
//! 已实现（M0 第一批）：
//! - 匹配器 [`Matcher`]：DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX /
//!   IP-CIDR（v4+v6 统一）/ GEOIP / PORT（含区间）/ PROTOCOL / PROCESS，
//!   以及嵌套逻辑表达式 AND / OR / NOT（[`Logical`]）
//! - 规则 DSL 解析（[`dsl::parse_rule`]）：
//!   `AND((DOMAIN-SUFFIX,netflix.com), NOT(IP-CIDR,10.0.0.0/8)) -> media`
//! - [`CompiledRules`]：顺序求值 + 每条规则命中计数（喂给 aegis-diag 的学习式建议
//!   与 UI 的规则排序）；兜底 `fallback` 必须由调用方显式传入
//!   （aegis-config 强制 final 必填，未写默认 REJECT 并产生诊断建议）
//!
//! 待办（后续迭代）：
//! - `ruleset/`：远程规则集加载、Ed25519 签名校验、版本与增量更新
//!   （`Matcher::RuleSetRef` 当前是引用桩，由配置层展开后运行期不再出现）
//! - 域名 trie 编译优化（当前为顺序求值；10 万规则集 p99 < 50µs 的验收门
//!   需 trie + criterion 基准驱动，见 docs/02 §8）
//! - fuzz：DSL 解析器与匹配器进 CI
//!
//! 热路径约定：`Matcher::matches` 零堆分配。

pub mod cidr;
pub mod dsl;
pub mod expr;
pub mod matcher;

pub use cidr::IpCidr;
pub use dsl::{parse_rule, ParsedRule};
pub use matcher::{ConnCtx, Logical, Matcher, Protocol};

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// 分流目标：直连 / 拒绝 / 指向策略组（组 id 由 aegis-config 定义并管理）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Direct,
    Reject,
    Group(String),
}

/// 一次规则求值的结果：目标 + 命中的规则下标（`None` = 兜底 final）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub target: Target,
    pub rule_index: Option<usize>,
}

/// 编译后的规则集：加载期构建一次，运行期只读（命中计数除外）。
#[derive(Debug)]
pub struct CompiledRules {
    rules: Vec<CompiledRule>,
    fallback: Target,
}

#[derive(Debug)]
struct CompiledRule {
    condition: Matcher,
    target: Target,
    hits: AtomicU64,
}

impl CompiledRules {
    /// `rules` 按顺序求值，首个命中生效；`fallback` 为显式兜底目标。
    pub fn build(rules: Vec<ParsedRule>, fallback: Target) -> Self {
        Self {
            rules: rules
                .into_iter()
                .map(|r| CompiledRule {
                    condition: r.condition,
                    target: r.target,
                    hits: AtomicU64::new(0),
                })
                .collect(),
            fallback,
        }
    }

    pub fn matches(&self, ctx: &ConnCtx) -> MatchResult {
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.condition.matches(ctx) {
                rule.hits.fetch_add(1, Ordering::Relaxed);
                return MatchResult {
                    target: rule.target.clone(),
                    rule_index: Some(idx),
                };
            }
        }
        MatchResult {
            target: self.fallback.clone(),
            rule_index: None,
        }
    }

    /// 各规则命中计数（喂给 aegis-diag 的学习式建议与 UI 的规则命中排序）。
    pub fn hit_counts(&self) -> Vec<(usize, u64)> {
        self.rules
            .iter()
            .enumerate()
            .map(|(i, r)| (i, r.hits.load(Ordering::Relaxed)))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn fallback(&self) -> &Target {
        &self.fallback
    }
}

/// DSL / 表达式解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// 规则缺少 `-> TARGET`
    MissingTarget,
    /// 目标策略组 id 非法
    InvalidTarget(String),
    UnknownMatcher(String),
    TooFewArgs {
        matcher: &'static str,
        expected: usize,
    },
    TooManyArgs {
        matcher: &'static str,
        expected: usize,
    },
    UnbalancedParen(usize),
    TrailingInput(String),
    /// CIDR / IP 解析失败，`value` 为原始输入
    BadCidr(String),
    BadPort(String),
    BadRegex(String),
    /// 未知协议名（应为 http/tls/quic/dtls/stun）
    BadProtocol(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::MissingTarget => write!(f, "缺少 '-> TARGET' 目标"),
            ParseError::InvalidTarget(t) => write!(f, "非法目标策略组 id: {t:?}"),
            ParseError::UnknownMatcher(m) => write!(f, "未知匹配器: {m}"),
            ParseError::TooFewArgs { matcher, expected } => {
                write!(f, "{matcher} 参数不足，需要 {expected} 个")
            }
            ParseError::TooManyArgs { matcher, expected } => {
                write!(f, "{matcher} 参数过多，应只有 {expected} 个")
            }
            ParseError::UnbalancedParen(pos) => write!(f, "括号不配对（第 {pos} 字符附近）"),
            ParseError::TrailingInput(s) => write!(f, "表达式后有多余内容: {s:?}"),
            ParseError::BadCidr(v) => write!(f, "无法解析 CIDR/IP: {v}"),
            ParseError::BadPort(v) => write!(f, "无法解析端口: {v}"),
            ParseError::BadRegex(v) => write!(f, "无法解析正则: {v}"),
            ParseError::BadProtocol(v) => {
                write!(f, "未知协议: {v}（应为 http/tls/quic/dtls/stun）")
            }
        }
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(lines: &[&str], fallback: Target) -> CompiledRules {
        let parsed = lines
            .iter()
            .map(|l| parse_rule(l).expect("解析失败"))
            .collect();
        CompiledRules::build(parsed, fallback)
    }

    fn ctx(domain: Option<&str>, dst_ip: Option<std::net::IpAddr>) -> ConnCtx<'_> {
        let mut c = ConnCtx::new(dst_ip, 443);
        c.domain = domain;
        c
    }

    #[test]
    fn dsl_matches_and_fallback() {
        let r = rules(
            &[
                "AND((DOMAIN-SUFFIX,netflix.com), NOT(IP-CIDR,10.0.0.0/8)) -> media",
                "GEOIP,CN -> DIRECT",
                "DOMAIN,openai.com -> proxy",
            ],
            Target::Reject,
        );

        // 命中第 0 条 → media
        let m = r.matches(&ctx(Some("www.NetFlix.com"), None));
        assert_eq!(m.target, Target::Group("media".into()));
        assert_eq!(m.rule_index, Some(0));

        // 命中 NOT 分支外的内网 → 第 0 条不中，兜底 REJECT
        let m = r.matches(&ctx(
            Some("www.netflix.com"),
            Some("10.1.2.3".parse().unwrap()),
        ));
        assert_eq!(m.target, Target::Reject);
        assert_eq!(m.rule_index, None);

        // GEOIP 由调用方填入上下文
        let mut c = ctx(None, Some("223.5.5.5".parse().unwrap()));
        c.geoip_country = Some("CN");
        assert_eq!(r.matches(&c).target, Target::Direct);

        // 大小写不敏感的精确域名
        assert_eq!(
            r.matches(&ctx(Some("OPENAI.com"), None)).target,
            Target::Group("proxy".into())
        );
    }

    #[test]
    fn hit_counts_track() {
        let r = rules(&["DOMAIN-SUFFIX,netflix.com -> media"], Target::Reject);
        for _ in 0..3 {
            r.matches(&ctx(Some("netflix.com"), None));
        }
        r.matches(&ctx(Some("example.com"), None));
        assert_eq!(r.hit_counts(), vec![(0, 3)]);
    }

    #[test]
    fn suffix_boundary() {
        let r = rules(&["DOMAIN-SUFFIX,netflix.com -> media"], Target::Reject);
        assert_eq!(
            r.matches(&ctx(Some("netflix.com"), None)).rule_index,
            Some(0)
        );
        assert_eq!(
            r.matches(&ctx(Some("www.netflix.com"), None)).rule_index,
            Some(0)
        );
        // mynetflix.com 不是 netflix.com 的子域
        assert_eq!(
            r.matches(&ctx(Some("mynetflix.com"), None)).rule_index,
            None
        );
    }

    #[test]
    fn port_protocol_process_matchers() {
        let r = rules(
            &[
                "PORT,1024-65535 -> p_high",
                "PROTOCOL,tls -> p_tls",
                "PROCESS,git -> p_git",
            ],
            Target::Reject,
        );

        let mut c = ConnCtx::new(None, 80);
        assert_eq!(r.matches(&c).target, Target::Reject);

        c.dst_port = 8080;
        assert_eq!(r.matches(&c).target, Target::Group("p_high".into()));

        let mut tls = ConnCtx::new(None, 80);
        tls.protocol = Some(Protocol::Tls);
        assert_eq!(r.matches(&tls).target, Target::Group("p_tls".into()));

        let mut proc = ConnCtx::new(None, 80);
        proc.process = Some("Git");
        assert_eq!(r.matches(&proc).target, Target::Group("p_git".into()));
    }

    #[test]
    fn parse_errors() {
        assert!(matches!(
            parse_rule("DOMAIN-SUFFIX,x.com"),
            Err(ParseError::MissingTarget)
        ));
        assert!(matches!(
            parse_rule("WHAT,foo -> DIRECT"),
            Err(ParseError::UnknownMatcher(_))
        ));
        assert!(matches!(
            parse_rule("IP-CIDR,10.0.0.0/33 -> DIRECT"),
            Err(ParseError::BadCidr(_))
        ));
        assert!(matches!(
            parse_rule("DOMAIN-REGEX,[ -> DIRECT"),
            Err(ParseError::BadRegex(_))
        ));
        assert!(matches!(
            parse_rule("AND(DOMAIN,x.com -> DIRECT"),
            Err(ParseError::UnbalancedParen(_))
        ));
        assert!(matches!(
            parse_rule("AND(DOMAIN,x.com)) -> DIRECT"),
            Err(ParseError::TrailingInput(_))
        ));
        assert!(matches!(
            parse_rule("PORT,1-2-3 -> DIRECT"),
            Err(ParseError::BadPort(_))
        ));
        assert!(matches!(
            parse_rule("DOMAIN,a.com,extra -> DIRECT"),
            Err(ParseError::TooManyArgs { .. })
        ));
        assert!(matches!(
            parse_rule("DOMAIN,a.com -> my group"),
            Err(ParseError::InvalidTarget(_))
        ));
    }

    #[test]
    fn v6_cidr_and_keyword() {
        let r = rules(
            &[
                "IP-CIDR6,2001:db8::/32 -> v6",
                "DOMAIN-KEYWORD,google -> g",
                "DOMAIN-REGEX,^api\\.example\\.(com|net)$ -> api",
            ],
            Target::Reject,
        );

        assert_eq!(
            r.matches(&ctx(None, Some("2001:db8::1".parse().unwrap())))
                .target,
            Target::Group("v6".into())
        );
        assert_eq!(
            r.matches(&ctx(Some("accounts.GooGle.com"), None)).target,
            Target::Group("g".into())
        );
        assert_eq!(
            r.matches(&ctx(Some("api.example.net"), None)).target,
            Target::Group("api".into())
        );
    }

    /// 性能冒烟：10 万条后缀规则构建 + 单次匹配（不设硬性断言，正式基准见 docs/02 §8）。
    #[test]
    fn perf_smoke_100k_rules() {
        let parsed: Vec<ParsedRule> = (0..100_000)
            .map(|i| parse_rule(&format!("DOMAIN-SUFFIX,host{i}.example.com -> g{i}")).unwrap())
            .collect();
        let r = CompiledRules::build(parsed, Target::Reject);
        assert_eq!(r.len(), 100_000);

        let ctx = ctx(Some("host99999.example.com"), None);
        let t = std::time::Instant::now();
        let m = r.matches(&ctx);
        let elapsed = t.elapsed();
        assert_eq!(m.rule_index, Some(99_999));
        println!("100k 顺序求值: {elapsed:?}");
    }
}
