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
//! - [`CompiledRules`]：首中语义 + 每条规则命中计数（喂给 aegis-diag 的学习式建议
//!   与 UI 的规则排序）；兜底 `fallback` 必须由调用方显式传入
//!   （aegis-config 强制 final 必填，未写默认 REJECT 并产生诊断建议）
//! - 域名 trie 编译优化（M0 后续批次）：DOMAIN / DOMAIN-SUFFIX 编译期进
//!   [`trie::DomainTrie`]（反转标签），运行期一次查询替代顺序扫描，
//!   结果与顺序扫描按下标取 min——行为与纯顺序扫描严格等价，
//!   10 万规则 p99 < 50µs 验收门（`perf_gate_100k_rules_p99_under_50us` 强制）
//!
//! 待办（后续迭代）：
//! - `ruleset/`：远程规则集加载、Ed25519 签名校验、版本与增量更新
//!   （`Matcher::RuleSetRef` 当前是引用桩，由配置层展开后运行期不再出现）
//! - fuzz：DSL 解析器与匹配器进 CI
//!
//! 热路径约定：`Matcher::matches` 零堆分配。

pub mod cidr;
pub mod dsl;
pub mod expr;
pub mod matcher;
mod trie;

pub use cidr::IpCidr;
pub use dsl::{parse_rule, parse_target, ParsedRule};
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
    /// 按原始下标存放全部规则（target / 命中计数 / 条件）
    rules: Vec<CompiledRule>,
    /// 非 trie 规则的下标表（升序）——顺序扫描只走这里，
    /// 域名规则全进 trie 后 miss 路径不随规则数线性增长
    seq: Vec<usize>,
    /// DOMAIN / DOMAIN-SUFFIX 的编译期 trie（快路径，见模块文档）
    trie: trie::DomainTrie,
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
        let mut trie = trie::DomainTrie::default();
        let mut seq = Vec::new();
        for (idx, r) in rules.iter().enumerate() {
            match &r.condition {
                Matcher::DomainExact(d) => trie.insert_exact(d, idx),
                Matcher::DomainSuffix(s) => trie.insert_suffix(s, idx),
                _ => seq.push(idx),
            }
        }
        Self {
            rules: rules
                .into_iter()
                .map(|r| CompiledRule {
                    condition: r.condition,
                    target: r.target,
                    hits: AtomicU64::new(0),
                })
                .collect(),
            seq,
            trie,
            fallback,
        }
    }

    /// 求值：与纯顺序扫描严格等价。trie 一次查询给出所有命中域名规则的
    /// 最小下标；顺序扫描只看非域名规则，且到该下标即截断。
    pub fn matches(&self, ctx: &ConnCtx) -> MatchResult {
        let mut best: Option<usize> = ctx.domain.and_then(|d| self.trie.lookup(d));
        for &idx in &self.seq {
            if best.is_some_and(|b| idx >= b) {
                break; // 顺序扫描不可能给出更小下标了
            }
            if self.rules[idx].condition.matches(ctx) {
                best = Some(idx);
                break;
            }
        }
        match best {
            Some(idx) => {
                self.rules[idx].hits.fetch_add(1, Ordering::Relaxed);
                MatchResult {
                    target: self.rules[idx].target.clone(),
                    rule_index: Some(idx),
                }
            }
            None => MatchResult {
                target: self.fallback.clone(),
                rule_index: None,
            },
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

    #[test]
    fn trie_and_sequential_equivalence() {
        // trie 规则（DOMAIN/SUFFIX）与顺序规则（KEYWORD/PORT）交错，
        // 首中语义必须与纯顺序扫描严格一致
        let r = rules(
            &[
                "DOMAIN-KEYWORD,evil -> blocked",      // 0
                "DOMAIN-SUFFIX,good.com -> proxy",     // 1
                "PORT,443 -> tls",                     // 2
                "DOMAIN,exact.good.com -> direct",     // 3
                "DOMAIN-SUFFIX,deep.good.com -> deep", // 4
            ],
            Target::Reject,
        );
        // keyword（idx 0）优先于后缀（idx 1）
        assert_eq!(
            r.matches(&ctx(Some("evil.good.com"), None)).rule_index,
            Some(0)
        );
        // 后缀（idx 1）优先于端口（idx 2）与更深后缀（idx 4）
        assert_eq!(
            r.matches(&ctx(Some("sub.deep.good.com"), None)).rule_index,
            Some(1)
        );
        // "exact.good.com" 同时命中后缀（idx 1）与精确（idx 3）→ 首中取 1，
        // 与纯顺序扫描一致（端口规则 idx 2 也命中但被越过）
        assert_eq!(
            r.matches(&ctx(Some("exact.good.com"), None)).rule_index,
            Some(1)
        );
        // 精确规则在前时取胜：单独场景验证
        let r2 = rules(
            &[
                "DOMAIN,exact.good.com -> direct",
                "DOMAIN-SUFFIX,good.com -> proxy",
            ],
            Target::Reject,
        );
        assert_eq!(
            r2.matches(&ctx(Some("exact.good.com"), None)).rule_index,
            Some(0)
        );
        assert_eq!(
            r2.matches(&ctx(Some("other.good.com"), None)).rule_index,
            Some(1)
        );
        // 无域名时端口规则照常（trie 跳过）
        assert_eq!(r.matches(&ctx(None, None)).rule_index, Some(2));
        // 未命中且端口不匹配 → 兜底（ctx helper 固定 443，绕开 PORT 规则）
        let mut c = ConnCtx::new(None, 80);
        c.domain = Some("other.org");
        assert_eq!(r.matches(&c).rule_index, None);
    }

    /// M0 性能门（docs/02 §8）：10 万条域名规则，p99 求值 < 50µs。
    /// trie 快路径使域名查询与规则数无关；50µs 预算宽裕，CI 抖动下也稳定。
    #[test]
    fn perf_gate_100k_rules_p99_under_50us() {
        let parsed: Vec<ParsedRule> = (0..100_000)
            .map(|i| parse_rule(&format!("DOMAIN-SUFFIX,host{i}.example.com -> g{i}")).unwrap())
            .collect();
        let r = CompiledRules::build(parsed, Target::Reject);
        assert_eq!(r.len(), 100_000);

        // 混合命中/未命中域名，各 1000 次求值取 p99
        let mut samples = Vec::with_capacity(2000);
        for i in 0..1000 {
            let d_hit = format!("deep.host{i}.example.com");
            let d_miss = format!("host{i}.nowhere.example.com");
            for (c, expect_hit) in [
                (ctx(Some(&d_hit), None), true),
                (ctx(Some(&d_miss), None), false),
            ] {
                let t = std::time::Instant::now();
                let m = r.matches(&c);
                samples.push(t.elapsed().as_nanos() as u64);
                assert_eq!(
                    m.rule_index.is_some(),
                    expect_hit,
                    "命中/未命中判定与预期不符"
                );
            }
        }
        samples.sort_unstable();
        let p99 = samples[(samples.len() as f64 * 0.99) as usize];
        println!("100k 规则求值 p99: {p99}ns（门槛 50µs）");
        assert!(p99 < 50_000, "10 万规则 p99 {p99}ns 超出 50µs 验收门");
    }
}
