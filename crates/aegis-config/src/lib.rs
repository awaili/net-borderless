//! # aegis-config
//!
//! 配置层（PRD F7 / 架构 L0）。
//!
//! 已实现（M0 第二批）：
//! - 声明式 YAML schema（[`schema::Profile`]，`deny_unknown_fields` 严格校验），
//!   与 `presets/example.yaml` 一一对应（活样例，测试强制同步）
//! - [`Profile::from_yaml_str`] / [`Profile::from_path`]：解析 + 加载期校验
//! - 硬错误（拒绝加载）vs 软警告（[`Warning`]，进诊断与 UI）分层：
//!   硬错误——版本不支持、id 重复、成员引用不存在、组循环引用、规则语法错误、
//!   规则目标组不存在、未声明规则集、监听地址非法
//!   软警告——final 缺省（默认 REJECT）、规则集桩未生效、未引用节点、DNS 上游缺失
//! - [`Profile::compile_rules`]：产出 aegis-rules 的 [`CompiledRules`]
//!
//! 待办（后续迭代）：
//! - `import/`：sing-box JSON / Clash YAML / 订阅 URI 导入（只读副本）
//! - `ruleset/`：远程规则集加载、Ed25519 签名校验、增量更新（消除 RuleSetRef 桩）
//! - `reload/`：文件监听与热重载 diff 事件
//! - 凭据注入：Keychain 引用替换（运行期，与平台层协作）

pub mod schema;

pub use schema::{
    Dns, DnsMode, Dur, Group, GroupType, Inbound, Mixed, Node, Profile, Protocol, RuleSet,
    SplitDns, Subscription, Tun, Warning, WarningKind,
};

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;

use aegis_rules::{CompiledRules, Matcher, ParsedRule, Target};
use thiserror::Error;

/// 配置加载/校验错误。
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("YAML 解析失败: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("读取文件失败: {0}")]
    Io(#[from] std::io::Error),
    #[error("不支持的配置版本 {0}（当前支持 1）")]
    UnsupportedVersion(u32),
    #[error("id 重复: {0}")]
    DuplicateId(String),
    #[error("策略组 {0} 引用了不存在的节点/组: {1}")]
    UnknownMember(String, String),
    #[error("规则 #{0} 的目标组不存在: {1}")]
    UnknownRuleTarget(usize, String),
    #[error("规则 #{0} 语法错误: {1}")]
    BadRule(usize, #[source] aegis_rules::ParseError),
    #[error("规则 #{0} 引用了未声明的规则集: {1}")]
    UnknownRuleSet(usize, String),
    #[error("策略组循环引用: {0}")]
    GroupCycle(String),
    #[error("监听地址非法: {0}")]
    BadListen(String),
    #[error("兜底目标非法: {0}")]
    BadFinal(#[source] aegis_rules::ParseError),
}

impl Profile {
    /// 解析并校验一份 YAML 配置（`presets/example.yaml` 是活样例）。
    pub fn from_yaml_str(s: &str) -> Result<Self, ConfigError> {
        let mut p: Profile = serde_yaml::from_str(s)?;
        p.post_load()?;
        Ok(p)
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&s)
    }

    /// 兜底目标：`final:` 未写时默认 REJECT（调用方应先检查 `warnings` 里的
    /// `DefaultFallback`，UI 需要向用户展示这一事实）。
    pub fn fallback_target(&self) -> Result<Target, ConfigError> {
        match &self.fallback {
            Some(s) => aegis_rules::parse_target(s).map_err(ConfigError::BadFinal),
            None => Ok(Target::Reject),
        }
    }

    /// 把 `rules:` 编译为规则引擎可求值的 [`CompiledRules`]（每次调用重新解析，
    /// 配置热重载路径上代价可忽略）。
    pub fn compile_rules(&self) -> Result<CompiledRules, ConfigError> {
        let rules = self.parse_rules()?;
        Ok(CompiledRules::build(rules, self.fallback_target()?))
    }

    pub fn group(&self, id: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.id == id)
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    fn parse_rules(&self) -> Result<Vec<ParsedRule>, ConfigError> {
        self.rules
            .iter()
            .enumerate()
            .map(|(i, line)| aegis_rules::parse_rule(line).map_err(|e| ConfigError::BadRule(i, e)))
            .collect()
    }

    /// 加载期校验：硬错误走 `Err`，软问题收集进 `warnings`。
    fn post_load(&mut self) -> Result<(), ConfigError> {
        let mut warnings = Vec::new();
        if self.version != 1 {
            return Err(ConfigError::UnsupportedVersion(self.version));
        }

        // DNS 上游必须显式声明；未声明是运行期强制拒绝，加载期只警告（PRD F4）
        if self.dns.default.is_none() {
            warnings.push(Warning {
                kind: WarningKind::NoDnsUpstream,
                message: "未配置 DNS 上游：运行期将拒绝所有域名解析（防泄露设计），请检查这是否是你想要的".into(),
            });
        }

        // id 唯一性
        check_dup("节点", self.nodes.iter().map(|n| n.id.as_str()))?;
        check_dup("策略组", self.groups.iter().map(|g| g.id.as_str()))?;
        check_dup("订阅", self.subscriptions.iter().map(|s| s.id.as_str()))?;
        check_dup("规则集", self.rule_sets.iter().map(|r| r.id.as_str()))?;

        let node_ids: HashSet<&str> = self.nodes.iter().map(|n| n.id.as_str()).collect();
        let group_map: HashMap<&str, &Group> =
            self.groups.iter().map(|g| (g.id.as_str(), g)).collect();
        let rule_set_ids: HashSet<&str> = self.rule_sets.iter().map(|r| r.id.as_str()).collect();

        // 组成员引用存在性 + 组间循环检测
        for g in &self.groups {
            for m in &g.members {
                let known = node_ids.contains(m.as_str())
                    || group_map.contains_key(m.as_str())
                    || m == "DIRECT"
                    || m == "REJECT";
                if !known {
                    return Err(ConfigError::UnknownMember(g.id.clone(), m.clone()));
                }
            }
        }
        let mut state: HashMap<&str, u8> = HashMap::new(); // 1=访问中 2=完成
        for g in &self.groups {
            visit_group(g, &group_map, &mut state)?;
        }

        // 规则：语法、目标组、规则集引用
        for (i, line) in self.rules.iter().enumerate() {
            let parsed = aegis_rules::parse_rule(line).map_err(|e| ConfigError::BadRule(i, e))?;
            if let Target::Group(g) = &parsed.target {
                if !group_map.contains_key(g.as_str()) {
                    return Err(ConfigError::UnknownRuleTarget(i + 1, g.clone()));
                }
            }
            let mut refs = Vec::new();
            collect_ruleset_refs(&parsed.condition, &mut refs);
            for rs in refs {
                if rule_set_ids.contains(rs.as_str()) {
                    warnings.push(Warning {
                        kind: WarningKind::RuleSetStub,
                        message: format!(
                            "规则 #{0} 引用的规则集 {rs:?} 尚未实现展开，该条暂不生效",
                            i + 1
                        ),
                    });
                } else {
                    return Err(ConfigError::UnknownRuleSet(i + 1, rs.clone()));
                }
            }
        }

        // final：缺失软警告（默认 REJECT），写了但非法硬错误
        match &self.fallback {
            None => warnings.push(Warning {
                kind: WarningKind::DefaultFallback,
                message: "未声明 final:，兜底默认 REJECT（未匹配流量将被拒绝）".into(),
            }),
            Some(s) => {
                aegis_rules::parse_target(s).map_err(ConfigError::BadFinal)?;
            }
        }

        // 未被任何策略组引用的节点
        let mut referenced: HashSet<&str> = HashSet::new();
        for g in &self.groups {
            for m in &g.members {
                if node_ids.contains(m.as_str()) {
                    referenced.insert(m.as_str());
                }
            }
        }
        for n in &self.nodes {
            if !referenced.contains(n.id.as_str()) {
                warnings.push(Warning {
                    kind: WarningKind::UnusedNode,
                    message: format!("节点 {} 未被任何策略组引用", n.id),
                });
            }
        }

        // mixed 监听地址
        if let Some(listen) = &self.inbound.mixed.listen {
            listen
                .parse::<SocketAddr>()
                .map_err(|_| ConfigError::BadListen(listen.clone()))?;
        }

        self.warnings = warnings;
        Ok(())
    }
}

/// id 唯一性检查。
fn check_dup<'a>(
    kind: &'static str,
    ids: impl Iterator<Item = &'a str>,
) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(ConfigError::DuplicateId(format!("{kind} {id}")));
        }
    }
    Ok(())
}

/// 组引用的环检测（白/灰/黑三色 DFS）。
fn visit_group<'a>(
    g: &'a Group,
    map: &HashMap<&'a str, &'a Group>,
    state: &mut HashMap<&'a str, u8>,
) -> Result<(), ConfigError> {
    match state.get(g.id.as_str()).copied() {
        Some(2) => return Ok(()),
        Some(1) => return Err(ConfigError::GroupCycle(g.id.clone())),
        _ => {}
    }
    state.insert(g.id.as_str(), 1);
    for m in &g.members {
        if let Some(sub) = map.get(m.as_str()) {
            visit_group(sub, map, state)?;
        }
    }
    state.insert(g.id.as_str(), 2);
    Ok(())
}

/// 递归收集 Matcher 里的 RULE-SET 引用。
fn collect_ruleset_refs(m: &Matcher, out: &mut Vec<String>) {
    match m {
        Matcher::RuleSetRef(id) => out.push(id.clone()),
        Matcher::Logical(aegis_rules::Logical::And(ms))
        | Matcher::Logical(aegis_rules::Logical::Or(ms)) => {
            ms.iter().for_each(|m| collect_ruleset_refs(m, out));
        }
        Matcher::Logical(aegis_rules::Logical::Not(inner)) => collect_ruleset_refs(inner, out),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_rules::ConnCtx;

    /// 活样例（docs/05 §5：schema 变更必须同步此文件）
    const EXAMPLE: &str = include_str!("../../../presets/example.yaml");

    fn load(yaml: &str) -> Result<Profile, ConfigError> {
        Profile::from_yaml_str(yaml)
    }

    #[test]
    fn example_yaml_loads_compiles_and_warns_about_ruleset_stub() {
        let p = load(EXAMPLE).expect("活样例必须可加载");
        // 唯一警告：规则集桩
        let kinds: Vec<_> = p.warnings.iter().map(|w| w.kind).collect();
        assert_eq!(kinds, vec![WarningKind::RuleSetStub]);

        let rules = p.compile_rules().unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(*rules.fallback(), Target::Reject);

        // netflix 域名 → media 组（PRD F2 示例表达式）
        let mut ctx = ConnCtx::new(None, 443);
        ctx.domain = Some("www.netflix.com");
        assert_eq!(rules.matches(&ctx).target, Target::Group("media".into()));

        // GEOIP,CN → DIRECT
        let mut ctx = ConnCtx::new(Some("223.5.5.5".parse().unwrap()), 443);
        ctx.domain = Some("baidu.com");
        ctx.geoip_country = Some("CN");
        assert_eq!(rules.matches(&ctx).target, Target::Direct);

        // 时长解析：interval 300s / tolerance 50ms
        let auto = p.group("auto").unwrap();
        assert_eq!(auto.interval.unwrap().as_secs(), 300);
        assert_eq!(auto.tolerance.unwrap().as_millis(), 50);
    }

    const MINIMAL: &str = "version: 1\n";

    #[test]
    fn missing_final_defaults_to_reject_with_warning() {
        let p = load(MINIMAL).unwrap();
        assert!(p
            .warnings
            .iter()
            .any(|w| w.kind == WarningKind::DefaultFallback));
        assert_eq!(p.fallback_target().unwrap(), Target::Reject);
        // DNS 上游缺失也应产生防泄露警告
        assert!(p
            .warnings
            .iter()
            .any(|w| w.kind == WarningKind::NoDnsUpstream));
    }

    #[test]
    fn duration_forms() {
        // 注意：测试里的 YAML 必须用原始字符串——Rust 的 \ 续行会吞掉行首缩进
        let p = load(
            r#"
            version: 1
            groups:
              - id: g
                type: url-test
                members: [n1]
                interval: 2m
                tolerance: 100
            nodes:
              - id: n1
                protocol: trojan
                server: s
                port: 443
                key-ref: k
            "#,
        )
        .unwrap();
        let g = p.group("g").unwrap();
        assert_eq!(g.interval.unwrap().as_secs(), 120);
        assert_eq!(g.tolerance.unwrap().as_secs(), 100);
    }

    #[test]
    fn hard_errors() {
        // 版本
        assert!(matches!(
            load("version: 2"),
            Err(ConfigError::UnsupportedVersion(2))
        ));

        // id 重复
        let dup = r#"
            version: 1
            nodes:
              - {id: n1, protocol: trojan, server: s, port: 1, key-ref: k}
              - {id: n1, protocol: trojan, server: s, port: 2, key-ref: k}
        "#;
        assert!(matches!(load(dup), Err(ConfigError::DuplicateId(_))));

        // 成员引用不存在
        let member = r#"
            version: 1
            groups:
              - {id: g, type: select, members: [nope]}
        "#;
        assert!(matches!(
            load(member),
            Err(ConfigError::UnknownMember(_, _))
        ));

        // 组循环引用
        let cycle = r#"
            version: 1
            groups:
              - {id: a, type: select, members: [b]}
              - {id: b, type: select, members: [a]}
        "#;
        assert!(matches!(load(cycle), Err(ConfigError::GroupCycle(_))));

        // 规则语法错误（带行号）
        let bad_rule = r#"
            version: 1
            groups:
              - {id: g, type: select, members: [DIRECT]}
            rules:
              - 'WHAT,x -> g'
        "#;
        assert!(matches!(load(bad_rule), Err(ConfigError::BadRule(0, _))));

        // 规则目标组不存在
        let bad_target = r#"
            version: 1
            groups:
              - {id: g, type: select, members: [DIRECT]}
            rules:
              - 'DOMAIN,x.com -> nope'
        "#;
        assert!(matches!(
            load(bad_target),
            Err(ConfigError::UnknownRuleTarget(1, _))
        ));

        // 引用未声明的规则集
        let bad_rs = r#"
            version: 1
            groups:
              - {id: g, type: select, members: [DIRECT]}
            rules:
              - 'RULE-SET,missing -> g'
        "#;
        assert!(matches!(
            load(bad_rs),
            Err(ConfigError::UnknownRuleSet(1, _))
        ));

        // 监听地址非法
        let bad_listen = r#"
            version: 1
            inbound:
              mixed:
                enabled: true
                listen: not-an-addr
        "#;
        assert!(matches!(load(bad_listen), Err(ConfigError::BadListen(_))));

        // final 写了但非法
        let bad_final = "version: 1\nfinal: 'my group'\n";
        assert!(matches!(load(bad_final), Err(ConfigError::BadFinal(_))));
    }

    #[test]
    fn unknown_field_is_rejected() {
        // deny_unknown_fields：拼错字段立即报错而非静默忽略
        assert!(load("version: 1\nnode: []").is_err());
    }
}
