//! 规则条目 DSL（对应 presets/example.yaml 的 `rules:` 列表）。
//!
//! ```text
//! rule   := CONDITION "->" TARGET
//! TARGET := "DIRECT" | "REJECT" | 策略组 id（不含空白与 , ( )）
//! ```
//!
//! 兜底（配置的 `final:`）不在 DSL 内，由调用方显式传给 [`crate::CompiledRules::build`]。

use crate::expr::parse_expr;
use crate::matcher::Matcher;
use crate::{ParseError, Target};

/// 一条解析完成的规则：条件 + 目标。
#[derive(Debug, Clone)]
pub struct ParsedRule {
    pub condition: Matcher,
    pub target: Target,
}

/// 解析单行规则，如 `AND((DOMAIN-SUFFIX,netflix.com), NOT(IP-CIDR,10.0.0.0/8)) -> media`。
pub fn parse_rule(line: &str) -> Result<ParsedRule, ParseError> {
    let Some((cond, target)) = line.split_once("->") else {
        return Err(ParseError::MissingTarget);
    };
    let target = parse_target(target.trim())?;
    let condition = parse_expr(cond.trim())?;
    Ok(ParsedRule { condition, target })
}

/// 解析目标：`DIRECT` / `REJECT`（大小写不敏感）或策略组 id。
pub fn parse_target(s: &str) -> Result<Target, ParseError> {
    match s.to_ascii_uppercase().as_str() {
        "DIRECT" => return Ok(Target::Direct),
        "REJECT" => return Ok(Target::Reject),
        _ => {}
    }
    let valid = !s.is_empty()
        && !s
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b',' | b'(' | b')'));
    if valid {
        Ok(Target::Group(s.to_string()))
    } else {
        Err(ParseError::InvalidTarget(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(parse_target("direct").unwrap(), Target::Direct);
        assert_eq!(parse_target("REJECT").unwrap(), Target::Reject);
        assert_eq!(
            parse_target("media").unwrap(),
            Target::Group("media".into())
        );
        assert!(parse_target("").is_err());
        assert!(parse_target("my group").is_err());
        assert!(parse_target("a,b").is_err());
    }

    #[test]
    fn rule_split() {
        let r = parse_rule("DOMAIN-SUFFIX,netflix.com -> media").unwrap();
        assert_eq!(r.target, Target::Group("media".into()));
        assert!(matches!(r.condition, Matcher::DomainSuffix(_)));
        assert!(matches!(
            parse_rule("DOMAIN-SUFFIX,netflix.com"),
            Err(ParseError::MissingTarget)
        ));
    }
}
