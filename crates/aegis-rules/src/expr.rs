//! 逻辑表达式解析（PRD F2）。
//!
//! 语法：
//! ```text
//! expr    := '(' expr ')'                        // 多余括号
//!          | AND '(' expr (',' expr)* ')'
//!          | OR  '(' expr (',' expr)* ')'
//!          | NOT '(' expr ')'
//!          | primary                              // 如 DOMAIN-SUFFIX,netflix.com
//! ```

use crate::matcher::{from_args, Logical, Matcher};
use crate::ParseError;

/// 解析一个条件表达式（不含 `-> TARGET` 部分）。
pub fn parse_expr(input: &str) -> Result<Matcher, ParseError> {
    expr(input)
}

fn expr(s: &str) -> Result<Matcher, ParseError> {
    let s = s.trim();
    if let Some(inner) = strip_parens(s) {
        return expr(inner);
    }
    if let Some(m) = try_logical(s)? {
        return Ok(m);
    }
    primary(s)
}

/// 识别 `AND(...)` / `OR(...)` / `NOT(...)`，名字大小写不敏感。
fn try_logical(s: &str) -> Result<Option<Matcher>, ParseError> {
    for (name, is_not) in [("AND", false), ("OR", false), ("NOT", true)] {
        if s.len() <= name.len() || !s[..name.len()].eq_ignore_ascii_case(name) {
            continue;
        }
        let bytes = s.as_bytes();
        // 宽容逻辑名与 '(' 之间的空白：`AND (...)` 与 `AND(...)` 等价
        let after_name = &s[name.len()..];
        let ws = after_name.len() - after_name.trim_start().len();
        let open = name.len() + ws;
        if bytes.get(open) != Some(&b'(') {
            continue;
        }
        // 找到与 open 处 '(' 配对的 ')'
        let mut depth = 0usize;
        let mut close = None;
        for (i, &b) in bytes.iter().enumerate().skip(open) {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            return Err(ParseError::UnbalancedParen(open + 1));
        };
        let rest = s[close + 1..].trim();
        if !rest.is_empty() {
            return Err(ParseError::TrailingInput(rest.to_string()));
        }
        if is_not {
            // NOT 的操作数是单个表达式（如 NOT(IP-CIDR,10.0.0.0/8)——
            // 其中的逗号是匹配器自身的参数分隔符，不按顶层逗号切分）
            return Ok(Some(Matcher::Logical(Logical::Not(Box::new(expr(
                &s[open + 1..close],
            )?)))));
        }
        let args = split_top_level(&s[open + 1..close], name)?;
        let nested = args
            .iter()
            .map(|a| expr(a))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Some(Matcher::Logical(if name == "AND" {
            Logical::And(nested)
        } else {
            Logical::Or(nested)
        })));
    }
    Ok(None)
}

/// 解析最简单的 `NAME,arg[,arg...]` 形式。
fn primary(s: &str) -> Result<Matcher, ParseError> {
    let mut parts = s.split(',');
    let name = parts.next().unwrap_or("").trim().to_ascii_uppercase();
    let args: Vec<&str> = parts.map(str::trim).collect();
    if name.is_empty() {
        return Err(ParseError::TooFewArgs {
            matcher: "<空>",
            expected: 1,
        });
    }
    from_args(&name, &args)
}

/// 在顶层（括号深度 0）按逗号切分参数，每段已 trim。
fn split_top_level<'a>(s: &'a str, ctx_name: &'static str) -> Result<Vec<&'a str>, ParseError> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(ParseError::UnbalancedParen(i + 1))?;
            }
            b',' if depth == 0 => {
                out.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(ParseError::UnbalancedParen(s.len()));
    }
    out.push(s[start..].trim());
    if out.iter().all(|a| a.is_empty()) {
        return Err(ParseError::TooFewArgs {
            matcher: ctx_name,
            expected: 1,
        });
    }
    Ok(out)
}

/// 若 `s` 整体被一对括号包裹（首字符 '(' 与末字符 ')' 互相配对），返回内部内容。
fn strip_parens(s: &str) -> Option<&str> {
    if !s.starts_with('(') || !s.ends_with(')') {
        return None;
    }
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                // 首个 '(' 的配对必须就是最后一个字符，否则不是整体包裹
                if depth == 0 && i + 1 != bytes.len() {
                    return None;
                }
            }
            _ => {}
        }
    }
    Some(&s[1..s.len() - 1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_logic() {
        // AND((A), NOT(B)) —— PRD 中的示例
        let m = parse_expr("AND((DOMAIN-SUFFIX,netflix.com), NOT(IP-CIDR,10.0.0.0/8))").unwrap();
        let mut ctx = crate::ConnCtx::new(None, 443);
        ctx.domain = Some("www.netflix.com");
        assert!(m.matches(&ctx));
        ctx.dst_ip = Some("10.1.2.3".parse().unwrap());
        assert!(!m.matches(&ctx));

        // OR + 多余括号
        let m = parse_expr("(( OR ((DOMAIN,a.com), (DOMAIN,b.com)) ))").unwrap();
        let mut ctx = crate::ConnCtx::new(None, 0);
        ctx.domain = Some("b.com");
        assert!(m.matches(&ctx));
    }

    #[test]
    fn primary_forms() {
        assert!(parse_expr(" domain-suffix , Netflix.com ").is_ok());
        assert!(matches!(
            parse_expr("BOGUS,x"),
            Err(ParseError::UnknownMatcher(_))
        ));
        assert!(matches!(
            parse_expr("DOMAIN"),
            Err(ParseError::TooFewArgs { .. })
        ));
        assert!(matches!(parse_expr(""), Err(ParseError::TooFewArgs { .. })));
    }
}
