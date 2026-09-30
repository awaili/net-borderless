//! # aegis-rules
//!
//! 规则引擎（PRD F2 / 架构 L1）：
//! - 匹配器：DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX / IP-CIDR / GEOIP / PORT /
//!   PROTOCOL（嗅探）/ PROCESS（仅桌面）
//! - 嵌套逻辑表达式：`AND((DOMAIN-SUFFIX,netflix.com), NOT(IP-CIDR,10.0.0.0/8))`
//! - RULE-SET：sing-box rule-set 兼容 + Ed25519 签名自有格式、版本与增量更新
//! - 命中计数（喂给 aegis-diag 的学习式建议）
//!
//! 规划模块：
//! - `matcher/`：各匹配器（热路径零堆分配，arena 预分配）
//! - `expr/`：逻辑表达式 AST
//! - `compile/`：Profile 加载期编译为 `CompiledRules`（单次匹配 p99 < 50µs，fuzz 进 CI）
//! - `ruleset/`：规则集加载、签名校验、版本与缓存
