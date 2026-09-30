//! # aegis-router
//!
//! 连接编排层（PRD F3 / 架构 L2）——核心引擎的心脏。
//!
//! 已实现（M0 第三批，最小闭环）：
//! - [`Router::build`]：从 [`aegis_config::Profile`] 构建路由器
//!   （规则编译 + 节点映射为出站连接器 + 策略组**展开**为扁平出站序列）
//! - [`Router::route`]：规则求值；[`Router::resolve`]：目标 → 出站连接器
//!   （M0 策略组一律取首个可用成员；url-test/fallback/load-balance/smart
//!   的探活选路是下一批——见 `prober/` 待办）
//! - [`Router::handle`]：单连接完整编排——建上下文 → 规则求值 → 出站连接 →
//!   入站应答 → 双向拷贝（带字节计数）→ [`ConnReport`]（连接报告，
//!   aegis-observe 接入前的临时观测形态，bin 直接打印）
//! - 不支持的出站协议在 build 期跳过并记录（不静默：bin 会打印提示）
//!
//! 待办（后续迭代）：
//! - `sniffer/`：首包嗅探（SNI / HTTP host / QUIC SNI）——M0 阶段域名来自
//!   代理协议本身，无需嗅探
//! - `prober/`：探活调度器（双探针 + 摘除回融，PRD F3 全部行为）
//! - `group/`：url-test / fallback / load-balance / smart 选路逻辑
//! - `session/`：连接池与 mux 复用
//! - 事件推送：经 aegis-observe 的 `EventSink` 单向推流（当前 ConnReport 由
//!   调用方同步取回）

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use aegis_config::{ConfigError, Profile, Protocol};
use aegis_inbound::Via;
use aegis_outbound::{Endpoint, Outbound, OutboundError};
use aegis_rules::{CompiledRules, ConnCtx, MatchResult, Target};
use tokio::io::copy_bidirectional;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("配置错误: {0}")]
    Config(#[from] ConfigError),
    #[error("目标 {0} 没有可用的出站节点")]
    NoOutbound(String),
    #[error("分流决策为 REJECT: {0}")]
    Rejected(String),
    #[error(transparent)]
    Outbound(#[from] OutboundError),
    #[error("入站协议错误: {0}")]
    Inbound(#[from] aegis_inbound::InboundError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// 单连接报告（观察数据的最小形态；aegis-observe 接入后转为事件推流）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnReport {
    pub target: Endpoint,
    /// 命中规则下标（None = final 兜底）
    pub rule_index: Option<usize>,
    /// 分流目标（DIRECT/REJECT/组 id）
    pub decision: Target,
    /// 实际使用的出站描述（DIRECT / socks5://…）
    pub via: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// 路由器：构建一次，运行期只读（命中计数在 CompiledRules 内部）。
#[derive(Debug)]
pub struct Router {
    rules: CompiledRules,
    /// 组 id → 展开后的出站序列（首 个可用成员生效——M0 行为）
    groups: HashMap<String, Vec<Outbound>>,
    /// build 期被跳过的节点（协议尚未实现），供诊断/启动日志展示
    skipped_nodes: Vec<String>,
    total_conns: AtomicU64,
}

impl Router {
    pub fn build(profile: &Profile) -> Result<Self, RouterError> {
        let rules = profile.compile_rules()?;
        let mut outbound_by_node: HashMap<&str, Outbound> = HashMap::new();
        let mut skipped_nodes = Vec::new();
        for n in &profile.nodes {
            match outbound(n.protocol, n) {
                Some(o) => {
                    outbound_by_node.insert(n.id.as_str(), o);
                }
                None => skipped_nodes.push(format!(
                    "{}（协议 {} 尚未实现，被跳过）",
                    n.id,
                    describe_protocol(n.protocol)
                )),
            }
        }

        // 策略组展开为扁平出站序列（嵌套组递归展开；配置层已校验无环，
        // 这里的 visited 是防御性兜底）
        let mut groups = HashMap::new();
        for g in &profile.groups {
            let mut out = Vec::new();
            let mut visited: HashSet<&str> = HashSet::new();
            visited.insert(g.id.as_str());
            for m in &g.members {
                expand_member(m, profile, &outbound_by_node, &mut out, &mut visited);
            }
            groups.insert(g.id.clone(), out);
        }

        Ok(Self {
            rules,
            groups,
            skipped_nodes,
            total_conns: AtomicU64::new(0),
        })
    }

    /// build 期被跳过的节点说明（启动日志/诊断用）。
    pub fn skipped_nodes(&self) -> &[String] {
        &self.skipped_nodes
    }

    pub fn total_conns(&self) -> u64 {
        self.total_conns.load(Ordering::Relaxed)
    }

    /// 规则求值。
    pub fn route(&self, ctx: &ConnCtx) -> MatchResult {
        self.rules.matches(ctx)
    }

    /// 分流目标 → 出站连接器。
    ///
    /// REJECT 与无可用成员的组返回 `None`（调用方应向客户端回复失败并关闭）。
    /// M0：所有组类型都取首个可用成员（url-test 等探活选路为下一批）。
    pub fn resolve(&self, target: &Target) -> Option<Outbound> {
        match target {
            Target::Direct => Some(Outbound::Direct),
            Target::Reject => None,
            Target::Group(id) => self.groups.get(id)?.first().cloned(),
        }
    }

    /// 单连接完整编排。`inbound` 是已完成请求解析的客户端流。
    pub async fn handle<S>(
        &self,
        endpoint: &Endpoint,
        inbound: &mut S,
        via: Via,
    ) -> Result<ConnReport, RouterError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.total_conns.fetch_add(1, Ordering::Relaxed);

        // 1) 上下文：代理协议已给出目标（域名或 IP），M0 无嗅探
        let mut ctx = ConnCtx::new(endpoint.ip(), endpoint.port);
        if endpoint.ip().is_none() {
            ctx.domain = Some(&endpoint.host);
        }

        // 2) 规则求值 + 出站选择
        let m = self.route(&ctx);
        let Some(outbound) = self.resolve(&m.target) else {
            aegis_inbound::reply_err(inbound, via).await?;
            return Err(RouterError::Rejected(target_desc(&m.target)));
        };

        // 3) 出站连接（失败：向客户端回错并上抛）
        let mut out = outbound.connect(endpoint).await?;
        aegis_inbound::reply_ok(inbound, via).await?;

        // 4) 双向拷贝
        let (bytes_up, bytes_down) = copy_bidirectional(inbound, &mut out).await?;

        Ok(ConnReport {
            target: endpoint.clone(),
            rule_index: m.rule_index,
            decision: m.target,
            via: outbound.describe(),
            bytes_up,
            bytes_down,
        })
    }
}

/// 组成员递归展开。
fn expand_member<'a>(
    member: &str,
    profile: &'a Profile,
    outbound_by_node: &HashMap<&str, Outbound>,
    out: &mut Vec<Outbound>,
    visited: &mut HashSet<&'a str>,
) {
    match member {
        "DIRECT" => out.push(Outbound::Direct),
        "REJECT" => {} // REJECT 成员：组内跳过（组级 REJECT 由规则引擎 Target 表达）
        _ => {
            if let Some(o) = outbound_by_node.get(member) {
                out.push(o.clone());
            } else if let Some(sub) = profile.group(member) {
                if visited.insert(sub.id.as_str()) {
                    for m in &sub.members {
                        expand_member(m, profile, outbound_by_node, out, visited);
                    }
                }
            }
            // 未匹配到任何东西：配置层校验已拒绝未知引用，静默跳过不可达
        }
    }
}

fn outbound(protocol: Protocol, node: &aegis_config::Node) -> Option<Outbound> {
    let proxy = Endpoint::new(node.server.clone(), node.port);
    match protocol {
        Protocol::Http => Some(Outbound::Http { proxy, auth: None }),
        Protocol::Socks5 => Some(Outbound::Socks5 { proxy, auth: None }),
        _ => None,
    }
}

fn describe_protocol(p: Protocol) -> &'static str {
    match p {
        Protocol::Shadowsocks2022 => "shadowsocks-2022",
        Protocol::Trojan => "trojan",
        Protocol::VlessReality => "vless-reality",
        Protocol::Wireguard => "wireguard",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Tuic => "tuic",
        Protocol::Http => "http",
        Protocol::Socks5 => "socks5",
    }
}

/// Target 的人类可读描述（日志/报告用）。
pub fn target_desc(t: &Target) -> String {
    match t {
        Target::Direct => "DIRECT".into(),
        Target::Reject => "REJECT".into(),
        Target::Group(id) => id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CFG: &str = r#"
        version: 1
        nodes:
          - {id: n1, protocol: socks5, server: 127.0.0.1, port: 1080, key-ref: k}
          - {id: n2, protocol: http, server: 10.0.0.1, port: 8080, key-ref: k}
          - {id: n3, protocol: trojan, server: 10.0.0.2, port: 443, key-ref: k}
        groups:
          - {id: g_outer, type: select, members: [g_inner]}
          - {id: g_inner, type: select, members: [n1, n2]}
        rules:
          - 'DOMAIN-SUFFIX,netflix.com -> g_outer'
        final: DIRECT
    "#;

    fn router() -> Router {
        let p = Profile::from_yaml_str(CFG).unwrap();
        Router::build(&p).unwrap()
    }

    #[test]
    fn groups_expand_nested_and_skip_unsupported() {
        let r = router();
        // 嵌套组展开为扁平序列，未实现协议（trojan）被跳过
        let outer = r.groups.get("g_outer").unwrap();
        assert_eq!(
            outer,
            &vec![
                Outbound::Socks5 {
                    proxy: Endpoint::new("127.0.0.1", 1080),
                    auth: None
                },
                Outbound::Http {
                    proxy: Endpoint::new("10.0.0.1", 8080),
                    auth: None
                },
            ]
        );
        assert_eq!(r.skipped_nodes().len(), 1);
        assert!(r.skipped_nodes()[0].contains("n3"));
    }

    #[test]
    fn resolve_targets() {
        let r = router();
        assert_eq!(r.resolve(&Target::Direct), Some(Outbound::Direct));
        assert_eq!(r.resolve(&Target::Reject), None);
        // 组 → 首个可用成员
        assert_eq!(
            r.resolve(&Target::Group("g_outer".into())),
            Some(Outbound::Socks5 {
                proxy: Endpoint::new("127.0.0.1", 1080),
                auth: None
            })
        );
        assert_eq!(r.resolve(&Target::Group("missing".into())), None);
    }

    #[test]
    fn route_uses_rules() {
        let r = router();
        let mut ctx = ConnCtx::new(None, 443);
        ctx.domain = Some("www.netflix.com");
        assert_eq!(r.route(&ctx).target, Target::Group("g_outer".into()));
        // 未匹配 → final DIRECT
        let ctx = ConnCtx::new(None, 80);
        assert_eq!(r.route(&ctx).target, Target::Direct);
    }

    /// 端到端：DIRECT 出站到本地回显服务器，验证 handle 全链路
    /// （上下文 → 规则 → 出站 → 应答 → 双向拷贝 → 报告）。
    #[tokio::test]
    async fn handle_end_to_end_direct() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut c, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = c.split();
            tokio::io::copy(&mut r, &mut w).await.unwrap();
        });

        let cfg = "version: 1\nfinal: DIRECT\n";
        let r = Router::build(&Profile::from_yaml_str(cfg).unwrap()).unwrap();

        // 客户端 ↔ 入站（duplex 的 server 半边视作入站流）
        let (mut client, mut server) = tokio::io::duplex(4096);
        let target = Endpoint::new("127.0.0.1", echo_addr.port());
        let handle_task =
            tokio::spawn(async move { r.handle(&target, &mut server, Via::HttpConnect).await });

        // 收到 200 应答后开始传数据
        let mut buf = [0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
        client.write_all(b"ping-through").await.unwrap();
        let mut echo_buf = [0u8; 12];
        client.read_exact(&mut echo_buf).await.unwrap();
        assert_eq!(&echo_buf, b"ping-through");
        client.shutdown().await.unwrap();

        let report = handle_task.await.unwrap().unwrap();
        assert_eq!(report.decision, Target::Direct);
        assert_eq!(report.rule_index, None); // final 兜底
        assert_eq!(report.via, "DIRECT");
        assert_eq!(report.bytes_up, 12);
        assert!(report.bytes_down >= 12);
        echo_task.await.unwrap();
    }
}
