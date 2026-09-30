//! # aegis-router
//!
//! 连接编排层（PRD F3 / 架构 L2）——核心引擎的心脏。
//!
//! 已实现（M0 第四批，最小闭环 + 策略组选路）：
//! - [`Router::build`]：从 [`aegis_config::Profile`] 构建路由器
//!   （规则编译 + 节点映射为出站连接器 + 策略组展开为 [`group::GroupRuntime`]）
//! - [`Router::route`]：规则求值；[`Router::resolve`]：目标 → 出站连接器
//!   （五种组类型语义见 [`group`] 模块文档）
//! - [`Router::handle`]：单连接完整编排——建上下文 → 规则求值 → 出站连接 →
//!   入站应答 → 双向拷贝（带字节计数）→ [`ConnReport`]（连接报告，
//!   aegis-observe 接入前的临时观测形态，bin 直接打印）
//! - [`Router::start_probers`]：拉起每组探活调度（[`prober`] 模块），
//!   事件推流给观测层
//! - 不支持的出站协议在 build 期跳过并记录（不静默：bin 会打印提示）
//!
//! 待办（后续迭代）：
//! - `sniffer/`：首包嗅探（SNI / HTTP host / QUIC SNI）——M0 阶段域名来自
//!   代理协议本身，无需嗅探
//! - smart 组的 P1 选路（当前同 fallback）
//! - `session/`：连接池与 mux 复用
//! - 事件推送：经 aegis-observe 的 `EventSink` 单向推流（当前 ConnReport 由
//!   调用方同步取回、探活事件走 mpsc 临时通道）

pub mod group;
pub mod prober;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aegis_config::{ConfigError, GroupType, Profile, Protocol};
use aegis_inbound::Via;
use aegis_outbound::{Endpoint, Outbound, OutboundError};
use aegis_rules::{CompiledRules, ConnCtx, MatchResult, Target};
use tokio::io::copy_bidirectional;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::UnboundedSender;

pub use group::{GroupRuntime, GroupStatus, MemberStatus};
pub use prober::ProberEvent;

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("配置错误: {0}")]
    Config(#[from] ConfigError),
    #[error("目标 {0} 没有可用的出站节点")]
    NoOutbound(String),
    #[error("分流决策为 REJECT: {0}")]
    Rejected(String),
    #[error("策略组错误: {0}")]
    Group(String),
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
    /// 组 id → 组运行时（选路语义与探活状态在 [`group::GroupRuntime`]）
    groups: HashMap<String, Arc<GroupRuntime>>,
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
                Ok(o) => {
                    outbound_by_node.insert(n.id.as_str(), o);
                }
                Err(reason) => skipped_nodes.push(format!("{}: {reason}", n.id)),
            }
        }

        // 策略组展开为扁平成员序列（嵌套组递归展开；配置层已校验无环，
        // 这里的 visited 是防御性兜底），再包成 GroupRuntime（选路语义 + 探活状态）
        let mut groups = HashMap::new();
        for g in &profile.groups {
            let mut members = Vec::new();
            let mut visited: HashSet<&str> = HashSet::new();
            visited.insert(g.id.as_str());
            for m in &g.members {
                expand_member(m, profile, &outbound_by_node, &mut members, &mut visited);
            }
            groups.insert(
                g.id.clone(),
                Arc::new(GroupRuntime::new(
                    g.id.clone(),
                    g.group_type,
                    members,
                    g.url
                        .clone()
                        .unwrap_or_else(|| group::DEFAULT_PROBE_URL.into()),
                    g.interval.map(|d| d.0).unwrap_or(group::DEFAULT_INTERVAL),
                    g.tolerance.map(|d| d.0).unwrap_or(group::DEFAULT_TOLERANCE),
                )),
            );
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
    /// 组内选中语义见 [`group::GroupRuntime::pick`]。
    pub fn resolve(&self, target: &Target) -> Option<Outbound> {
        match target {
            Target::Direct => Some(Outbound::Direct),
            Target::Reject => None,
            Target::Group(id) => {
                let g = self.groups.get(id)?;
                let i = g.pick()?;
                g.members.get(i).map(|m| m.outbound.clone())
            }
        }
    }

    /// 手动锁定组选中（UI 手动切换入口；对 url-test 组锁定即停止自动切换）。
    pub fn set_manual(&self, group_id: &str, member_id: &str) -> Result<(), RouterError> {
        let g = self
            .groups
            .get(group_id)
            .ok_or_else(|| RouterError::Group(format!("策略组不存在: {group_id}")))?;
        g.set_manual(member_id).map_err(RouterError::Group)
    }

    /// 所有组的快照（状态页/诊断展示用），按组 id 排序。
    pub fn group_statuses(&self) -> Vec<GroupStatus> {
        let mut v: Vec<_> = self
            .groups
            .values()
            .map(|g| {
                let states = g.states.read().unwrap();
                GroupStatus {
                    id: g.id().to_string(),
                    group_type: g.group_type,
                    current: g.current_member().map(|m| m.id.clone()),
                    members: g
                        .members
                        .iter()
                        .enumerate()
                        .map(|(i, m)| MemberStatus {
                            id: m.id.clone(),
                            rtt: states.get(i).and_then(|s| s.rtt),
                            alive: states.get(i).is_some_and(|s| s.alive),
                        })
                        .collect(),
                }
            })
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    /// 拉起探活调度（每组一个任务，select 组不探活）。
    /// 返回任务句柄（调用方持有即可保活，abort 即停）。
    /// 事件经 `tx` 推流；接收方退出（tx 失效）时调度任务自然结束。
    pub fn start_probers(
        &self,
        tx: UnboundedSender<ProberEvent>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        self.groups
            .values()
            .filter(|g| g.group_type != GroupType::Select && !g.members.is_empty())
            .map(|g| tokio::spawn(prober::run_group(g.clone(), tx.clone())))
            .collect()
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

/// 组成员递归展开（扁平化：嵌套组的成员并入本组，叶子 id 保留）。
fn expand_member<'a>(
    member: &str,
    profile: &'a Profile,
    outbound_by_node: &HashMap<&str, Outbound>,
    out: &mut Vec<group::Member>,
    visited: &mut HashSet<&'a str>,
) {
    match member {
        "DIRECT" => out.push(group::Member {
            id: "DIRECT".into(),
            outbound: Outbound::Direct,
        }),
        "REJECT" => {} // REJECT 成员：组内跳过（组级 REJECT 由规则引擎 Target 表达）
        _ => {
            if let Some(o) = outbound_by_node.get(member) {
                out.push(group::Member {
                    id: member.to_string(),
                    outbound: o.clone(),
                });
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

/// 节点 → 出站连接器。`Err(原因)` = build 期跳过并记录（不静默）。
fn outbound(protocol: Protocol, node: &aegis_config::Node) -> Result<Outbound, String> {
    let proxy = Endpoint::new(node.server.clone(), node.port);
    match protocol {
        Protocol::Http => Ok(Outbound::Http { proxy, auth: None }),
        Protocol::Socks5 => Ok(Outbound::Socks5 { proxy, auth: None }),
        Protocol::Shadowsocks2022 => {
            // 密钥注入（M0 CLI 桥）：AEGIS_KEY_<REF>（非字母数字→下划线，大写）。
            // 移动端由 FFI/Keychain 注入（PRD F7），环境变量桥仅限桌面 CLI。
            let Some(method_str) = node.method.as_deref() else {
                return Err("ss2022 节点缺少 method（配置层本应拦截）".into());
            };
            let method = aegis_outbound::ss2022::Ss2022Method::parse(method_str)?;
            let var = format!("AEGIS_KEY_{}", sanitize_env_ref(&node.key_ref));
            let key_b64 = std::env::var(&var).map_err(|_| {
                format!("未找到密钥环境变量 {var}（M0 CLI 从环境注入；移动端由 Keychain 注入）")
            })?;
            let key = aegis_outbound::ss2022::decode_key(method, &key_b64)?;
            Ok(Outbound::Ss2022 { proxy, method, key })
        }
        Protocol::Trojan => {
            let var = format!("AEGIS_KEY_{}", sanitize_env_ref(&node.key_ref));
            let password = std::env::var(&var).map_err(|_| {
                format!("未找到密码环境变量 {var}（M0 CLI 从环境注入；移动端由 Keychain 注入）")
            })?;
            Ok(Outbound::Trojan {
                proxy,
                password,
                tls: aegis_outbound::trojan::TlsParams {
                    sni: node.sni.clone(),
                    skip_verify: node.skip_cert_verify,
                },
            })
        }
        other => Err(format!(
            "协议 {} 尚未实现（M0 里程碑内陆续接入）",
            describe_protocol(other)
        )),
    }
}

/// key-ref → 环境变量名段：非字母数字转下划线后大写。
/// 例：`keychain://nodes/tokyo-01` → `KEYCHAIN__NODES_TOKYO_01`
fn sanitize_env_ref(key_ref: &str) -> String {
    key_ref
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
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
        let ids: Vec<&str> = outer.members.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["n1", "n2"]);
        assert_eq!(
            outer.members[0].outbound,
            Outbound::Socks5 {
                proxy: Endpoint::new("127.0.0.1", 1080),
                auth: None
            }
        );
        assert_eq!(
            outer.members[1].outbound,
            Outbound::Http {
                proxy: Endpoint::new("10.0.0.1", 8080),
                auth: None
            }
        );
        assert_eq!(r.skipped_nodes().len(), 1);
        assert!(r.skipped_nodes()[0].contains("n3"));
    }

    #[test]
    fn resolve_targets() {
        let r = router();
        assert_eq!(r.resolve(&Target::Direct), Some(Outbound::Direct));
        assert_eq!(r.resolve(&Target::Reject), None);
        // select 组默认首个成员
        assert_eq!(
            r.resolve(&Target::Group("g_outer".into())),
            Some(Outbound::Socks5 {
                proxy: Endpoint::new("127.0.0.1", 1080),
                auth: None
            })
        );
        assert_eq!(r.resolve(&Target::Group("missing".into())), None);
    }

    /// ss2022 节点映射：env 密钥桥（AEGIS_KEY_<REF>）注入 + 缺密钥时给出
    /// 人读跳过原因（不静默）。用独立 key-ref 避免与其他测试的 env 串扰。
    #[test]
    fn ss2022_node_env_key_bridge() {
        std::env::set_var("AEGIS_KEY_SS2022_MAP", "BwcHBwcHBwcHBwcHBwcHBw==");
        let cfg = r#"
version: 1
nodes:
  - {id: s1, protocol: shadowsocks-2022, server: 127.0.0.1, port: 8388, method: 2022-blake3-aes-128-gcm, key-ref: ss2022-map}
  - {id: s2, protocol: shadowsocks-2022, server: 127.0.0.1, port: 8389, method: 2022-blake3-aes-128-gcm, key-ref: no-such-key}
groups:
  - {id: g, type: select, members: [s1, s2]}
final: g
"#;
        let p = Profile::from_yaml_str(cfg).unwrap();
        let r = Router::build(&p).unwrap();
        // s1 经 env 密钥映射成功
        assert_eq!(
            r.resolve(&Target::Group("g".into())),
            Some(Outbound::Ss2022 {
                proxy: Endpoint::new("127.0.0.1", 8388),
                method: aegis_outbound::ss2022::Ss2022Method::Aes128Gcm,
                key: vec![7u8; 16],
            })
        );
        // s2 缺密钥：跳过 + 明确原因
        assert_eq!(r.skipped_nodes().len(), 1);
        assert!(r.skipped_nodes()[0].contains("AEGIS_KEY_NO_SUCH_KEY"));
        std::env::remove_var("AEGIS_KEY_SS2022_MAP");
    }

    #[test]
    fn ss2022_without_method_is_config_error() {
        let cfg = "version: 1\nnodes:\n  - {id: s, protocol: shadowsocks-2022, server: 127.0.0.1, port: 8388, key-ref: k}\n";
        let err = Profile::from_yaml_str(cfg).unwrap_err();
        assert!(err.to_string().contains("method"));
    }

    #[test]
    fn manual_selection_via_router() {
        let r = router();
        // 手动锁定到 n2，解锁后停在 n2
        r.set_manual("g_outer", "n2").unwrap();
        assert_eq!(
            r.resolve(&Target::Group("g_outer".into())),
            Some(Outbound::Http {
                proxy: Endpoint::new("10.0.0.1", 8080),
                auth: None
            })
        );
        let g = r.groups.get("g_outer").unwrap();
        g.clear_manual();
        assert_eq!(g.current_member().map(|m| m.id.as_str()), Some("n2"));
        // 未知组/未知成员 → 错误
        assert!(r.set_manual("nope", "n1").is_err());
        assert!(r.set_manual("g_outer", "nope").is_err());
    }

    #[test]
    fn group_statuses_snapshot() {
        let r = router();
        let s = r.group_statuses();
        let outer = s.iter().find(|g| g.id == "g_outer").unwrap();
        assert_eq!(outer.current.as_deref(), Some("n1"));
        assert_eq!(outer.members.len(), 2);
        assert!(outer.members.iter().all(|m| !m.alive)); // 尚未探活
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
