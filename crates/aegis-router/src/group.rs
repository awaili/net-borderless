//! 策略组运行时（PRD F3）——构建一次，选路读写分离。
//!
//! 选路语义：
//! - `select`：手动锁定优先，否则用当前选中（初始为首个成员）；
//!   [`GroupRuntime::set_manual`] / [`GroupRuntime::clear_manual`] 是 UI 手动切换的入口
//! - `url-test`：探活调度器维护 `current`（最低 RTT + 容忍度防抖动，见 prober）
//! - `fallback`：按成员顺序取首个存活；全灭时仍用 `current`（总比拒绝好）
//! - `load-balance`：存活成员间轮转
//! - `smart`：P1；M0 行为同 fallback（构建期配置层已给 P1 提示）
//!
//! 探活状态（[`MemberState`]）与 `members` 下标平行，探活调度器独占写，
//! 选路只读——读多写少，`RwLock` 足够（无争用热点）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use aegis_config::GroupType;
use aegis_outbound::Outbound;

pub const DEFAULT_PROBE_URL: &str = "http://www.gstatic.com/generate_204";
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(300);
pub const DEFAULT_TOLERANCE: Duration = Duration::from_millis(50);
/// 摘除回融退避序列：失败后 30s → 60s → 120s（封顶）再探
pub const REMOVAL_BACKOFF: [Duration; 3] = [
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
];

/// 组成员：节点 id（或嵌套组展开而来的成员）+ 对应出站。
#[derive(Debug, Clone)]
pub struct Member {
    pub id: String,
    pub outbound: Outbound,
}

/// 单成员探活状态（与 `members` 下标平行；探活调度器独占写）。
#[derive(Debug, Clone)]
pub struct MemberState {
    /// 最近一次成功探活的往返延迟
    pub rtt: Option<Duration>,
    pub alive: bool,
    /// 连续失败次数（驱动 [`REMOVAL_BACKOFF`] 退避）
    pub fails: u32,
    /// 下次应探活时刻
    pub next_probe: Instant,
}

/// 探活目标（从组配置的 `url` 解析）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
    /// https:// 时仅 TCP 连接探针（M0 无 TLS 探活）；http:// 加测 HTTP 首字节
    pub tls: bool,
}

impl ProbeTarget {
    /// 解析探活 URL。只接受 http/https，其余报错（探活 URL 配错要在加载期发现）。
    pub fn parse(url: &str) -> Result<Self, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| format!("探活 URL 缺少 scheme: {url}"))?;
        let tls = match scheme {
            "http" => false,
            "https" => true,
            other => return Err(format!("探活 URL 协议必须是 http/https，收到 {other}")),
        };
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, format!("/{p}")),
            None => (rest, "/".to_string()),
        };
        if authority.is_empty() {
            return Err(format!("探活 URL 主机为空: {url}"));
        }
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| format!("探活 URL 端口非法: {p}"))?,
            ),
            None => (authority.to_string(), default_port),
        };
        Ok(Self {
            host,
            port,
            path,
            tls,
        })
    }
}

/// 组运行时。
#[derive(Debug)]
pub struct GroupRuntime {
    id: String,
    pub group_type: GroupType,
    pub members: Vec<Member>,
    /// 当前选中成员下标（url-test 由探活维护；select 手动切换也写这里）
    current: RwLock<usize>,
    /// select/url-test 的手动锁定（下标）
    manual: RwLock<Option<usize>>,
    /// 探活状态（与 members 平行）
    pub states: RwLock<Vec<MemberState>>,
    /// load-balance 轮转计数
    rr: AtomicU64,
    pub probe_url: String,
    pub interval: Duration,
    pub tolerance: Duration,
}

impl GroupRuntime {
    pub fn new(
        id: String,
        group_type: GroupType,
        members: Vec<Member>,
        probe_url: String,
        interval: Duration,
        tolerance: Duration,
    ) -> Self {
        let n = members.len();
        let now = Instant::now();
        Self {
            id,
            group_type,
            members,
            current: RwLock::new(0),
            manual: RwLock::new(None),
            states: RwLock::new(
                (0..n)
                    .map(|_| MemberState {
                        rtt: None,
                        alive: false, // 探活确认前不算存活
                        fails: 0,
                        next_probe: now,
                    })
                    .collect(),
            ),
            rr: AtomicU64::new(0),
            probe_url,
            interval,
            tolerance,
        }
    }

    /// 组 id（事件/诊断展示用）。
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 选中成员下标（`None` = 组内没有可用成员）。
    pub fn pick(&self) -> Option<usize> {
        if self.members.is_empty() {
            return None;
        }
        match self.group_type {
            GroupType::Select | GroupType::UrlTest => {
                if let Some(m) = *self.manual.read().unwrap() {
                    return Some(m);
                }
                Some(*self.current.read().unwrap())
            }
            // fallback / smart（M0 同 fallback）：按顺序取首个存活；全灭时仍取 current
            GroupType::Fallback | GroupType::Smart => {
                if let Some(i) = self.first_alive() {
                    if i != *self.current.read().unwrap() {
                        *self.current.write().unwrap() = i;
                    }
                    return Some(i);
                }
                Some(*self.current.read().unwrap())
            }
            GroupType::LoadBalance => {
                let alive: Vec<usize> = self
                    .states
                    .read()
                    .unwrap()
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.alive)
                    .map(|(i, _)| i)
                    .collect();
                if alive.is_empty() {
                    return Some(*self.current.read().unwrap());
                }
                let n = self.rr.fetch_add(1, Ordering::Relaxed) as usize % alive.len();
                Some(alive[n])
            }
        }
    }

    /// 成员 id 查下标。
    pub fn member_index(&self, id: &str) -> Option<usize> {
        self.members.iter().position(|m| m.id == id)
    }

    /// 手动锁定选中成员（UI 手动切换）。对 url-test 组同样生效：锁定即停止
    /// 自动切换，直到 [`GroupRuntime::clear_manual`]。
    pub fn set_manual(&self, id: &str) -> Result<(), String> {
        let i = self
            .member_index(id)
            .ok_or_else(|| format!("组内没有成员 {id}"))?;
        *self.manual.write().unwrap() = Some(i);
        *self.current.write().unwrap() = i;
        Ok(())
    }

    /// 解除手动锁定，恢复自动选路。
    pub fn clear_manual(&self) {
        *self.manual.write().unwrap() = None;
    }

    /// 探活调度器专用：直接改 current（不经 manual）。
    pub fn set_current(&self, i: usize) {
        *self.current.write().unwrap() = i;
    }

    pub fn current(&self) -> usize {
        *self.current.read().unwrap()
    }

    /// 当前选中成员 id（诊断展示用）。
    pub fn current_member(&self) -> Option<&Member> {
        self.members.get(self.current())
    }

    fn first_alive(&self) -> Option<usize> {
        self.states.read().unwrap().iter().position(|s| s.alive)
    }

    /// url-test 重算选中（纯决策，供探活调度器在探完一轮后调用）：
    /// 存活成员中 RTT 最低者；与 current 的差距小于容忍度不切换（防抖动）。
    /// 返回 `Some(新下标)` 表示需要切换。
    pub fn recompute_url_test(&self) -> Option<usize> {
        let states = self.states.read().unwrap();
        let best = states
            .iter()
            .enumerate()
            .filter(|(_, s)| s.alive && s.rtt.is_some())
            .min_by_key(|(_, s)| s.rtt.unwrap())
            .map(|(i, _)| i)?;
        let current = *self.current.read().unwrap();
        if !states.get(current).is_some_and(|s| s.alive) {
            return Some(best); // 当前选中已摘除，必须切
        }
        let cur_rtt = states[current].rtt?;
        if states[best].rtt.unwrap() + self.tolerance < cur_rtt {
            return Some(best);
        }
        None
    }
}

/// url-test 选路纯决策函数的语义快照（诊断/UI 展示用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupStatus {
    pub id: String,
    pub group_type: GroupType,
    pub current: Option<String>,
    pub members: Vec<MemberStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberStatus {
    pub id: String,
    pub rtt: Option<Duration>,
    pub alive: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &str) -> Member {
        Member {
            id: id.into(),
            outbound: Outbound::Direct,
        }
    }

    fn rt(group_type: GroupType, ids: &[&str]) -> GroupRuntime {
        GroupRuntime::new(
            "g".into(),
            group_type,
            ids.iter().map(|i| member(i)).collect(),
            DEFAULT_PROBE_URL.into(),
            Duration::from_millis(100),
            Duration::from_millis(50),
        )
    }

    fn set_alive(g: &GroupRuntime, idx: usize, alive: bool, rtt: Option<Duration>) {
        let mut s = g.states.write().unwrap();
        s[idx].alive = alive;
        s[idx].rtt = rtt;
    }

    #[test]
    fn empty_group_picks_none() {
        let g = rt(GroupType::Select, &[]);
        assert_eq!(g.pick(), None);
    }

    #[test]
    fn select_defaults_to_first_then_manual() {
        let g = rt(GroupType::Select, &["a", "b"]);
        assert_eq!(g.pick(), Some(0));
        g.set_manual("b").unwrap();
        assert_eq!(g.pick(), Some(1));
        g.clear_manual();
        // 手动切换会同步 current，解除锁定后停在手动位置（与 Shadowrocket 一致）
        assert_eq!(g.pick(), Some(1));
    }

    #[test]
    fn select_manual_unknown_member_is_error() {
        let g = rt(GroupType::Select, &["a"]);
        assert!(g.set_manual("nope").is_err());
    }

    #[test]
    fn fallback_first_alive_then_current_when_all_dead() {
        let g = rt(GroupType::Fallback, &["a", "b"]);
        assert_eq!(g.pick(), Some(0)); // 全灭时仍用 current
        set_alive(&g, 1, true, Some(Duration::from_millis(10)));
        assert_eq!(g.pick(), Some(1));
        set_alive(&g, 0, true, Some(Duration::from_millis(10)));
        assert_eq!(g.pick(), Some(0)); // 顺序优先，不看 RTT
    }

    #[test]
    fn load_balance_rotates_among_alive() {
        let g = rt(GroupType::LoadBalance, &["a", "b"]);
        set_alive(&g, 0, true, None);
        set_alive(&g, 1, true, None);
        let picks: Vec<usize> = (0..4).map(|_| g.pick().unwrap()).collect();
        assert_eq!(picks, vec![0, 1, 0, 1]);
        // 存活集合收窄时只在存活内轮转
        set_alive(&g, 0, false, None);
        assert_eq!(g.pick(), Some(1));
        assert_eq!(g.pick(), Some(1));
    }

    #[test]
    fn url_test_recompute_respects_tolerance() {
        let g = rt(GroupType::UrlTest, &["a", "b"]);
        // 初始 current=0(a)，但 a 未探活 → 必须切到存活的 b
        set_alive(&g, 1, true, Some(Duration::from_millis(200)));
        assert_eq!(g.recompute_url_test(), Some(1));
        g.set_current(1); // 调度器应用切换

        // a 回融且明显更快 → 切回 a
        set_alive(&g, 0, true, Some(Duration::from_millis(80)));
        assert_eq!(g.recompute_url_test(), Some(0));
        g.set_current(0);

        // b 稍快但差距在容忍度(50ms)内 → 不切换（防抖动）
        set_alive(&g, 1, true, Some(Duration::from_millis(50)));
        assert_eq!(g.recompute_url_test(), None);

        // 差距超过容忍度 → 切换
        set_alive(&g, 1, true, Some(Duration::from_millis(20)));
        assert_eq!(g.recompute_url_test(), Some(1));
    }

    #[test]
    fn probe_target_parse() {
        let t = ProbeTarget::parse("http://www.gstatic.com/generate_204").unwrap();
        assert_eq!(
            t,
            ProbeTarget {
                host: "www.gstatic.com".into(),
                port: 80,
                path: "/generate_204".into(),
                tls: false
            }
        );
        let t = ProbeTarget::parse("https://cp.cloudflare.com:8443/").unwrap();
        assert_eq!(
            t,
            ProbeTarget {
                host: "cp.cloudflare.com".into(),
                port: 8443,
                path: "/".into(),
                tls: true
            }
        );
        assert!(ProbeTarget::parse("ftp://x/").is_err());
        assert!(ProbeTarget::parse("http:///path").is_err());
        assert!(ProbeTarget::parse("http://h:bad/").is_err());
    }
}
