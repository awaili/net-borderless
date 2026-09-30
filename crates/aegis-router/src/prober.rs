//! 探活调度器（PRD F3）——双探针 + 摘除回融退避。
//!
//! 探针：
//! - TCP 探针：经出站全链路（含代理握手）建立到探活目标的连接，耗时即 RTT
//! - HTTP 首字节探针：`http://` 探活 URL 在 TCP 之上再发 `GET` 测首字节，
//!   更接近真实网页体验；`https://` M0 无 TLS 探活，仅 TCP 探针
//!
//! 摘除回融（[`REMOVAL_BACKOFF`]）：探活失败即摘除（选路立即绕开），之后按
//! 30s → 60s → 120s（封顶）退避重探，成功即回融——快摘慢回，避免抖动成员
//! 反复进出造成连接颠簸。
//!
//! 调度：每组一个任务（`Router::start_probers` 拉起），组内成员按各自的
//! `next_probe` 到期探活；探完一轮重算选中并推送 [`ProberEvent`]。
//!
//! 锁纪律：**任何 RwLock 都不跨 await 持有**——先读快照、释放锁、
//! 异步探活、再短锁写回。

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedSender;

use aegis_config::GroupType;
use aegis_outbound::{Endpoint, Outbound};

use crate::group::{GroupRuntime, MemberState, ProbeTarget, REMOVAL_BACKOFF};

/// 探活调度器推给观测层的事件（aegis-observe 接入前的临时形态，bin 打印）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProberEvent {
    /// 组选中切换
    Switched {
        group: String,
        from: String,
        to: String,
        /// "更低延迟" / "故障转移" / "当前选中已摘除"
        reason: &'static str,
    },
    /// 成员被摘除
    Removed {
        group: String,
        member: String,
        error: String,
    },
    /// 成员回融
    Revived {
        group: String,
        member: String,
        rtt: Duration,
    },
}

/// 单次探活：返回探得的 RTT。
async fn probe_once(outbound: &Outbound, target: &ProbeTarget) -> Result<Duration, String> {
    let t0 = Instant::now();
    let mut s = outbound
        .connect(&Endpoint::new(target.host.clone(), target.port))
        .await
        .map_err(|e| e.to_string())?;
    let mut rtt = t0.elapsed(); // TCP 探针：出站全链路（含代理握手）耗时
    if !target.tls {
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: aegis-probe\r\nConnection: close\r\n\r\n",
            target.path, target.host
        );
        s.write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut b = [0u8; 1];
        s.read(&mut b).await.map_err(|e| e.to_string())?;
        rtt = t0.elapsed(); // HTTP 首字节探针
    }
    Ok(rtt)
}

/// 摘除后的下次探活时刻：按连续失败次数走退避序列。
fn next_probe_after_fail(now: Instant, fails: u32) -> Instant {
    let delay = REMOVAL_BACKOFF[(fails as usize - 1).min(REMOVAL_BACKOFF.len() - 1)];
    now + delay
}

/// 单组调度任务。`tx` 关闭（接收方退出）时结束。
pub async fn run_group(group: Arc<GroupRuntime>, tx: UnboundedSender<ProberEvent>) {
    let target = match ProbeTarget::parse(&group.probe_url) {
        Ok(t) => t,
        Err(e) => {
            // 配置错误在加载期就该拦截；这里兜底并放弃该组探活
            let _ = tx.send(ProberEvent::Removed {
                group: group.id().to_string(),
                member: "(整组)".into(),
                error: format!("探活 URL 非法: {e}"),
            });
            return;
        }
    };

    loop {
        // 1) 快照：最近到期时刻 + 到期成员
        let (next_due, due) = {
            let states = group.states.read().unwrap();
            let now = Instant::now();
            let due: Vec<usize> = states
                .iter()
                .enumerate()
                .filter(|(_, s)| s.next_probe <= now)
                .map(|(i, _)| i)
                .collect();
            let next_due = states
                .iter()
                .map(|s| s.next_probe)
                .min()
                .unwrap_or(now + group.interval);
            (next_due, due)
        };
        if due.is_empty() {
            tokio::time::sleep_until(tokio::time::Instant::from_std(next_due)).await;
            continue;
        }

        // 2) 逐个探活到期成员（不持锁）
        for i in due {
            let (prev_alive, prev_fails) = {
                let states = group.states.read().unwrap();
                (states[i].alive, states[i].fails)
            };
            match probe_once(&group.members[i].outbound, &target).await {
                Ok(rtt) => {
                    let revived = !prev_alive;
                    let member_id = group.members[i].id.clone();
                    {
                        let mut states = group.states.write().unwrap();
                        states[i] = MemberState {
                            rtt: Some(rtt),
                            alive: true,
                            fails: 0,
                            next_probe: Instant::now() + group.interval,
                        };
                    }
                    if revived {
                        let _ = tx.send(ProberEvent::Revived {
                            group: group.id().to_string(),
                            member: member_id,
                            rtt,
                        });
                    }
                }
                Err(e) => {
                    let removed = prev_alive;
                    let fails = prev_fails + 1;
                    let member_id = group.members[i].id.clone();
                    {
                        let mut states = group.states.write().unwrap();
                        states[i].alive = false;
                        states[i].rtt = None;
                        states[i].fails = fails;
                        states[i].next_probe = next_probe_after_fail(Instant::now(), fails);
                    }
                    if removed {
                        let _ = tx.send(ProberEvent::Removed {
                            group: group.id().to_string(),
                            member: member_id,
                            error: e,
                        });
                    }
                }
            }
        }

        // 3) 重算选中并推送切换事件
        recompute_selection(&group, &tx);
    }
}

/// 探完一轮后的选中重算（组类型决定语义）。
fn recompute_selection(group: &GroupRuntime, tx: &UnboundedSender<ProberEvent>) {
    match group.group_type {
        GroupType::UrlTest => {
            if let Some(i) = group.recompute_url_test() {
                switch_to(group, tx, i, "更低延迟");
            }
        }
        GroupType::Fallback | GroupType::Smart => {
            // pick() 已把 first_alive 写进 current；这里只为发事件
            let before = group.current();
            group.pick();
            if group.current() != before {
                let reason = "故障转移";
                let to = group
                    .current_member()
                    .map(|m| m.id.clone())
                    .unwrap_or_default();
                let from = group
                    .members
                    .get(before)
                    .map(|m| m.id.clone())
                    .unwrap_or_default();
                let _ = tx.send(ProberEvent::Switched {
                    group: group.id().to_string(),
                    from,
                    to,
                    reason,
                });
            }
        }
        // select 由人决策；load-balance 在选路时轮转，无"当前选中"概念
        GroupType::Select | GroupType::LoadBalance => {}
    }
}

fn switch_to(
    group: &GroupRuntime,
    tx: &UnboundedSender<ProberEvent>,
    to_idx: usize,
    reason: &'static str,
) {
    let from = group
        .current_member()
        .map(|m| m.id.clone())
        .unwrap_or_default();
    let to = group.members[to_idx].id.clone();
    if from == to {
        return;
    }
    group.set_current(to_idx);
    let _ = tx.send(ProberEvent::Switched {
        group: group.id().to_string(),
        from,
        to,
        reason,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{GroupRuntime, Member};
    use aegis_config::GroupType;

    /// 本地探活目标：接受连接即回一个字节（HTTP 首字节探针即可完成）。
    async fn probe_server() -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = l.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 128];
                    let _ = c.read(&mut buf).await;
                    let _ = c.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn fallback_probes_revives_and_fails_over() {
        let good = probe_server().await;
        // bad 成员的出站本身不可达：SOCKS5 指向无人监听的端口
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let members = vec![
            Member {
                id: "bad".into(),
                outbound: Outbound::Socks5 {
                    proxy: Endpoint::new("127.0.0.1", dead_port),
                    auth: None,
                },
            },
            Member {
                id: "good".into(),
                outbound: Outbound::Direct,
            },
        ];
        let url = format!("http://127.0.0.1:{}/204", good.port());
        let group = Arc::new(GroupRuntime::new(
            "g".into(),
            GroupType::Fallback,
            members,
            url,
            Duration::from_millis(80),
            Duration::from_millis(50),
        ));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run_group(group.clone(), tx));

        // 给调度器跑一轮
        tokio::time::sleep(Duration::from_millis(400)).await;
        task.abort();

        let mut revived = false;
        let mut switched = false;
        while let Ok(ev) = rx.try_recv() {
            match ev {
                ProberEvent::Revived { member, .. } if member == "good" => revived = true,
                ProberEvent::Switched { to, reason, .. }
                    if to == "good" && reason == "故障转移" =>
                {
                    switched = true;
                }
                _ => {}
            }
        }
        assert!(revived, "good 成员应回融");
        assert!(switched, "bad 摘除后应故障转移到 good");
        assert_eq!(group.pick(), Some(1));
        let states = group.states.read().unwrap();
        assert!(!states[0].alive, "bad 应被摘除");
        assert!(
            states[1].alive && states[1].rtt.is_some(),
            "good 应存活且带 RTT"
        );
    }

    #[tokio::test]
    async fn url_test_switches_when_current_is_removed() {
        // url-test 的 RTT 排序与容忍度逻辑由 group.rs 纯单测覆盖；
        // 这里验证调度器整链：初始 current=0 在首轮被摘除（探活目标不可达），
        // 存活的 fast 被选中并发送 Switched 事件。
        let good = probe_server().await;
        // dead 成员的出站本身不可达：SOCKS5 指向无人监听的端口
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let members = vec![
            Member {
                id: "dead".into(),
                outbound: Outbound::Socks5 {
                    proxy: Endpoint::new("127.0.0.1", dead_port),
                    auth: None,
                },
            },
            Member {
                id: "fast".into(),
                outbound: Outbound::Direct,
            },
        ];
        let url = format!("http://127.0.0.1:{}/204", good.port());
        let group = Arc::new(GroupRuntime::new(
            "g".into(),
            GroupType::UrlTest,
            members,
            url,
            Duration::from_millis(80),
            Duration::from_millis(50),
        ));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run_group(group.clone(), tx));
        tokio::time::sleep(Duration::from_millis(400)).await;
        task.abort();

        let mut switched = false;
        while let Ok(ev) = rx.try_recv() {
            if let ProberEvent::Switched { to, .. } = ev {
                if to == "fast" {
                    switched = true;
                }
            }
        }
        assert!(switched, "初始选中被摘除后应切换到存活成员");
        assert_eq!(group.pick(), Some(1));
    }

    #[test]
    fn backoff_schedule() {
        let now = Instant::now();
        assert_eq!(next_probe_after_fail(now, 1), now + Duration::from_secs(30));
        assert_eq!(next_probe_after_fail(now, 2), now + Duration::from_secs(60));
        assert_eq!(
            next_probe_after_fail(now, 3),
            now + Duration::from_secs(120)
        );
        assert_eq!(
            next_probe_after_fail(now, 99),
            now + Duration::from_secs(120)
        );
    }
}
