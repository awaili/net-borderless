//! # aegis（bin）
//!
//! 无头核心 + CLI（架构 L4）。
//!
//! 已实现：`aegis run -c <profile.yaml>`——加载配置 → 构建 Router →
//! 监听 mixed 入站 → 每连接打印一行分流报告（proto-可观测性）。
//!
//! 待办：`aegis status` / `aegis diag` / `aegis import`（经本地 API，M0 后续批次）。

use std::process::ExitCode;
use std::sync::Arc;

use aegis_config::Profile;
use aegis_inbound::read_request;
use aegis_router::Router;
use tokio::net::{TcpListener, TcpStream};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") => {
            let config = args
                .iter()
                .position(|a| a == "-c" || a == "--config")
                .and_then(|i| args.get(i + 1))
                .cloned();
            let Some(config) = config else {
                eprintln!("用法: aegis run -c <profile.yaml>");
                return ExitCode::from(2);
            };
            match tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(run(&config))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("错误: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            println!(
                "aegis {} — Aegis core engine (work in progress)
用法:
  aegis run -c <profile.yaml>    启动无头核心（mixed 入站）",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::from(2)
        }
    }
}

async fn run(config: &str) -> Result<(), Box<dyn std::error::Error>> {
    let profile = Profile::from_path(config)?;

    println!(
        "aegis {} · 配置 {config}: {} 节点 / {} 策略组 / {} 条规则 / 兜底 {}",
        env!("CARGO_PKG_VERSION"),
        profile.nodes.len(),
        profile.groups.len(),
        profile.rules.len(),
        profile
            .fallback
            .clone()
            .unwrap_or_else(|| "REJECT(缺省)".into())
    );
    for w in &profile.warnings {
        println!("  ⚠ {}", w.message);
    }

    let router = Arc::new(Router::build(&profile)?);
    for skipped in router.skipped_nodes() {
        println!("  ⚠ 节点被跳过: {skipped}");
    }

    let listen = match (profile.inbound.mixed.enabled, &profile.inbound.mixed.listen) {
        (true, Some(l)) => l.clone(),
        _ => return Err("未启用 mixed 入站（inbound.mixed.enabled + listen 必填）".into()),
    };
    let listener = TcpListener::bind(&listen).await?;
    println!("mixed 入站监听 {listen}（socks5 + http CONNECT）");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("accept 失败: {e}");
                continue;
            }
        };
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(stream, router, peer).await {
                eprintln!("  [{peer}] 关闭: {e}");
            }
        });
    }
}

async fn serve(
    mut stream: TcpStream,
    router: Arc<Router>,
    peer: std::net::SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let req = read_request(&mut stream).await?;
    let report = router.handle(&req.target, &mut stream, req.via).await?;
    let rule = match report.rule_index {
        Some(i) => format!("规则#{i}"),
        None => "final".to_string(),
    };
    println!(
        "[{peer}] {} → {}（{}，{}） ↑{} ↓{}",
        report.target,
        aegis_router::target_desc(&report.decision),
        rule,
        report.via,
        humanize(report.bytes_up),
        humanize(report.bytes_down),
    );
    Ok(())
}

fn humanize(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n}B")
    } else {
        format!("{v:.1}{}", UNITS[u])
    }
}
