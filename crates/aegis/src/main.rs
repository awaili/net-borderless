//! # aegis（bin）
//!
//! 无头核心 + CLI（架构 L4）：
//! - `aegis run -c <profile.yaml>`：启动守护进程（桌面系统服务模式 / 手动前台模式）
//! - `aegis status`：经本地 API 查询状态
//! - `aegis diag`：触发一键诊断并输出报告
//! - `aegis import <file>`：导入 sing-box / Clash 配置
//!
//! M0 阶段本入口即验证载体（无 GUI）；M1 起桌面 UI 通过本地 API 消费本进程。

fn main() {
    println!(
        "aegis {} — Aegis core engine (work in progress)",
        env!("CARGO_PKG_VERSION")
    );
}
