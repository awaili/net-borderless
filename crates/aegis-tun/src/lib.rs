//! # aegis-tun
//!
//! TUN 设备抽象（架构 L0）。
//!
//! 统一抽象：
//! ```text
//! TunDevice: 读包循环 / 写包 / 默认路由接管 / 平台包过滤（kill switch 兜底）
//! ```
//!
//! 规划模块（`cfg(target_os)` 切分，见 docs/05 §1 的合并说明）：
//! - `apple.rs`：utun（iOS NetworkExtension / macOS SystemExtension 共用）
//! - `windows.rs`：wintun（核心跑 Windows Service，UI 仅是客户端）
//! - `linux.rs`：/dev/net/tun
//! - `android.rs`：VpnService fd
//!
//! iOS 内存预算（目标 < 40MB）：TUN 缓冲 + 连接表（5k 上限）合计 < 8MB（docs/02 §5）。
