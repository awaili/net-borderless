//! # aegis-inbound
//!
//! 入站层（架构 L0）：
//! - mixed / http / socks5 本地监听，产出统一的入站连接事件交给 aegis-router
//! - 与 aegis-tun 并列：一个是显式代理入站，一个是 TUN 全量入站
