//! # aegis-config
//!
//! 配置层（PRD F7 / 架构 L0）：
//! - 声明式 YAML schema（`Profile`），多 Profile 管理，热重载（diff 事件）
//! - 生态导入：sing-box JSON / Clash YAML / 标准 URI 订阅（`import/`）
//! - 凭据不落盘：敏感字段在加载后立即交由平台 Keychain 引用替换（与 aegis-observe 存储约定对齐）
//!
//! 规划模块：
//! - `schema/`：类型定义与校验（serde，schema 变更须同步 `presets/example.yaml`）
//! - `reload/`：文件监听与热重载 diff 事件
//! - `import/`：sing-box / Clash / 订阅 URI 导入器（导入为只读副本）
