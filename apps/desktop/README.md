# apps/desktop（M1）

桌面 UI 壳（macOS + Windows）。**Tauri 薄壳**：前端仅通过 `aegis-api`（127.0.0.1 + token）与核心通信，不直接链接任何核心 crate。

- 核心以系统服务运行（launchd / Windows Service），UI 退出网络不断
- 信息架构见 docs/03 §5：菜单栏/托盘速览 + 完整窗口（连接/规则/配置编辑器/Git 同步）
- 状态：占位，M0 结束后启动（技术选型已定：Tauri + TS）