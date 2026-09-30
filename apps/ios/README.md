# apps/ios（M2）

iOS App + Packet Tunnel Provider。

- Rust 核心编译为 aarch64-apple-ios staticlib（`aegis-tun` 的 apple 模块 + cbindgen FFI 头）
- App ↔ NE 扩展：App Group + 本地 API（契约同桌面，见 aegis-api）
- NE 内存预算 < 40MB（分解表见 docs/02 §5）；崩溃 fail-closed（TUN 默认路由仍在 → 黑洞而非裸奔）
- 信息架构：状态/连接/规则三 Tab + 首次配置向导（docs/03 §2–3）
- 状态：占位，M1 公测验证后启动