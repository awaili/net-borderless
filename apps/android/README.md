# apps/android（M1 · 首个移动端交付）

Android 端：`VpnService` + 前台服务。

- 核心编译为 `aarch64-linux-android` 动态库（uni-FFI/JNI 绑定），配置加密走 Keystore
- 凭据（订阅 URL、节点密钥）只存 Keystore，配置库只存引用 ID
- 信息架构：状态/连接/规则三 Tab + 首次配置向导（docs/03 §2–3）——**移动端 UX 在此定型，iOS 继承**
- 分发：GitHub Releases 侧载内测（M1，免审核快速迭代）→ Play 内部测试 → 1.0 全球上架（不含中国大陆区）
- M0 前置项：`aarch64-linux-android` 交叉编译链路 + uni-FFI 边界冻结（docs/04 M0 验收门）
- 真机矩阵验收（M1）：Android 10–16，≥ 6 机型（含国产 ROM：MIUI/EMUI 等激进省电策略适配）

状态：占位，M0 核心验证后启动。