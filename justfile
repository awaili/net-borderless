# Aegis 常用命令入口（需安装 just: https://github.com/casey/just）

default:
    @just --list

# 编译检查全部 crate
check:
    cargo check --workspace

# 运行全部测试（crate 单测 + 集成测试）
test:
    cargo test --workspace

# 格式化
fmt:
    cargo fmt --all

# 静态检查（CI 同款，warning 即失败）
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# 许可证与依赖审计
deny:
    cargo deny check

# 以默认示例配置启动无头核心（M0 后可用）
# run:
#     cargo run -p aegis -- run -c presets/example.yaml