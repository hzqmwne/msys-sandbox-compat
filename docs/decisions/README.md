# 架构决策记录

当前实现见 [design.md](../design.md)，已落地变更见 [CHANGELOG](../../CHANGELOG.md)。这里记录代码无法充分说明、维护者可能重新追问的重要取舍。

| 编号 | 决定 | 状态 |
|---|---|---|
| [0001](0001-suspended-msys-preparation.md) | 挂起创建、按导入名识别与严格原生边界 | Accepted |
| [0002](0002-native-console-handle-owner.md) | PSEC 内公开 ConPTY 与原生标准句柄所有者 | Accepted |
| [0003](0003-read-only-security-context.md) | 只读安全上下文查询与冷启动 MSYS 的 token 前置检查 | Accepted |
| [0004](0004-preserve-sandbox-object-policy.md) | 保留隔离启动器默认对象策略，恢复真实 MSYS 原生桥接回入 | Accepted |
| [0005](0005-restricted-token-context.md) | 受限令牌沿用启动器对象 ACL，并按启动建立 MSYS 私有命名空间 | Accepted |
| [0006](0006-opt-in-native-relay.md) | 显式选择原生创建 relay，同一安全上下文内自动回入 MSYS | Accepted |

Accepted ADR 的正文不重写。决定变化时新增 ADR，在新旧记录中补充替代关系；小型实现细节由 Git 历史和变更记录表达。研究计划与未验证候选不写成 Accepted 决定。
