# 架构决策记录

[English](../../decisions/README.md) | 简体中文

当前实现见 [design.md](../design.md)，已落地变更见 [CHANGELOG](../../../CHANGELOG.zh-CN.md)。这里记录代码无法充分说明、维护者可能重新追问的重要取舍。

| 编号 | 决定 | 状态 |
|---|---|---|
| [0001](0001-suspended-msys-preparation.md) | 挂起创建、按导入名识别与严格原生边界 | Accepted，EXE 识别和初始化时机分别由 0012、0015 更新 |
| [0002](0002-native-console-handle-owner.md) | PSEC 内公开 ConPTY 与原生标准句柄所有者 | Accepted，会话宿主的原生 relay 由 0013 更新 |
| [0003](0003-read-only-security-context.md) | 只读安全上下文查询与冷启动 MSYS 的 token 前置检查 | Accepted，前置检查由 0018 移除 |
| [0004](0004-preserve-sandbox-object-policy.md) | 保留隔离启动器默认对象策略，恢复真实 MSYS 原生桥接回入 | Superseded by 0008 |
| [0005](0005-restricted-token-context.md) | 受限令牌沿用启动器对象 ACL，并按启动建立 MSYS 私有命名空间 | Accepted |
| [0006](0006-opt-in-native-relay.md) | 显式选择原生创建 relay，同一安全上下文内自动回入 MSYS | Accepted，默认值和位数范围由 0013 更新，token 核对由 0018 移除 |
| [0007](0007-production-artifacts.md) | 生产兼容 EXE/DLL 与可选隔离验证工具分开交付 | Accepted |
| [0008](0008-adapt-requested-object-acls.md) | 基于当次输入适配对象 ACL/默认策略，保留 ntdll 接入与早期依赖约束 | Accepted，默认 DACL 基准和进程创建适配分别由 0016、0017 更新 |
| [0009](0009-minhook-relocation-backend.md) | MinHook 核心搬迁 ntdll 入口，隔离后端并保留已有 hook 路径 | Accepted |
| [0010](0010-reserve-cygheap-at-creation.md) | 在 Windows 创建进程时预留 MSYS cygheap 原址 | Superseded by 0011 |
| [0011](0011-release-heap-reservations-before-start.md) | 在 MSYS 执行前释放创建时的临时堆预留 | Accepted |
| [0012](0012-prefer-dll-image-base-at-map.md) | 在 DLL 映射时按 section 元数据尝试 PE 首选基址 | Accepted |
| [0013](0013-default-relay-with-wow64.md) | 默认启用原生创建 relay，覆盖混合位数启动链 | Accepted，token 比较特例由 0018 移除 |
| [0014](0014-conpty-preserve-redirected-stdio.md) | 自动 ConPTY 逐路保留重定向，只桥接控制台 | Accepted |
| [0015](0015-initialize-at-child-loader-entry.md) | 在子进程加载器入口初始化兼容层，保留应用启动上下文 | Accepted |
| [0016](0016-drop-relay-default-dacl-baseline.md) | relay 沿用 Windows 默认 DACL 继承，撤除历史基准和创建锁 | Accepted |
| [0017](0017-adapt-process-dacl-at-creation.md) | 创建进程和初始线程时适配调用者显式提供的 DACL | Accepted |
| [0018](0018-resolve-acl-context-in-each-process.md) | 各进程按自身主 token 初始化 ACL 适配，移除父子核对 | Accepted |

Accepted ADR 的正文不重写。决定变化时新增 ADR，在新旧记录中补充替代关系；小型实现细节由 Git 历史和变更记录表达。研究计划与未验证候选不写成 Accepted 决定。
