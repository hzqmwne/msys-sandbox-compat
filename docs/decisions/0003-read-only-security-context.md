# ADR-0003：只读安全上下文查询与 MSYS token 前置检查

Status: Accepted
Partially superseded by: ADR-0004，原生桥接后的 MSYS 冷启动已有成功兼容处理；只读上下文查询和恢复前检查继续保留。
Date: 2026-10-20
Related: ADR-0001

## Context

在受测 PSEC/MSYS 组合中，MSYS 创建的原生后代仍是 AppContainer、保留 package SID，却无法重开自身真实 token。原生匿名事件可以创建，Win32 命名事件即使显式提供私有描述符也拒绝；查询命名空间路径和在同一路径直接创建 NT 事件则成功。

实际对象 SD 的只读采样表明：初始 Bash 的 token 对象包含 package ACE，而原生后代及其再创建的冷启动 Bash token 对象缺少它。宿主仅改用伪句柄并跳过事件探针后，第二个 Bash 已能恢复，但在 MSYS 初始化时报告 token 查询失败并停住。

## Decision

宿主使用 `GetCurrentProcessToken` 完成自身只读查询，用 `GetAppContainerNamedObjectPath` 和 `TokenSessionId` 取得本次对象路径；不创建用于发现路径的命名事件，不修改 token、token 对象 SD 或默认 DACL。

对确认关联 MSYS 的根映像，在恢复初始线程前检查该进程真实 token 的 `TOKEN_QUERY` 访问。拒绝就沿现有失败路径终止目标、关闭句柄并返回明确错误。原生目标继续保持无注入，能够在继承的原生后代安全上下文中运行。

## Consequences

移除宿主对可重开 token 和 Win32 命名事件准备的非必要依赖；原生工作负载回入可用，同时 MSYS 冷启动的已知失败可在初始化前定位并回收。真实 token 前置检查是已复现拒绝的必要条件检查，不保证其余初始化步骤全部成功。

MSYS 原生桥接透明传播和受限 token 下的冷启动兼容仍不在支持范围。不能把宿主查询成功、预期拒绝通过或保留 package SID 当作整条 MSYS 链路成功。
