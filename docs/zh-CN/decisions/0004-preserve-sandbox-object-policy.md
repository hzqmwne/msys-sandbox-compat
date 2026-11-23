# ADR-0004：保留隔离启动器的默认对象策略以恢复真实 MSYS 链路

[English](../../decisions/0004-preserve-sandbox-object-policy.md)

Status: Accepted
Superseded by: ADR-0008，基于当次输入补充授权，不再整份恢复启动快照。下文保留原决策背景。
Date: 2026-10-20
Supersedes: ADR-0001 的完全不干预 token 默认 DACL 约定；ADR-0003 的 MSYS 原生后代只能拒绝回入的能力边界。只读上下文查询及恢复前错误检查继续保留。

## Context

目标是让真实 MSYS 程序及其进程链在隔离环境正常运行。仅绕过宿主查询或将失败提前报告，不能完成 Bash 经原生工具再进入 Bash/Perl 的工作负载。

受测 MSYS 的冷启动将默认对象 DACL 替换为普通用户模板，丢掉隔离启动器原先设置的 package/logon 授权。原生后代的 token 对象随之缺少相应访问，导致下一次 MSYS 冷启动失败。隔离启动器的初始 ACL 已经能支持首次 MSYS 启动。

## Decision

宿主保存隔离环境初始 `TokenDefaultDacl`。仅在确认的 MSYS 进程内增加 `NtSetInformationToken` hook；当目标是当前主 token、信息类是 `TokenDefaultDacl` 时，使用保存的初始 ACL 执行原系统调用。其他 token 和信息类原样传递。

保留 token 身份、能力、受限 SID、权限和文件策略，不加入任意额外 SID，不改安装目录 ACL。原生进程在默认模式不注入。调用者仍显式使用兼容入口覆盖原生工具后的 MSYS 创建边界。

## Consequences

MSYS 的默认对象策略与隔离启动器保持一致，原生后代和再次冷启动的 MSYS 可重开所需对象。hook 数由八个增为九个，接受这一变化以满足实际兼容目标。

回归以真实工作负载成功为准：原生入口、Bash、多层未注入的原生工具、再次进入 Bash/Perl、fork、二级线程 fork、管道、读写拒绝边界与退出码。显式对象描述符仍由现有对象 hook 处理，默认 ACL 保留不能代替它们。
