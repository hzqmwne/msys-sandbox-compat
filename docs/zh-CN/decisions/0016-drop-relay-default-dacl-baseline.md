# ADR-0016：relay 沿用 Windows 的默认 DACL 继承

Status: Accepted

Date: 2026-11-23

Partially supersedes: [ADR-0006](0006-opt-in-native-relay.md)、[ADR-0008](0008-adapt-requested-object-acls.md) 和 [ADR-0013](0013-default-relay-with-wow64.md) 的默认 DACL 比较。

Partially superseded by: [ADR-0018](0018-resolve-acl-context-in-each-process.md) 移除其余父子 token 比较。

## 决定

MSYS 调用 `NtSetInformationToken` 设置当前主 token 的默认 DACL 时，兼容层按当次输入适配，由 Windows 检查权限并执行设置。relay 沿用 Windows 对子 token 默认 DACL 的继承语义，合法的默认 DACL 变化可以随进程继续传播。删除历史 DACL 基准、设置后的读回和用于同步该基准的创建锁。

relay 当前仍携带用户 SID、受限主体 SID 和命名空间等配置，因此继续比较父子安全上下文。进程和初始线程对象的 DACL 适配仍按 `process-dacl` 模块执行。
