# ADR-0017 创建进程时适配显式 DACL

Status: Accepted
Date: 2026-11-23
Partially supersedes: [ADR-0008](0008-adapt-requested-object-acls.md) 的进程和初始线程 DACL 读回适配。

## 背景

MSYS fork 用 `sec_user_nih` 在内存中为新进程和初始线程组装显式安全描述符，再传给 `CreateProcessW`。fork 恢复时跳过冷启动的进程 DACL 设置，而信号发送方随后需要按 PID 以 `PROCESS_DUP_HANDLE` 重开目标。只移除创建后修正的对照使 PSEC 和 FullRestricted 中的跨进程信号失败。

## 决定

受限上下文启用 `process-dacl` 时，在 `NtCreateUserProcess` 原始调用前检查两个对象属性中的显式 DACL。使用 ADR-0008 的转换规则，需要调整时用临时属性副本传递修改后的描述符。MSYS 和仍处于传播链中的原生创建调用使用同一规则。该路径按输入和模块状态决定是否适配，省去 DACL 适配所需的目标映像识别及创建后的对象 DACL 查询和写回。

描述符缺省时由 Windows 使用默认 DACL。独立启动器也沿用这个创建语义。MSYS 运行时通过 `NtSetSecurityObject` 重设自身进程的 DACL 时，继续走独立的设置入口。

## 验证

Release 定向回归覆盖普通启动及混合位数 relay、模块开关、PSEC ConPTY、PSEC 和 FullRestricted 的显式回入及 relay 进程链，以及共享 ACL 转换。原生 PSEC 对照给进程和初始线程显式传入同一份 DACL。模块开启时，创建者在恢复前可以重开两者。模块关闭时两个重开均返回拒绝访问。两种情况下，调用者输入均保持原样，初始线程挂起计数均为 1。
