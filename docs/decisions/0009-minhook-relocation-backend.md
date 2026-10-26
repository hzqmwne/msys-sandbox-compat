# ADR-0009：以 MinHook 核心搬迁 ntdll 入口，隔离后端接口

状态：Accepted，2026-10-26。接续 [ADR-0008](0008-adapt-requested-object-acls.md) 的早期运行依赖约束。

## 背景

原安装器只接受 `mov r10,rcx; mov eax,imm32`，固定搬迁八字节。它未硬编码 syscall 编号，但仍依赖 ntdll 入口的特定机器码，无法处理其他合法前导及已有 inline hook。用户选择先以 MinHook 成熟的解码与搬迁核心解决当前 ntdll 入口，同时保留未来切换 Detours 的选择。

## 决定

固定 MinHook v1.3.4，revision `c3fcafdc10146beb5919319d0683e44e3c30d537`。vendor 原样 HDE64 源码及相关头，基于其 `trampoline.c` 适配 AMD64 搬迁后端；不引入完整 hook 管理器、分配器和线程管理。保留完整 BSD 两条款许可及 HDE 版权，随安装包交付。

公开 `inline_hook.h` 只包含源字节及有效长度、源/目标/handler VA、固定容量的搬迁计划与错误类别，不暴露 MinHook 类型。后端只做纯计划，不解引用目标进程地址。CMake 的 `add_compat_hook_backend` 集中选择实现；宿主与 agent 仍按各自的运行时约束分别编译。未来 Detours 后端保留该计划接口及入口补丁约定，进程传播代码无需更换。

安装器负责查询目标进程的可读可执行区域、有界读取、先生成全部计划、写入全部 trampoline，再复核源字节并安装五字节 E9 补丁。agent 位于 ntdll 附近，每个槽位增至 64 字节；入口直接跳到 handler，保持继承识别与后端无关。安装失败时尝试恢复已写入口及原保护，并使本次挂起创建失败；不恢复执行失败的子进程。跨保护区域的五字节补丁直接拒绝。

已有跳转被搬迁并保留其当下路径，例如 E9、EB、FF25、mov rax/jmp rax。每个子进程重新读取自己的入口并重建 trampoline，不沿用父进程私有 hook 地址，不自动深入第三方模块下补丁。MSYS 的九个入口和 opt-in native relay 的单个入口范围保持原有规则；relay 仍构造供内部调用的其他原入口 trampoline。

agent 继续无 CRT 初始化、普通/延迟导入、TLS、全局构造、DllMain 或附加 DLL 依赖。没有新增动态库部署要求。

## 保守边界与后果

使用稳定版 HDE 的指令覆盖，未知/截断/过长指令返回明确失败。RIP 相对位移和入口跳转检查有符号 32 位可达性；不静默截断。内部跳转须落在已搬迁指令边界，跨扩展指令或跳入覆盖区的 call 等不支持情况拒绝。禁用在入口上方借空间的 patch-above 回退，避免改写其他入口/区域；不支持任意函数或所有安全软件的动态安装/卸载共存。

这些边界集中在后端和安装器，后续可增加验证充分的支持，或替换为 Detours。已有 hook 的合成执行测试不等于特定安全产品的兼容承诺。

## 验证

`inline-hook-test` 覆盖分离的逻辑 VA、RIP/入口范围、内部跳转边界、截断/非法输入、不可读页面末尾，实际执行常见已有跳转串接及 ENDBR 前导，并检查批量安装、native relay 单入口范围、失败回滚和页面保护恢复。真实受限环境继续运行 fork/线程 fork、native relay、ConPTY 和 ACL 的集成回归。最终产物核对导入、TLS、入口和许可证安装。
