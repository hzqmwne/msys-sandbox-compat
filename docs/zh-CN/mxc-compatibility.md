# MXC ProcessContainer 中的 MSYS 兼容性

MSYS Sandbox Compat 通过 hook 让已安装的 x64 MSYS2 运行时在 MXC ProcessContainer 中运行，用于上游补丁进入正式运行时包之前的过渡。文件访问仍遵循现有策略。 [使用说明](getting-started.md) · [下载 v0.1.0](https://github.com/hzqmwne/msys-sandbox-compat/releases/tag/v0.1.0)

## 实测命令

在宿主上运行以下命令。ProcessContainer 策略需允许读取和执行 shim 与 MSYS 安装中的相关文件。

```powershell
.\wxc-exec.exe --config .\policy.json -- 'C:\tools\msys-sandbox-compat-shim.exe' -- 'C:\msys64\usr\bin\bash.exe' --noprofile --norc -c 'echo ready; (echo fork-ok); echo pipe-ok | /usr/bin/tr a-z A-Z'
```

实测环境为 Windows 11 x64 `26300.9974`，`wxc-exec.exe 1.1.0+6a89e69c` 使用原生 `base-container` 模式。直接启动官方 MSYS2 `3.6.12-1` 时，`NtCreateDirectoryObject` 返回 `STATUS_ACCESS_DENIED`（`0xC0000022`），进程以 `0xC0000142` 退出。使用同一份只读策略，经 v0.1.0 shim 启动后，示例输出 `ready`、`fork-ok` 和 `PIPE-OK`，退出码为 `0`。 [MXC 原始报告](https://github.com/microsoft/mxc/issues/1061)

## 上游工作与 shim 处理

上游补丁直接修改 MSYS 运行时中的 fork、spawn 和 AppContainer 对象处理。v0.1.0 shim 保留原安装的 `msys-2.0.dll`，通过 `ntdll.dll` 层的 hook 处理相关调用。控制台桥接使用 Windows ConPTY API。 [MSYS2 runtime PR #403](https://github.com/msys2/msys2-runtime/pull/403) · [Git for Windows runtime PR #148](https://github.com/git-for-windows/msys2-runtime/pull/148)

| 问题 | 上游修复方向 | v0.1.0 shim 的处理 |
| --- | --- | --- |
| **栈和堆。** 加载器可能占用 MSYS 的栈和堆所需的地址。 | 用 `CREATE_SUSPENDED` 启动受影响的 fork/spawn 子进程，在恢复子进程前用 `VirtualAllocEx` 预留 cygheap 区间 `[0x800000000, 0xA00000000)`（32–40 GiB）。 | 在 `NtCreateUserProcess` 的属性列表中加入 `PS_ATTRIBUTE_MEMORY_RESERVE`，预留 `[0x600000000, 0x1000000000)`（24–64 GiB）。`CreateProcessW` 没有对应的属性。创建者在恢复子进程或交回挂起进程前释放自己的预留。 |
| **EXE 与 DLL 选址。** 映像重定位可能导致 fork 失败。 | 按父进程实载地址映射 fork 子进程的 EXE，并更新 PEB 和启动入口。MSYS2 3.6.12 另行恢复了运行时 DLL 的 `DYNAMIC_BASE`。 [MSYS2 runtime PR #381](https://github.com/msys2/msys2-runtime/pull/381) | fork 时，`prepare_exe_layout` 使用父进程记录的 EXE 基址。冷启动和 exec 时，对未设置 `DYNAMIC_BASE` 的 EXE 尝试 PE 头中的 `ImageBase`。调用者未指定 `BaseAddress` 时，`NtMapViewOfSection` hook 对符合条件且未设置 `DYNAMIC_BASE` 的 DLL 尝试 `ImageBase`，失败时重试原请求。 |
| **命名 IPC 与显式 DACL。** `NtCreateDirectoryObject` 创建 `\BaseNamedObjects` 下的 MSYS 目录时可能失败。 | 用 `RtlGetAppContainerNamedObjectPath` 定位共享对象目录，在 `sec_acl()` 中加入 AppContainer SID，适用的管道改用 `LOCAL\` 前缀重试。 | 在 `NtCreateDirectoryObject` 将 `OBJECT_ATTRIBUTES` 中匹配的 MSYS 名称改写到对应的 IPC 命名空间，在 `NtCreateNamedPipeFile` 处理管道创建。按用户或已启用组已有的权限适配符合条件的对象 DACL，以及传给 `NtCreateUserProcess` 的显式进程／线程 DACL。 |
| **默认与启动期 DACL。** MSYS 在启动时设置的 DACL 可能缺少受限 SID。 | 启动时经 `sec_acl()` 构造带 AppContainer SID 的令牌默认 DACL。 | 适配当前主令牌的 `NtSetInformationToken(TokenDefaultDacl)` 和当前进程仅设置 DACL 的 `NtSetSecurityObject` 请求。 |
| **交互终端。** 低完整性目标的读屏幕或写控制台输入可能被拒绝。 | MXC 在 [#1757](https://github.com/microsoft/mxc/issues/1757) 跟踪原生 ProcessContainer PTY 支持。 | 按需在受限环境内调用 `CreatePseudoConsole`。桥接控制台句柄，已重定向的文件和管道直接交给目标。 |

## v0.1.0 的已知问题

- **共享 DLL 状态与命名对象。** BaseNamedObjects（BNO）重定向把命名对象放到各自的 IPC 命名空间后，加载同一个 MSYS DLL 文件的进程仍可能共用它的可写 `.cygwin_` 段。对齐 DLL 基址可以避免这类 `wincap.caps` 指针失效。运行时还需要让 Winsock 事件表和保护它的互斥对象使用相同的共享范围。上游系列提议把事件表和序列号计数器移入与这些互斥对象同目录的命名共享区段。 [共享映像节](compatibility.md#msys-运行时的共享映像节) · [运行时 PR #403](https://github.com/msys2/msys2-runtime/pull/403)
- **继承磁盘文件 stdout 或 stderr。** 在受测的 Git for Windows MSYS 3.6.10 组合里，重建描述符时 `QueryDosDeviceW` 被 PSEC 拒绝，Bash 启动时可能在 `fstat` 崩溃。运行时需要正确处理这次拒绝。BaseContainer 里的 DOS 卷路径查询也在 Windows/MXC 侧另有跟踪。 [磁盘文件重定向](compatibility.md#psec-下的磁盘文件重定向) · [MXC #1464](https://github.com/microsoft/mxc/issues/1464)
- **商店版 PowerShell。** 在受测的 PSEC 环境中，容器内无包身份的父进程无法启动 Microsoft Store 版 PowerShell，Windows 包激活请求被拒绝。这条激活路径仍需 Windows/PSEC 侧处理。 [商店版 PowerShell 测试结果](compatibility.md#psec-下的-microsoft-store-powershell) · [MXC #1758](https://github.com/microsoft/mxc/issues/1758)
- **缩放后输入。** 在受测的 Windows Terminal Git Bash 会话中，调整窗口大小后立即输入，偶尔会丢失第一个字符。 [兼容性说明](compatibility.md)
