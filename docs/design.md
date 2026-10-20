# MSYS Compat 当前设计

本文描述当前实现，重要取舍见 [架构决策](decisions/README.md)，使用入口见 [使用说明](getting-started.md)，已落地变更见 [CHANGELOG](../CHANGELOG.md)。

## 生产约束

兼容层不修改任何磁盘文件或目录 ACL，不为兼容而放宽原 restricted token 的限制。文件读取、执行、写入及其他资源访问继续受原隔离策略约束；遇到拒绝时保留失败，不通过更大权限的 token、非受限代理或预开句柄绕过。兼容产物应位于原策略已允许的位置。

下文的对象描述符处理针对 MSYS IPC 与已识别 MSYS 的进程/线程内核对象；非 AppContainer 路径沿用启动器原默认 DACL，当前主 token 的默认 DACL 拦截保留启动时策略，不改其身份或限制。内核对象处理不构成修改磁盘 ACL 或扩大原资源授权的许可。测试夹具单独建立的文件 ACL 只定义该夹具的初始策略。

## 进程创建与识别

PSEC 创建工具或外部受限令牌启动器负责隔离策略，兼容宿主负责运行时兼容。宿主要求已有 AppContainer SID 或实际受限令牌，以 `CREATE_SUSPENDED` 创建目标，在初始线程恢复前读取实际映像内存中的普通导入表。直接或间接导入 `msys-2.0.dll` 即按 MSYS 处理，文件名比较忽略大小写；运行时 DLL 自身按该文件名识别。

声明此导入名就是选择该 ABI 的兼容处理，不另加文件 ID 或导出指纹认证。先检查当前映像的直接导入，再用有界队列遍历间接依赖。同一次识别按路径去重，每次只映射一个依赖；最多 128 个映像、16 层。原生 EXE 改名为 Bash 不会命中；目标运行后才安装的包可以在首次创建、映射时识别。

识别返回状态码与命中结果。遍历越界、读取或分配失败会返回错误；已经命中 MSYS 后获取首选地址失败，保留命中结果并停止准备。无法确认的子进程保持原样，trace 标明识别不可用；根进程识别失败则直接报错。

## 初始准备

命中后，宿主手工映射没有 CRT、普通导入、TLS 或 DllMain 初始化依赖的 agent，完成重定位和状态复制。agent 在 ntdll 附近分配，以普通相对跳转连接 hook；检查受支持的系统调用入口格式后才安装补丁，并为 trampoline、异常展开和代码保护建立所需状态。

准备工作包括 EXE/DLL 首选地址、MSYS 堆预留与地址修正、私有对象路径及安全描述符。root 和 child 使用同一套 agent 节保护规则；child 只重置进程局部状态。

## 九个 hook 的职责

| 入口 | 兼容职责 |
|---|---|
| `NtCreateDirectoryObject` | MSYS 私有对象目录与授权 |
| `NtCreateSection` | 共享 section 授权 |
| `NtCreateMutant` | mutex 授权 |
| `NtCreateSymbolicLinkObject` | MSYS 目录链接与授权 |
| `NtCreateNamedPipeFile` | MSYS 管道授权 |
| `NtMapViewOfSection` | 按需识别并固定相关映像地址 |
| `NtAllocateVirtualMemory` | 修正 MSYS 私有堆地址及 fork 提交范围 |
| `NtCreateUserProcess` | 子进程初始挂起、识别、准备和传播 |
| `NtSetInformationToken` | MSYS 重设当前主 token 默认 DACL 时保留隔离启动器配置的初始 ACL |

对象路径重定向限于 MSYS 使用的对象，文件安装目录 ACL 不被修改。兼容层保留隔离启动器传入的默认对象 ACL，避免 MSYS 冷启动将 package/logon 等授权替换为普通用户模板；仅对当前主 token 的 `TokenDefaultDacl` 设置调用生效，其他 token 与信息类原样传递。调用仍由原 Native API 执行，不改变 token 身份、权限、受限 SID 或文件策略。取舍见 [ADR-0004](decisions/0004-preserve-sandbox-object-policy.md)。显式传入的对象描述符仍需相应创建 hook 处理，保留默认 ACL 不替代它们。

宿主只读查询自身主 token 时使用 `GetCurrentProcessToken` 伪句柄。PSEC 对象命名空间通过 `GetAppContainerNamedObjectPath` 与 token session 查询取得，不创建命名事件探针。该路径避免将宿主启动依赖于实际 token 对象可重开或 Win32 命名对象初始化。查询取舍见 [ADR-0003](decisions/0003-read-only-security-context.md)。

非 AppContainer 受限令牌没有 package 私有命名空间。宿主在当前 session 的 `BaseNamedObjects` 下创建每次启动的目录，沿用启动器默认 DACL 作为 MSYS 对象描述符，不遍历 restricting SID 并全部授权。目录句柄保持到进程树退出；内部环境变量 `MSYS_COMPAT_SESSION` 携带数字启动标记，使原生中间程序后的显式兼容入口复用同一目录。普通 MSYS 和其他兼容会话的对象不会占用该目录。PSEC 路径不使用此标记。取舍及受测边界见 [ADR-0005](decisions/0005-restricted-token-context.md)。

## fork 与进程链

MSYS 自身仍负责 fork 的复制、同步和恢复语义。兼容层解决环境导致的对象访问和地址布局障碍，并在相关子进程的初始线程恢复前复制 agent。它保留调用者原有的挂起状态，不用调试事件截获创建。

原生子进程保持原样，其后续创建操作不会经过 MSYS 父进程的 hook。Job 管理生命周期并接收退出通知。进程链支持范围见 [兼容范围](compatibility.md)。

MSYS 创建的原生后代可显式调用兼容宿主启动原生或 MSYS 目标。默认对象 ACL 在 MSYS 冷启动时保留，因此原生后代及再次进入的 MSYS 仍能重开所需对象。端到端回归覆盖一层和三层原生桥接后的 Bash、Perl、线程中 fork、管道、文件边界与退出码。宿主仍在 MSYS 根进程恢复前检查真实 token 查询权限；从未受兼容处理的祖先继承了不兼容 token 时明确拒绝，这个错误检查不是成功验收。

## ConPTY

正式路径在既有受限上下文内用公开 API 创建 ConPTY，再复用兼容宿主 EXE 的一个原生实例持有自动标准句柄。真实 MSYS 目标只继承明确的句柄副本，避免 MSYS 关闭标准流后，控制台清理使用旧数值误关复用的句柄。agent 不重开 CONIN$/CONOUT$。

这个设计复用已有 EXE，增加一个原生宿主实例。

该路径已在 PSEC 和两种固定非 AppContainer 受限令牌中完成交互验收；未改变生产代码或测试初始权限。受限令牌回归在终端内完成 Perl/线程 fork、原生命令、Ctrl+C、作业控制和退出码，并在交互前后验证原有文件访问拒绝。实际 harness 的完整性等级、desktop 和句柄条件仍以其自身验收为准。
