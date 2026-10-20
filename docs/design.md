# MSYS Compat 当前设计

本文描述当前实现，重要取舍见 [架构决策](decisions/README.md)，使用入口见 [使用说明](getting-started.md)，已落地变更见 [CHANGELOG](../CHANGELOG.md)。

## 进程创建与识别

PSEC 创建工具与兼容宿主分别负责隔离策略和运行时兼容。宿主以 `CREATE_SUSPENDED` 创建目标，在初始线程恢复前读取实际映像内存中的普通导入表。直接或间接导入 `msys-2.0.dll` 即按 MSYS 处理，文件名比较忽略大小写；运行时 DLL 自身按该文件名识别。

声明此导入名就是选择该 ABI 的兼容处理，不另加文件 ID 或导出指纹认证。先检查当前映像的直接导入，再用有界队列遍历间接依赖。同一次识别按路径去重，每次只映射一个依赖；最多 128 个映像、16 层。原生 EXE 改名为 Bash 不会命中；目标运行后才安装的包可以在首次创建、映射时识别。

识别返回状态码与命中结果。遍历越界、读取或分配失败会返回错误；已经命中 MSYS 后获取首选地址失败，保留命中结果并停止准备。无法确认的子进程保持原样，trace 标明识别不可用；根进程识别失败则直接报错。

## 初始准备

命中后，宿主手工映射没有 CRT、普通导入、TLS 或 DllMain 初始化依赖的 agent，完成重定位和状态复制。agent 在 ntdll 附近分配，以普通相对跳转连接 hook；检查受支持的系统调用入口格式后才安装补丁，并为 trampoline、异常展开和代码保护建立所需状态。

准备工作包括 EXE/DLL 首选地址、MSYS 堆预留与地址修正、私有对象路径及安全描述符。root 和 child 使用同一套 agent 节保护规则；child 只重置进程局部状态。

## 八个 hook 的职责

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

对象路径重定向限于 MSYS 使用的对象；文件安装目录 ACL 和 token 不被修改。仅调整 TokenDefaultDacl 无法覆盖运行时显式传入的对象安全描述符。

## fork 与进程链

MSYS 自身仍负责 fork 的复制、同步和恢复语义。兼容层解决环境导致的对象访问和地址布局障碍，并在相关子进程的初始线程恢复前复制 agent。它保留调用者原有的挂起状态，不用调试事件截获创建。

原生子进程保持原样，其后续创建操作不会经过 MSYS 父进程的 hook。Job 管理生命周期并接收退出通知。进程链支持范围见 [兼容范围](compatibility.md)。

## ConPTY

正式路径在 PSEC 内用公开 API 创建 ConPTY，再复用兼容宿主 EXE 的一个原生实例持有自动标准句柄。真实 MSYS 目标只继承明确的句柄副本，避免 MSYS 关闭标准流后，控制台清理使用旧数值误关复用的句柄。agent 不重开 CONIN$/CONOUT$。

这个设计复用已有 EXE，增加一个原生宿主实例。
