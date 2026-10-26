# MSYS Sandbox Compat 当前设计

本文描述当前实现，重要取舍见 [架构决策](decisions/README.md)，使用入口见 [使用说明](getting-started.md)，已落地变更见 [CHANGELOG](../CHANGELOG.md)。

## 生产约束

兼容层不修改任何磁盘文件或目录 ACL，不为兼容而放宽原 restricted token 的限制。文件读取、执行、写入及其他资源访问继续受原隔离策略约束；遇到拒绝时保留失败，不通过更大权限的 token、非受限代理或预开句柄绕过。兼容产物应位于原策略已允许的位置。

下文的对象描述符处理针对 MSYS IPC 与已识别 MSYS 的进程/线程内核对象；显式 ACL 与当前主 token 默认 DACL 均基于当次输入补充受限主体，不改其身份或限制。内核对象处理不构成修改磁盘 ACL 或扩大原资源授权的许可。测试夹具单独建立的文件 ACL 只定义该夹具的初始策略。

## 适配方向与依赖

兼容层参照合理的受限环境版运行时行为，分别处理对象授权、fork 布局、创建传播和终端会话。残余影响、hook/进程数量及不改默认值均是取舍维度，由维护者结合功能和维护成本决定。保留 ntdll hook 通用接入，不限定 MSYS 模块/IAT/内部 RVA；当前识别和注入范围不因此扩大。

最终仍交付兼容 EXE/DLL。宿主静态链接 CRT；早期 agent 无 CRT、普通/延迟导入、TLS、全局构造或 DllMain 依赖。当前采用 MinHook v1.3.4 的 HDE64 与适配的搬迁核心，不引入其完整运行时管理器。后端与安装器以独立的有界字节/逻辑地址/搬迁计划接口分开，CMake 集中选择后端，保留未来切换 Detours 的空间。见 [ADR-0009](decisions/0009-minhook-relocation-backend.md)。

## 进程创建与识别

外部隔离启动器负责原有策略，生产兼容层仅包含兼容 EXE/DLL。可选 psec-run 开发工具用于创建 PSEC 验证环境，不进入默认安装包。宿主与 agent 共享 core 源码，分别按各自 CRT/栈约束编译，不增加共享运行库。宿主要求已有 AppContainer SID 或实际受限令牌，以 `CREATE_SUSPENDED` 创建目标，在初始线程恢复前读取实际映像内存中的普通导入表。直接或间接导入 `msys-2.0.dll` 即按 MSYS 处理，文件名比较忽略大小写；运行时 DLL 自身按该文件名识别。

声明此导入名就是选择该 ABI 的兼容处理，不另加文件 ID 或导出指纹认证。先检查当前映像的直接导入，再用有界队列遍历间接依赖。同一次识别按路径去重，每次只映射一个依赖；最多 128 个映像，不另设依赖深度限制；去重和固定队列同时约束循环、存储与处理数量。原生 EXE 改名为 Bash 不会命中；目标运行后才安装的包可以在首次创建、映射时识别。

识别返回状态码与命中结果。遍历越界、读取或分配失败会返回错误；已经命中 MSYS 后获取首选地址失败，保留命中结果并停止准备。默认模式中无法确认的子进程保持原样，trace 标明识别不可用；根进程识别失败则直接报错。显式 relay 模式遇到无法分类或传播的子进程时终止本次挂起创建并返回失败，不静默留下传播缺口。

## 初始准备

启动时只确认受限上下文，并提前准备供原生桥接继承的会话标记。确认目标需要完整兼容或 relay 后，才选择兼容 SID、建立命名空间和准备传播策略；普通原生目标不受兼容快照容量限制。

宿主手工映射无初始化依赖的 agent，完成重定位和状态复制。agent 位于 ntdll 附近；搬迁后端按目标自己的入口字节保留现有路径，安装器复核源字节、写入补丁并恢复页面保护。安装失败由调用方终止尚未恢复的新进程，不维护入口恢复事务。成功后设置 agent 节保护并建立异常展开状态。后端具体支持边界及上游差异见源码中的 `third_party/minhook/README.md`。

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
| `NtSetInformationToken` | 当前主 token 默认 DACL 按当次输入补受限主体并更新传播基准 |

对象路径规则保持不变。普通 allow ACL 保留原 ACE，只补当前用户及 enabled、非 deny-only 组已有、受限主体尚未具有的权限位。AppContainer 使用 package SID；非 AppContainer 优先使用同时属于 enabled/restricting 列表的 logon SID，或初始 ACL 中唯一可确定的非宽泛 restricting 主体。deny、带 flags 和复杂 ACE 原样传递；空 ACL 不补权。NULL DACL 用 Everyone:GA 加受限主体:GA 表达其开放意图，支持受测 PSEC 的共享 section。未指定 SD/缺省 DACL 仍由系统形成；absolute/self-relative SD 的 owner/group/SACL/control 语义保留。已识别进程/线程查询实际 DACL 后使用同一转换器。

默认设置同样使用当次 ACL，不恢复启动快照。仅匹配当前主 token 的 TokenDefaultDacl；NtCompareObjects 不要求输入句柄有查询权限，最终由原 NtSetInformationToken 检查设置权限。默认值对后续采用默认 SD 的对象有连带影响，作为已接受的兜底取舍；不修改已有磁盘/注册表 ACL。显式对象仍需创建路径适配。决定见 [ADR-0008](decisions/0008-adapt-requested-object-acls.md)。
宿主只读查询自身主 token 时使用 `GetCurrentProcessToken` 伪句柄。PSEC 对象命名空间通过 `GetAppContainerNamedObjectPath` 与 token session 查询取得，不创建命名事件探针。该路径避免将宿主启动依赖于实际 token 对象可重开或 Win32 命名对象初始化。查询取舍见 [ADR-0003](decisions/0003-read-only-security-context.md)。

非 AppContainer 受限令牌没有 package 私有命名空间。宿主在当前 session 的 `BaseNamedObjects` 下创建每次启动的目录，目录初始策略沿用启动器默认 DACL，实际对象按当次输入适配，不遍历 restricting SID 并全部授权。目录句柄保持到进程树退出；内部环境变量 `MSYS_SANDBOX_COMPAT_SESSION` 携带数字启动标记，使原生中间程序后的显式兼容入口复用同一目录。普通 MSYS 和其他兼容会话的对象不会占用该目录。PSEC 路径不使用此标记。取舍及受测边界见 [ADR-0005](decisions/0005-restricted-token-context.md)。

## fork 与进程链

MSYS 自身仍负责 fork 的复制、同步和恢复语义。兼容层解决环境导致的对象访问和地址布局障碍，并在相关子进程的初始线程恢复前复制 agent。它保留调用者原有的挂起状态，不用调试事件截获创建。

默认模式的原生子进程保持原样，其后续创建操作不会经过 MSYS 父进程的 hook。Job 管理生命周期并接收退出通知。进程链支持范围见 [兼容范围](compatibility.md)。

MSYS 创建的原生后代可显式调用兼容宿主启动原生或 MSYS 目标。默认对象 ACL 在 MSYS 冷启动时基于当次请求补充受限主体，因此原生后代及再次进入的 MSYS 仍能重开所需对象。端到端回归覆盖一层和三层原生桥接后的 Bash、Perl、线程中 fork、管道、文件边界与退出码。宿主仍在 MSYS 根进程恢复前检查真实 token 查询权限；从未受兼容处理的祖先继承了不兼容 token 时明确拒绝，这个错误检查不是成功验收。

## 显式原生 relay

`--native-relay` 将传播范围扩展到本次启动的原生根和原生后代。仍手工映射同一 agent 映像，为共享识别/准备代码初始化原入口 trampoline；原生进程仅修改 `NtCreateUserProcess` 一个入口，不修改其对象 ACL、默认 DACL 或 MSYS 地址区。确认关联 MSYS 的子进程才应用完整九个 hook 和 MSYS 准备。调用者原有的挂起状态保留。

原生创建 hook 在恢复前识别并复制相应模式，因而覆盖 MSYS → 多层普通原生程序 → MSYS。已处于 relay 中的显式兼容启动器从本进程创建 hook 对应的 agent 映像识别继承状态，复用原运行上下文；其创建调用已准备子进程，宿主不重复识别、复制完整状态或再次注入。首次映射在独立的 agent 状态副本中绑定 trampoline，不临时改写宿主 API。ConPTY 的原生会话宿主同样适用。该模式继承到进程树后代，省略嵌套启动器选项不会关闭已有 relay 或替换原上下文。

relay 创建前核对最近已观察的默认策略，创建后比较父子 token 身份与隔离上下文，并核对子进程默认 DACL。基准容纳 8 KiB ACL，仅在 relay 模式下建立和维护；完整 agent 的设置 hook 在成功后更新它，并与创建/克隆串行化。未观察的策略改变、上下文不一致或查询失败时拒绝传播，已创建目标在恢复前回收。非 relay 仅做当次 ACL 适配，不维护快照或持有策略锁。该模式不承诺跨凭据或其他安全上下文自动传播。决定见 [ADR-0006](decisions/0006-opt-in-native-relay.md) 及 [ADR-0008](decisions/0008-adapt-requested-object-acls.md)。

## ConPTY

正式路径在既有受限上下文内用公开 API 创建 ConPTY，再复用兼容宿主 EXE 的一个原生实例持有自动标准句柄。真实 MSYS 目标只继承明确的句柄副本，避免 MSYS 关闭标准流后，控制台清理使用旧数值误关复用的句柄。agent 不重开 CONIN$/CONOUT$。

这个设计复用已有 EXE，增加一个原生宿主实例。输入脚本与标准输入统一通过句柄读取，脚本只打开一次；关闭时仍取消阻塞输入并排空输出。

该路径已在 PSEC 和两种固定非 AppContainer 受限令牌中完成交互验收；未改变生产代码或测试初始权限。受限令牌回归在终端内完成 Perl/线程 fork、原生命令、Ctrl+C、作业控制和退出码，并在交互前后验证原有文件访问拒绝。实际 harness 的完整性等级、desktop 和句柄条件仍以其自身验收为准。
