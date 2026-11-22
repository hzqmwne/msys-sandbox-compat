# MSYS Sandbox Compat 当前设计

本文描述当前实现，重要取舍见 [架构决策](decisions/README.md)，使用入口见 [使用说明](getting-started.md)，已落地变更见 [CHANGELOG](../CHANGELOG.md)。

## 生产约束

兼容层不修改任何磁盘文件或目录 ACL，不为兼容而放宽原 restricted token 的限制。文件读取、执行、写入及其他资源访问继续受原隔离策略约束；遇到拒绝时保留失败，不通过更大权限的 token、非受限代理或预开句柄绕过。兼容产物应位于原策略已允许的位置。

下文的对象描述符处理针对 MSYS IPC 与已识别 MSYS 的进程/线程内核对象；显式 ACL 与当前主 token 默认 DACL 均基于当次输入补充受限主体，不改其身份或限制。内核对象处理不构成修改磁盘 ACL 或扩大原资源授权的许可。测试夹具单独建立的文件 ACL 只定义该夹具的初始策略。

## 适配方向与依赖

兼容层参照合理的受限环境版运行时行为，分别处理对象授权、fork 布局、创建传播和终端会话。残余影响、hook/进程数量及不改默认值均是取舍维度，由维护者结合功能和维护成本决定。保留 ntdll hook 通用接入，不限定 MSYS 模块/IAT/内部 RVA；当前识别和注入范围不因此扩大。

最终仍交付兼容 EXE/DLL。宿主静态链接 CRT；早期 agent 无 CRT、普通/延迟导入、TLS、全局构造或 DllMain 依赖。当前采用 MinHook v1.3.4 的 HDE64 与适配的搬迁核心，不引入其完整运行时管理器。后端与安装器以独立的有界字节/逻辑地址/搬迁计划接口分开，CMake 集中选择后端，保留未来切换 Detours 的空间。见 [ADR-0009](decisions/0009-minhook-relocation-backend.md)。

## 进程创建与识别

外部隔离启动器负责原有策略，生产兼容层包含兼容 EXE/DLL。可选 psec-run 开发工具用于创建 PSEC 验证环境。宿主与 agent 共享 core 源码，分别按各自 CRT/栈约束编译。宿主以 `CREATE_SUSPENDED` 创建目标。直接导入 `msys-2.0.dll` 的 EXE 按 MSYS 处理，文件名比较忽略大小写。普通令牌也可启动，命名对象和 DACL 适配按令牌条件启用。

声明此导入名就是选择该 ABI 的兼容处理。识别仅读取当前 EXE 的导入表，传递依赖及延迟导入在范围外。原生 EXE 改名为 Bash 不会命中，运行中才安装的 EXE 可在首次创建时识别。

为使内核创建 PEB 和初始线程栈时避开 MSYS 的栈和堆地址区，创建时先按 Native 参数中的映像路径做一次导入预检。命中后追加 `PS_ATTRIBUTE_MEMORY_RESERVE`，短暂预留 24–64 GiB 窗口。agent 使用已有的创建 hook。独立宿主仅在本次直接启动期间替换自身 KernelBase 的一个导入槽，仍由 `CreateProcessW` 处理标准句柄、环境与控制台。已继承 relay 的宿主调用由 relay 处理。

识别返回状态码与命中结果。导入表越界或读取失败会返回错误。启用 relay 时，已确认的 WoW64 进程走原生传播路径。其他无法分类或准备的目标按失败回收。关闭 relay 时，无法确认的后代保持原样，trace 标明识别不可用。

实际挂起映像仍决定是否注入。创建前追加过预留的进程必须再次确认为 MSYS 才能恢复。完成挂起准备后，父进程在恢复或交还线程句柄前释放自己追加的预留。调用者已有的创建属性和预留原样保留。仅在创建后识别到 MSYS 时，继续准备实际映像及对象兼容，堆由 MSYS 自行分配。决定见 [ADR-0011](decisions/0011-release-heap-reservations-before-start.md)。

## 初始准备

宿主按模块和令牌条件准备命名空间和传播策略。普通令牌使用 Windows 自身的对象路径和 ACL。

宿主和 agent 使用相同的模块配置。创建前预检由堆窗口模块触发。父端依据实际挂起映像决定传播和创建阶段的对象 DACL 适配。IPC 模块使用当前兼容树的命名空间，三个 ACL 相关模块共享所需的 SID 信息，受限 relay 独立维护策略基准。关闭所有模块时，宿主挂起创建根进程，纳入 Job 后恢复。

父端准备 agent、模块配置及普通的父端映像数据结构，并安排子进程首次进入 `LdrInitializeThunk` 时执行初始化。挂起期间的应用启动上下文仍可由创建者读取或更新。首次恢复后，agent 恢复加载器入口，按实际子进程映像和令牌条件选择并安装正式 hook，再把控制权交回 Windows 加载器。恢复后的初始化失败通过子进程退出状态报告。

冷启动与 exec 时，未设置 `DYNAMIC_BASE` 的 MSYS 主 EXE 可尝试一次 PE 首选基址。首选址已使用时直接继续，尝试失败时沿用 Windows 已选定的基址。设置该标志的映像沿用 Windows 选址。fork 子进程仍在基址不同于父端实载基址时按父端路径对齐。新视图验证成功后才更新 PEB 和应用启动上下文，原视图继续保留。MSYS 启动后自行分配 cygheap 和 userheap。

## DLL 映射范围

完整 MSYS 兼容进程在 `NtMapViewOfSection` 入口处理后续 DLL 映射。调用方传入 `*BaseAddress == 0` 时，兼容层用 `NtQuerySection` 从当次 section 取得映像类型、长度、PE 标志和首选基址。首选基址必须非零且按 64 KiB 对齐，映像必须是未设置 `DYNAMIC_BASE` 的 AMD64 `SEC_IMAGE` DLL。按同一规则处理各路径下的 DLL，包括原生 DLL、主 EXE 的传递依赖和运行时加载的扩展。

在受测 AMD64 路径上，非零 `ZeroBits` 的数量编码以低 32 位为基准，例如 `1` 要求映像落在 2 GiB 以下。位图编码按最高置位确定上限。整个首选映像区间都必须落在上限内，原始 `ZeroBits` 继续传给内核。

不满足条件或查询失败时直接使用原请求。首选址映射失败时将 `*BaseAddress` 恢复为零，再用原请求重试一次。如果无法写回原基址则返回恢复错误。`--trace` 记录请求的首选址、该次映射状态和成功时的实址。首选址失败并恢复入参时会另记重试事件。当前决策及范围见 [ADR-0012](decisions/0012-prefer-dll-image-base-at-map.md)。

MSYS 在 fork 时按运行时登记的模块清单核对父子实载基址。启动期间调用 `dll_dllcrt0` 登记的 MSYS DLL 进入 `DLL_LINK`，已登记的原生 `DLL_NATIVE` 也经过重载后的基址核对。PE 导入表用于给已登记的模块排序。动态登记的 `DLL_LOAD` 可以在父进程偏离 PE 首选地址，MSYS 会尝试在子进程重载到父进程实际使用的地址，再复制所需的数据段。即使自动选址让 DLL 加载继续，父子实载基址不同仍可能导致 fork 失败。见 [测试说明](testing.md#映像地址对照)。

## Hook 的职责

| 入口 | 兼容职责 |
|---|---|
| `NtCreateDirectoryObject` | MSYS 私有对象目录与授权 |
| `NtCreateSection` | 共享 section 授权 |
| `NtCreateMutant` | mutex 授权 |
| `NtCreateSymbolicLinkObject` | MSYS 目录链接与授权 |
| `NtCreateNamedPipeFile` | MSYS 管道授权 |
| `NtMapViewOfSection` | 对基址未指定、未设置 `DYNAMIC_BASE` 且符合 `ZeroBits` 的 `SEC_IMAGE` DLL 尝试首选基址，失败时恢复原请求 |
| `NtCreateUserProcess` | 创建前识别并暂留堆窗口，挂起创建后准备、释放窗口及传播 |
| `NtSetInformationToken` | 当前主 token 默认 DACL 按当次输入补受限主体并更新传播基准 |
| `NtSetSecurityObject` | 当前进程伪句柄单独设置 DACL 时，按当次输入补受限主体 |

对象路径规则保持不变。普通 allow ACL 保留原 ACE，只补当前用户及 enabled、非 deny-only 组已有、受限主体尚未具有的权限位。AppContainer 使用 package SID；非 AppContainer 优先使用同时属于 enabled/restricting 列表的 logon SID，或初始 ACL 中唯一可确定的非宽泛 restricting 主体。deny、带 flags 和复杂 ACE 原样传递；空 ACL 不补权。NULL DACL 用 Everyone:GA 加受限主体:GA 表达其开放意图，支持受测 PSEC 的共享 section。未指定 SD/缺省 DACL 仍由系统形成；absolute/self-relative SD 的 owner/group/SACL/control 语义保留。已识别进程/线程查询实际 DACL 后使用同一转换器。

默认设置同样使用当次 ACL，不恢复启动快照。仅匹配当前主 token 的 TokenDefaultDacl；NtCompareObjects 不要求输入句柄有查询权限，最终由原 NtSetInformationToken 检查设置权限。默认值对后续采用默认 SD 的对象有连带影响，作为已接受的兜底取舍；不修改已有磁盘/注册表 ACL。显式对象仍需创建路径适配。决定见 [ADR-0008](decisions/0008-adapt-requested-object-acls.md)。

MSYS 冷启动分别设置 token 默认 DACL 和当前进程对象的 DACL。当前进程伪句柄的独立 DACL 设置复用同一转换器，原系统调用执行授权检查。Git for Windows 的新运行时通过进程句柄检查控制台所有者是否仍存活，这条设置路径会影响该检查。
宿主只读查询自身主 token 时使用 `GetCurrentProcessToken` 伪句柄。PSEC 对象命名空间通过 `GetAppContainerNamedObjectPath` 与 token session 查询取得，不创建命名事件探针。该路径避免将宿主启动依赖于实际 token 对象可重开或 Win32 命名对象初始化。查询取舍见 [ADR-0003](decisions/0003-read-only-security-context.md)。

非 AppContainer 受限令牌使用当前 Windows 会话的 `BaseNamedObjects`。宿主按自身 PID 命名兼容目录，沿用启动器默认 DACL，并持有目录句柄直到进程树退出。实际对象按当次输入适配。agent 在兼容树内传递目录路径。关闭 relay 时，经过原生中间程序后的显式兼容入口建立新树和新目录。默认 ConPTY 由内层宿主创建目录。AppContainer 使用 Windows 提供的 package 命名空间。取舍及受测边界见 [ADR-0005](decisions/0005-restricted-token-context.md)。

## fork 与进程链

MSYS 自身仍负责 fork 的复制、同步和恢复语义。兼容层解决环境导致的对象访问和地址布局障碍，并在相关子进程的初始线程恢复前复制 agent。它保留调用者原有的挂起状态，不用调试事件截获创建。

关闭 relay 时，自动传播在原生子进程处结束。Job 仍管理生命周期并接收退出通知。进程链支持范围见 [兼容范围](compatibility.md)。

MSYS 创建的原生后代可显式调用兼容宿主启动原生或 MSYS 目标。默认对象 ACL 在 MSYS 冷启动时基于当次请求补充受限主体，因此原生后代及再次进入的 MSYS 仍能重开所需对象。端到端回归覆盖一层和三层原生桥接后的 Bash、Perl、线程中 fork、管道、文件边界与退出码。宿主仍在 MSYS 根进程恢复前检查真实 token 查询权限；从未受兼容处理的祖先继承了不兼容 token 时明确拒绝，这个错误检查不是成功验收。

## 原生 relay

relay 默认覆盖原生根和后代，可通过 `--no-native-relay` 关闭。原生进程仅启用创建 hook。WoW64 通过其 AMD64 转换层调用原生 `NtCreateUserProcess`，因此复用同一份 AMD64 agent。完整布局与对象适配只用于已识别的 AMD64 MSYS。调用者原有的挂起状态保留。

原生创建 hook 在恢复前识别并复制相应模式，因而覆盖 MSYS → 多层普通原生程序 → MSYS。已处于 relay 中的显式兼容启动器从本进程创建 hook 对应的 agent 映像识别继承状态，复用原运行上下文；其创建调用已准备子进程，宿主不重复识别、复制完整状态或再次注入。首次映射在独立的 agent 状态副本中绑定 trampoline，不临时改写宿主 API。ConPTY 的原生会话宿主同样适用。该模式继承到进程树后代，省略嵌套启动器选项不会关闭已有 relay 或替换原上下文。

各进程只为自身实际安装的 hook 读取入口和生成 trampoline。未改写的入口由当前进程直接调用，以便原生 relay 执行后代准备。复制 agent 时根据子进程的 hook 集合重新绑定其原入口调用。启用传播时，agent 同时保存后代可能启用的 handler 位置。宿主通过版本标记核对配套 DLL 和继承的 relay 状态。

relay 创建后比较父子令牌身份与隔离上下文，受限环境还核对创建前后的默认 DACL。对于涉及 WoW64 的创建，允许 Windows 设置的每应用 UAC 虚拟化启用位变化，并通过独立的令牌信息类确认该值。其他令牌字段继续参与比较。受限 relay 的默认 DACL 基准容纳 8 KiB，MSYS 设置成功后更新，并与创建串行化。未观察到的默认策略改变、上下文不一致或查询失败时回收挂起的目标。决定见 [ADR-0006](decisions/0006-opt-in-native-relay.md) 及 [ADR-0008](decisions/0008-adapt-requested-object-acls.md)。

## ConPTY

stdin、stdout、stderr 都是控制台句柄时默认启用 ConPTY。主机在既有受限上下文内用公开 API 创建 ConPTY，再复用兼容宿主 EXE 的一个原生实例持有自动标准句柄。该实例显式直连目标。真实 MSYS 目标只继承明确的句柄副本，避免 MSYS 关闭标准流后，控制台清理使用旧数值误关复用的句柄。agent 不重开 CONIN$/CONOUT$。

在受测 PSEC 配置中，Low IL 客户端连接外部 Medium IL conhost 时，控制台连接策略拒绝 MSYS 所需的读屏和输入事件写回。外部普通 conhost 降至 Low 后，打开客户端进程时又会遇到目标进程 DACL 中的 AppContainer package SID 所触发的访问限制。普通 Untrusted 调用者在同一 PSEC 配置下也无法打开客户端进程。同一 PSEC 内创建的 conhost 已验证可以查询客户端 token，并通过后续控制台策略检查。[微软控制台访问规则](https://learn.microsoft.com/en-us/windows/console/console-buffer-security-and-access-rights#wrong-way-verbs)

这个设计复用已有 EXE，增加一个原生宿主实例。输入脚本与标准输入统一通过句柄读取，脚本只打开一次。双向转发遇到短写会继续写入剩余字节。外部数据源耗尽后，桥停止转发输入。目标的 stdin 仍是控制台句柄。在受测 Windows 上，关闭 conhost 的 VT 输入管道会向目标发出 `CTRL_CLOSE_EVENT`。桥因此把该管道保留到会话收尾，以便目标继续处理输入和输出结果。下游写入失败或零进展时，读取线程通过 job 的完成端口通知宿主结束进程树，同时继续读取并丢弃剩余 ConPTY 输出，直到终端退出。正常收尾取消阻塞输入并转发剩余输出。

交互模式默认从外层输出控制台的 `srWindow` 取得初始行列数。独立线程采样窗口尺寸，在变化时调用 `ResizePseudoConsole`，因而空闲时也能传递调整。关闭时先结束尺寸采样，再释放 ConPTY。显式尺寸、脚本输入和重定向标准流沿用固定尺寸。[控制台窗口尺寸查询](https://learn.microsoft.com/en-us/windows/console/getconsolescreenbufferinfo) · [ConPTY 调整尺寸](https://learn.microsoft.com/en-us/windows/console/resizepseudoconsole)

外层控制台的鼠标跟踪由内层应用协商。桥接输入时，将旧版 conhost 封装成 Win32 字符键的 SGR 鼠标报告还原为 VT 序列，由内层 ConPTY 按应用的输入模式处理。脚本和重定向输入保持原字节流。

对真实控制台句柄，桥接前保存各方向的 mode 与代码页，输入设置 raw VT / UTF-8，输出启用 processed / VT / UTF-8。收尾在最后一批输出排空之后恢复，包括目标启动失败的路径。compat 的等待实例和开发工具 psec-run 各自注册 Ctrl+C handler，防止控制台广播先终止等待宿主并触发 job 回收。该 handler 处理当前宿主的通知，子进程沿用自己的处理器。[控制台模式](https://learn.microsoft.com/en-us/windows/console/setconsolemode) · [控制事件处理](https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler)

该路径已在 PSEC 和两种固定非 AppContainer 受限令牌中完成交互验收。受限令牌回归在终端内完成 Perl/线程 fork、原生命令、Ctrl+C、作业控制和退出码，并在交互前后验证原有文件访问拒绝。实际 harness 的完整性等级、desktop 和句柄条件仍以其自身验收为准。
