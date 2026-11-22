# 兼容范围

当前项目为 0.1 开发版本。生产部署仅需兼容 EXE/DLL，运行于启动器已经提供的受限上下文；psec-run 仅为可选开发验证工具。已验证组合为 Windows 26300.9974 x64、原生 PSEC 1.0、MSYS 3.6.10，目标包含真实内部 Bash、Perl 和 GNU 工具。

| 能力 | 当前范围 |
|---|---|
| 原版 EXE 与 `msys-2.0.dll` | 使用原安装文件，不修改分发包 |
| fork、exec、管道、信号及线程中 fork | 受测组合通过回归与压力测试 |
| MSYS 连续子进程链 | 通过创建 hook 传播 |
| 进程链中的原生子进程 | 默认不注入；显式 relay 模式仅安装创建 hook |
| 原生根显式调用兼容入口 | 已由公开作用范围测试验证 |
| MSYS 原生后代调用兼容入口启动原生目标 | 已验证；原生目标无兼容补丁，继承的 token 默认 DACL 不变 |
| MSYS 创建原生中间程序后显式回入 MSYS | 一层/三层原生桥接后 Bash、Perl、线程中 fork、管道与退出码通过回归 |
| 原生中间程序直接创建 MSYS | `--native-relay` 下，一层/三层原生桥接后直接进入 Bash/Perl 已通过；默认模式仍需显式入口 |
| relay 的原生根、显式嵌套入口及挂起创建 | 受测 PSEC 和两种固定令牌均通过；仅创建入口被修改，保留退出码与挂起状态 |
| 运行中新出现的 EXE/DLL | EXE 按直接导入识别，符合映射条件的 DLL 在首次映射时处理 |
| ConPTY | 公开 API 路径在 PSEC 和两种固定非 AppContainer 受限令牌中通过交互回归。尺寸跟随通过 PSEC 内外两层 ConPTY 的原生探针验收 |
| Git `pre-commit` | 在已初始化的工作区，原生 Git 通过 `--native-relay` 自动启动 MSYS hook。PSEC 和两种固定受限令牌通过提交成功、hook 拒绝提交及文件边界回归 |
| 非 AppContainer write-restricted 令牌 | 固定夹具通过 Bash/Perl、fork、原生桥接、管道、文件边界及普通 MSYS 共存回归 |
| 非 AppContainer 完整 restricting SID 检查令牌 | 同一固定夹具通过上述工作负载与边界回归 |
| 验收依据 | 参照相关配置构造的 PSEC 与两种受限令牌模型；按有效安全策略与进程创建条件判断适用性 |
| 只复制旁置文件即可自动生效 | 尚未提供可靠通用加载入口 |

表中结果使用默认 MSYS 模块配置。可按模块关闭处理做对照，关闭后能支持哪些负载取决于实际运行时、隔离配置和启动链。见[兼容模块对照](getting-started.md#兼容模块对照)。

验证按底层隔离机制与配置组织；在相关安全策略、进程创建与控制台条件一致时，现有模型可代表上层启动环境。当前验收不要求先接入上层 harness，也不按产品名称分别建立兼容实现。

EXE 识别覆盖普通导入表中直接导入 `msys-2.0.dll` 的程序。纯原生根启动后才 LoadLibrary MSYS、仅 delay import 或仅由中间 DLL 引入运行时，均在预先识别范围外。完整 MSYS 兼容进程中的 DLL 映射规则适用于任意路径。首选址不可用时由 Windows 按原请求选址，fork 同址重载仍可能失败。见 [DLL 映射范围](design.md#dll-映射范围)。

设置 PE `DYNAMIC_BASE` 的 DLL 由 Windows 选址。使用该标志的 `msys-2.0.dll` 版本需在目标环境单独验证并存、父子映像布局和 fork。当前 DLL 基址调整覆盖 `NtMapViewOfSection` 入口。

relay 覆盖经受支持的 AMD64 `NtCreateUserProcess` 入口创建的后代，不接管已有进程、树外进程、绕过该入口的直接系统调用或纯原生进程运行后才动态加载 MSYS 的场景。它要求父子安全上下文与最近已观察的默认对象策略一致。完整 agent 内的默认 DACL 设置成功后会更新基准；未观察的策略改变在创建前拒绝。子进程切换凭据、限制、完整性或 package，默认 DACL 与基准不符，或必要查询失败时，已创建目标在恢复前回收。原生中间进程会驻留 agent 代码，但仅一个创建入口被修改；关闭该模式的默认行为保持不变。

两种受限令牌夹具均使用 `DISABLE_MAX_PRIVILEGE | LUA_TOKEN`、禁用 Administrators，并将当前 logon SID、Everyone、Builtin Users、Authenticated Users 放入 restricting SID 列表；write 模式另加 `WRITE_RESTRICTED`。启动器为对象保留 logon/SYSTEM 授权和 OWNER RIGHTS 限制。测试只在带标记的独立工作目录配置 ACL，将兼容产物和夹具暂存为只读；Git/MSYS 仍从原安装位置加载。完整检查模式的读取也必须通过 restricting SID 检查，生产所需文件读取与执行必须在原策略允许范围内。

上述文件授权是合成夹具的初始策略，不是生产兼容层执行的补权。生产不修改任何磁盘文件或目录 ACL，也不放宽既有 restricted token 的限制；只有原策略已允许的文件位置与访问才可使用。若真实 harness 原策略拒绝某个必要文件，本轮夹具结果不证明该环境已兼容，不能通过额外授权或非受限代理代读取得成功。

`restricted-run.exe` 是测试夹具，不随产品安装，也不是通用沙箱工具。回归验证明确配置的只读文件、拒绝文件、可写目录与对象策略，没有认证任意路径、网络或外部产品的隔离策略。两种令牌的 ConPTY 均复用既有实现及初始策略，已验证终端内 Perl/线程 fork、TTY、尺寸、原生命令、Ctrl+C、作业控制和退出码；交互前后的权限 probe 均要求原有拒绝保持有效。

在受测 Windows Terminal 的交互 Git Bash 会话中，调整窗口大小后立即输入，偶尔会丢失第一个字符。尺寸传递回归验证的是内层窗口收到尺寸变化。

兼容实现依赖 AMD64 ntdll 系统调用入口、Native API 和 MSYS 内部地址布局。入口或目标布局变化时需要重新验证，不承诺所有 Windows/MSYS 版本自动适用。

创建时暂留堆窗口、恢复执行前释放的路径已在 Windows 11 `26300.9974` x64 与 Git for Windows 的 MSYS 3.6.10 验证。`PS_ATTRIBUTE_MEMORY_RESERVE` 属于 Windows Native 进程创建接口。旧 Windows 上能否通过宿主使用的导入槽和实际运行时布局完成同一创建路径，需要独立验证。

测试策略保留安装目录只读和 canary 拒绝边界。项目不创建普通非隔离回退路径，也不通过改写安装目录 ACL 来解决 IPC 授权问题。识别范围与沙箱策略是不同职责；命中 MSYS 不会自动取得额外文件写权限。

## PSEC 下的磁盘文件重定向

在受测的 Git for Windows MSYS 3.6.10 中，Bash 经 Windows 原生启动链接收磁盘文件作为 stdout 或 stderr 时，会在脚本执行前崩溃。文件在 PSEC 内外打开均可复现。

MSYS 从继承的 Windows 标准句柄重建描述符时，会对磁盘文件调用 `QueryDosDeviceW(NULL, …)`，把 NT 设备路径映射到盘符。管道和 Windows `NUL` 走专用识别分支，直接启动的 MSYS 子进程沿用父进程的描述符状态，这些路径都跳过这次枚举。

该枚举在受测 PSEC 中返回 `ERROR_ACCESS_DENIED`。Bash 为 stdout 和 stderr 设置行缓冲时会触发 `fstat`，MSYS 随后在 inode 回退中解引用空路径指针。继承的文件 stdin 也会遇到枚举失败，直接读取成功，显式执行 `fstat` 则复现崩溃。

## MSYS 运行时的共享映像节

Git for Windows 的 MSYS 3.6.10 在 `.cygwin_` 可写共享映像节中保存 `wincap.caps`，其值是进程内的绝对指针。原生 PSEC 对照中，同一份 DLL 的两个实例在不同基址运行时，后启动的实例可能在 `DLL_PROCESS_ATTACH` 读取前一实例的地址并异常退出。保持未对齐实例存活时，共用同一文件的目标成功 0/4，使用字节相同的独立文件则成功 4/4。`BaseNamedObjects` 的隔离作用于有名称的 IPC 对象，映像节的这组共享数据随 DLL 文件映射。

Windows 按文件流维护映像节的共享状态。重新打开同一个文件或通过 NTFS 硬链接加载仍使用同一个文件流。当前兼容层使用原安装文件，`.cygwin_` 继续按文件流共享。命名 IPC 在 PSEC 下使用 Windows 提供的 AppContainer 命名空间，在非 AppContainer 受限令牌下使用本次启动的私有目录。跨进程协作数据的共享范围应与其命名对象一致。[Windows 映像节与文件流](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_section_object_pointers) · [命名空间设计](design.md#hook-的职责)

运行时可将 `wincap` 保存在进程私有、fork 时由子进程自行初始化的存储中。2026 年 11 月 9 日的 Cygwin 邮件补丁曾提出这一改法。MSYS2 的另一份提案检查指针是否落在本进程的映像内，仍保留共享字段。截至 2026 年 11 月 19 日，该 PR 尚未合并。[Cygwin 邮件补丁](https://www.mail-archive.com/cygwin-patches@cygwin.com/msg13326.html) · [MSYS2 PR #403](https://github.com/msys2/msys2-runtime/pull/403)

Winsock 事件表和编号分配需要在同一 AppContainer 的对应 MSYS 对象目录内共享，并和保护其槽位的互斥对象使用同一命名空间。Git for Windows 的上游提案把这些数据移到命名共享内存。独立文件和关闭整个映像节共享均只用于本机对照。套接字继承、事件通知和跨 AppContainer 隔离仍待验证。[Git for Windows PR #148](https://github.com/git-for-windows/msys2-runtime/pull/148)
