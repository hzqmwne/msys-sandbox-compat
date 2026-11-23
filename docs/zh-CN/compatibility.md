# 兼容范围

[English](../compatibility.md)

当前项目为 0.1 开发版本。生产部署使用单文件 `msys-sandbox-compat-shim.exe`，可在普通令牌或启动器提供的受限上下文中运行。psec-run 是独立的验证工具。已验证的受限组合包括 Windows 26300.9974 x64、原生 PSEC 1.0、MSYS 3.6.10，目标包含真实内部 Bash、Perl 和 GNU 工具。

| 能力 | 当前范围 |
|---|---|
| 原版 EXE 与 `msys-2.0.dll` | 使用原安装文件，不修改分发包 |
| fork、exec、管道、信号及线程中 fork | 受测组合通过回归与压力测试 |
| MSYS 连续子进程链 | 通过创建 hook 传播 |
| 进程链中的原生子进程 | 默认 relay 只启用创建 hook。用 `--native-relay=off` 关闭原生传播 |
| 原生根显式调用兼容入口 | 已由公开作用范围测试验证 |
| MSYS 原生后代调用兼容入口启动原生目标 | 关闭 relay 的作用范围对照通过，原生目标继承既有 token 默认 DACL |
| MSYS 创建原生中间程序后显式回入 MSYS | 一层/三层原生桥接后 Bash、Perl、线程中 fork、管道与退出码通过回归 |
| 原生中间程序直接创建 MSYS | 默认 relay 覆盖 AMD64 和 WoW64 原生首进程及中间进程，支持两种位数交替后返回 AMD64 MSYS。配套宿主与 agent 继续使用 AMD64 产物 |
| relay 的原生根、显式嵌套入口及挂起创建 | 受测 PSEC 和两种固定令牌均通过；仅创建入口被修改，保留退出码与挂起状态 |
| 运行中新出现的 EXE/DLL | EXE 按直接导入识别，符合映射条件的 DLL 在首次映射时处理 |
| ConPTY | 支持从已有 Windows Terminal 标签页正常启动。compat 通过系统 API 创建内层，外层继续由原终端管理。PSEC 和两种固定非 AppContainer 受限令牌通过交互回归。PSEC 双层 ConPTY 探针覆盖尺寸跟随、光标继承及退出后保留外层内容 |
| 传统控制台中的 cmd | 存在可用控制台且至少一路是控制台句柄时自动使用内层 ConPTY，其余各路保留原重定向。官方 MSYS2 与 Git for Windows 验证了八种组合的 `isatty`、读写去向及 `/dev/tty` 行为。`--terminal=inherit` 和自动模式下三路均重定向时直连。见 [ADR-0014](decisions/0014-conpty-preserve-redirected-stdio.md) |
| Git `pre-commit` | 在已初始化的工作区，原生 Git 通过默认 relay 自动启动 MSYS hook。PSEC 和两种固定受限令牌通过提交成功、hook 拒绝提交及文件边界回归 |
| 非 AppContainer write-restricted 令牌 | 固定夹具通过 Bash/Perl、fork、原生桥接、管道、文件边界及普通 MSYS 共存回归 |
| 非 AppContainer 完整 restricting SID 检查令牌 | 同一固定夹具通过上述工作负载与边界回归 |
| 验收依据 | 参照相关配置构造的 PSEC 与两种受限令牌模型；按有效安全策略与进程创建条件判断适用性 |
| 只复制旁置文件即可自动生效 | 尚未提供可靠通用加载入口 |

表中结果使用默认 MSYS 模块配置。可按模块关闭处理做对照，关闭后能支持哪些负载取决于实际运行时、隔离配置和启动链。见[兼容模块对照](getting-started.md#兼容模块对照)。

验证按底层隔离机制与配置组织；在相关安全策略、进程创建与控制台条件一致时，现有模型可代表上层启动环境。当前验收不要求先接入上层 harness，也不按产品名称分别建立兼容实现。

EXE 识别覆盖普通导入表中直接导入 `msys-2.0.dll` 的 AMD64 程序。纯原生根启动后才 LoadLibrary MSYS、仅 delay import 或仅由中间 DLL 引入运行时，均在预先识别范围外。Cygwin 不在当前支持范围内。完整 MSYS 兼容进程中的 DLL 映射规则适用于任意路径。首选址不可用时由 Windows 按原请求选址，fork 同址重载仍可能失败。见 [DLL 映射范围](design.md#dll-映射范围)。

设置 PE `DYNAMIC_BASE` 的 DLL 由 Windows 选址。使用该标志的 `msys-2.0.dll` 版本需在目标环境单独验证并存、父子映像布局和 fork。当前 DLL 基址调整覆盖 `NtMapViewOfSection` 入口。

MSYS2 官方 `msys2-runtime` 3.6.12-1 的 `msys-2.0.dll` 启用 `DYNAMIC_BASE`。这是上游有意恢复的链接配置。受测的 DLL、`bash.exe` 和 `uname.exe` 均未设置 `HIGH_ENTROPY_VA`，两个 EXE 也未设置 `DYNAMIC_BASE`。进程实际采用的 ASLR 策略还取决于目标 Windows 和启动环境。[MSYS2 runtime #381](https://github.com/msys2/msys2-runtime/pull/381) · [MSYS2 packages #6820](https://github.com/msys2/MSYS2-packages/pull/6820)

relay 覆盖经 AMD64 原生 `NtCreateUserProcess` 入口创建的后代，含经过该入口的 WoW64 调用。Windows 决定子进程的 token 和默认 DACL，各进程用自己的主 token 初始化 ACL 适配。IPC 重定向使用启动树提供的目录名，并受该目录的实际权限约束。用 `--native-relay=off` 让自动传播在原生进程处结束。路径细节见 [当前设计](design.md#原生-relay) 和 [ADR-0018](decisions/0018-resolve-acl-context-in-each-process.md)。

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

## PSEC 下的 Microsoft Store PowerShell

在 Windows 26300.9974 x64、PSEC 1.0 下，Microsoft Store PowerShell 7.7.0 可作为 PSEC 直接启动的首进程。执行别名和包内 `pwsh.exe` 均通过，实际进程保留 `Microsoft.PowerShell` 包身份并处于 AppContainer。原生跟踪确认，外层 `psec-run` 的 `CreateProcessW` 携带 PSEC 启动属性，转入 `processmodel!CreateProcessAsUserInsideSecurityEnvironment`。由该 PowerShell 再调用 compat 启动 Bash，Bash 通过了 fork 验证。

同一策略下，PSEC 内无包身份的父进程启动商店版 PowerShell 时遇到 Windows 创建错误。作为 compat 的目标，执行别名报 Win32 1920，包内 EXE 报 Win32 5。先经 compat 启动 Bash，再从 Bash 启动任一入口，均得到 `Permission denied` 和退出码 126。移除 compat 的原生进程创建对照仍复现 Windows 错误。同包的商店版 PowerShell 父进程在同一 PSEC 策略下可以通过任一入口启动 PowerShell 子进程。

文件 ACL 对普通用户授予读取权限，并通过条件 ACE 为 `WIN://SYSAPPID` 含 PowerShell 包族名的令牌授予执行权限。受测无包身份父进程可以读取和建立 `SEC_IMAGE` 文件映射，直接请求 `FILE_EXECUTE` 仍被拒绝。普通 Windows 父进程通过 AppModel 的包激活路径获得包令牌并重试，成功创建的子进程带有该包族属性。[Microsoft 条件 ACE 说明](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-) · [MSIX 命令行激活](https://devblogs.microsoft.com/insidemsix/activation-via-command-line/)

在 PSEC 内无包身份的父进程中，两条路径都在映像文件打开阶段返回。执行别名的首个 `NtCreateUserProcess` 返回 `STATUS_IO_REPARSE_TAG_NOT_HANDLED`，包内路径则返回 `STATUS_ACCESS_DENIED`。随后 Windows 分别调用 `AicGetPackageActivationTokenForAlias` 和 `AicGetPackageActivationTokenForFilePath`。两条路径都观测到 ALPC 建连返回 `STATUS_ACCESS_DENIED`，随后 AppModel RPC 报 1753（`EPT_S_NOT_REGISTERED`），均未再次调用 `NtCreateUserProcess`。在别名对照中，普通父进程连到 `\RPC Control` 下的端点并成功。PSEC 父进程请求相同端点名，但路径位于本 AppContainer 的命名空间下，建连被拒绝。观测定位到了建连失败，未进一步区分内核的具体授权检查。[Windows 系统错误 1753](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1700-3999-)

同包的 PSEC 父进程走 Windows 的 `processmodel!BrokerSandboxedCreateProcess`，创建出的商店版子进程仍具有 PowerShell 包身份并留在 AppContainer。

测试中实际进程没有包身份的 PowerShell 7.6.9 通过了 `PSEC → compat → pwsh → Bash` 和 `PSEC → compat → Bash → pwsh` 两条路径。判断这项限制时，应以实际 PowerShell 进程的包身份和启动链为准。

## MSYS 运行时的共享映像节

本机复核中，普通 Windows Bash 与原生 PSEC 下的兼容 Bash 同时使用 Git for Windows MSYS 3.6.10 的同一路径 DLL，两者的 DLL 实载基址都是 `0x210040000`。两轮均完成 Bash 管道、命令替换、Git 操作和 Perl fork，PSEC 端按预期退出 37。PSEC 端沿用由 `4d9e784` 引入的 section 首选基址策略。适用条件见 [DLL 映射决策](decisions/0012-prefer-dll-image-base-at-map.md)。

历史对照中，保持使用不同 DLL 基址的 PSEC 实例存活时，共用同一文件的目标成功 0/4，使用字节相同的独立文件则成功 4/4。该运行时的 `.cygwin_` 可写共享节保存 `wincap.caps` 绝对指针。实例落在不同基址时，后启动的实例可能在 `DLL_PROCESS_ATTACH` 访问前一实例的地址。这个条件仍可能出现在映像无法对齐的组合。

Windows 按文件流维护映像节的共享状态。重新打开同一个文件或通过 NTFS 硬链接加载仍使用同一个文件流。当前兼容层使用原安装文件，`.cygwin_` 继续按文件流共享。命名 IPC 在 PSEC 下使用 Windows 提供的 AppContainer 命名空间，在非 AppContainer 受限令牌下使用本次启动的私有目录。跨进程协作数据的共享范围应与其命名对象一致。[Windows 映像节与文件流](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_section_object_pointers) · [命名空间设计](design.md#hook-的职责)

运行时可将 `wincap` 保存在进程私有、fork 时由子进程自行初始化的存储中。2026 年 11 月 9 日的 Cygwin 邮件补丁曾提出这一改法。MSYS2 的另一份提案检查指针是否落在本进程的映像内，仍保留共享字段。截至 2026 年 11 月 19 日，该 PR 尚未合并。[Cygwin 邮件补丁](https://www.mail-archive.com/cygwin-patches@cygwin.com/msg13326.html) · [MSYS2 PR #403](https://github.com/msys2/msys2-runtime/pull/403)

Winsock 事件表和编号分配需要在同一 AppContainer 的对应 MSYS 对象目录内共享，并和保护其槽位的互斥对象使用同一命名空间。Git for Windows 的上游提案把这些数据移到命名共享内存。独立文件和关闭整个映像节共享均只用于本机对照。套接字继承、事件通知和跨 AppContainer 隔离仍待验证。[Git for Windows PR #148](https://github.com/git-for-windows/msys2-runtime/pull/148)
