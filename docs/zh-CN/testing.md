# 测试说明

生产构建默认不包含开发工具与测试夹具。可用 Windows PowerShell 5.1 或 PowerShell 7 执行 `build.ps1 -Tests` 和集成测试脚本。运行环境需允许创建 PSEC 和受限令牌。默认 Git 根为 `C:\Program Files\Git`，可通过各脚本的 `-GitRoot` 修改。

```powershell
.\build.ps1 -Tests
.\tests\verify.ps1 -Repetitions 10
.\tests\scope.ps1
.\tests\modules.ps1
.\tests\process-chain.ps1
.\tests\process-chain.ps1 -Environment WriteRestricted
.\tests\process-chain.ps1 -Environment FullRestricted
.\tests\git-hook.ps1
.\tests\git-hook.ps1 -Environment WriteRestricted
.\tests\git-hook.ps1 -Environment FullRestricted
.\tests\conpty.ps1
.\tests\conpty.ps1 -Environment WriteRestricted
.\tests\conpty.ps1 -Environment FullRestricted
.\tests\conpty-resize.ps1
.\tests\terminal-session.ps1
.\tests\shim.ps1
.\tests\stdio.ps1
.\tests\late-package.ps1
.\tests\acl.ps1
.\tests\acl.ps1 -Environment WriteRestricted
.\tests\acl.ps1 -Environment FullRestricted
```

| 测试 | 检查内容 |
|---|---|
| `inline-hook-test` | MinHook 计划接口、逻辑 VA/RIP 位移、指令与页面边界、已有跳转串接、批量安装/relay 范围与保护恢复 |
| `identify-test` | EXE 直接导入、间接导入不命中、PE 头跨读取范围和准备失败保留识别结果。检查关闭 EXE 布局时进程路径查询和重新打开文件均为零。创建前预检只打开目标 EXE。无需创建 PSEC |
| `object-security-test` | ACL 最小追加、enabled groups、空/NULL、输入不变、absolute/self-relative 的 owner/group/SACL/control 保留 |
| `stream-write-test` | ConPTY 双向转发共用的写入循环，覆盖连续短写、零进展和写入失败 |
| `acl.ps1` | 真实 MSYS 内显式对象与后续默认设置；有限权限、deny、其他 token、adjust-only/query-only 句柄；-Existing 可直接使用已有受限上下文 |
| `verify.ps1` | 重复 fork 和 Bash 管道、子 shell、命令替换、后台任务与 `uname`，以及读写边界、退出码、原生子进程和 Perl 根与后代的堆窗口释放 |
| `fork.pl` | PID、堆、COW、共享文件偏移、管道、EOF、信号、exec、WNOHANG、嵌套及并发 fork、线程中 fork |
| `scope.ps1` | 省略 `--runtime` 时验证原生根、改名原生程序、按导入名识别、原生子进程无补丁及显式回入。验证默认 Token DACL 保持，查询 Bash 根和 fork 子进程的两个堆原址及分配入口 |
| `modules.ps1` | 用直接导入夹具读取实际 hook 集合，覆盖各布局开关、传播与 ACL 模块、ConPTY 和 relay 配置继承、冲突处理以及关闭所有模块时保留原有文件拒绝 |
| `process-chain.ps1` | 原生入口 → Bash → 一层/三层原生工具 → 兼容入口 → Bash/Perl；真实 fork、二级线程 fork、管道、读写边界、默认 ACL 与退出码 |
| `process-chain.ps1 -Environment WriteRestricted/FullRestricted` | 两种非 AppContainer 令牌下复用完整链路；记录无兼容基线，保持普通 MSYS 会话并存，验证实际受限令牌及文件写入/WRITE_DAC 拒绝 |
| `git-hook.ps1` | 三种隔离模式中运行真实 `git init`、`git add`、`git status`，经 `--native-relay` 触发 MSYS `pre-commit`，并检查成功与拒绝提交、暂存内容和文件权限 |
| `conpty.ps1` | TTY、120×40 尺寸、UTF-8 往返、命令替换、fork、原生子进程、Ctrl+C、STOP/bg/fg、退出码 |
| `conpty-resize.ps1` | 外层 ConPTY 调整窗口后，PSEC 内原生探针在没有键盘输入的情况下观察到尺寸变化。验证自动启用、显式启用的固定尺寸和显式直连 |
| `terminal-session.ps1` | 嵌套会话继承外层的非零光标行列，退出后从外层缓冲区读回启动前的文字。覆盖 Unicode 屏幕、光标移动、正常和失败后的状态恢复、Bash 中文编辑与 Ctrl+C、PowerShell 5.1 参数传递和交互历史 |
| `shim.ps1` | 单文件独立部署、帮助和版本、尺寸参数错误、原生命令尾段、标准流、PSEC 下的原生 relay、fork、ConPTY 和文件日志 |
| `stdio.ps1` | PSEC 下 1 MiB 二进制 stdio 往返、stdin EOF 与管道读端提前关闭。覆盖控制台标准流八种组合、`2>&1`、`NUL`、混合管道、显式直连、内层读屏和写输入。检查 ConPTY 根进程退出后的后代输出和根退出码 |
| `conpty.ps1 -Environment WriteRestricted/FullRestricted` | 同一交互负载，加终端内 Perl 断言（含线程 fork）、可写文件、交互前后原受限令牌及文件写入/WRITE_DAC/读取拒绝 |
| `conpty.ps1 -Environment Existing` | 直接使用调用者已有受限上下文，完成交互与 Perl 负载；不创建测试 token/PSEC，不暂存或设置文件 ACL，不自动套用固定夹具的权限结论 |
| `process-chain.ps1 -NativeRelay` | 原生/MSYS 根 → 一层/三层原生工具 → 直接 MSYS，另测显式嵌套入口、保留挂起状态及原生进程更新默认 DACL 后的继承，支持三种环境参数 |
| `conpty.ps1 -NativeRelay` | 在同一 relay 模式下复用完整交互验收，可与三种环境或 Existing 组合 |
| `late-package.ps1` | 目标到达屏障后才在安装根外放置新 EXE/DLL，验证首次识别、动态模块和 fork。父子进程都检查显式基址、`DYNAMIC_BASE`、`ZeroBits` 两种编码和地址冲突回退 |
| `integrity.ps1` | 按需比较安装目录路径、长度和 SHA-256；不属于日常回归 |

完整性检查用于安装或部署写入逻辑变化、疑似分发文件被修改或发布验收。使用 `tests/integrity.ps1 -CaptureBaseline -Baseline <FILE>` 首次建立快照；后续比较时传入同一个基线文件。

支持 `-EvidenceDirectory` 的测试脚本可为每轮指定独立的日志目录。测试日志和运行状态是本地生成文件。

`git-hook.ps1` 在受测上下文内创建独立工作目录，初始化仓库、暂存文件、检查暂存与干净状态并运行提交。Git 自动拉起的 hook 也在受测上下文运行。完整受限令牌如果无法列出仓库祖先目录，文件型 ref 后端可能拒绝建立 `.git/HEAD`。用例核对该目录访问失败和 Git 诊断，再用宿主初始化夹具，继续在原令牌下检查后续命令。验证同时检查 hook 的计算结果、隔离文件访问和真实仓库状态。

`scope` 的七项场景要求实际成功。`process-chain` 从运行 MSYS 前的原生入口记录隔离启动器默认 ACL，并检查后续所有原生桥接保持同一 ACL；目标必须完成 Perl 测试、输出工作负载标记并逐层返回 37。拒绝或超时不能算作成功。

CTest 包含独立单测以及 PSEC、受限令牌、relay 和 ACL 集成套件。集成套件优先使用 pwsh，未找到时使用 Windows PowerShell。可用 CMake 缓存变量 `MSYS_SANDBOX_COMPAT_POWERSHELL` 显式选择解释器。集成测试串行运行以避免共享状态冲突，并使用当前构建目录的产物。

```powershell
# 在 tools/msvc-env.ps1 配置过的工具链环境中
ctest --test-dir build --output-on-failure
```

各集成脚本的 `-BinaryDirectory` 默认指向项目根目录的 `build/bin`，并从同一构建根定位 `tools/psec-run.exe` 和 `tests/bin` 下的夹具。从其他构建目录运行时显式指定该参数，CTest 会自动传入。源负载位于 `tests/fixtures`，独立单测位于 `tests/unit`。生产安装包不包含这些文件。

## 发布验证

Windows 发布工作流在 `windows-2025` 上构建 Release，运行七项定向 CTest，并将 CMake 的 `Runtime` 组件打包。ZIP 内含两个独立程序、项目许可证和第三方许可声明。使用和设计文档在仓库中查阅。工作流在解压后检查文件清单并验证两个程序。手动触发会将发布文件和 `SHA256SUMS.txt` 上传为 Actions 产物。推送版本标签时，后续任务核对产物校验和，然后带附件直接公开发布 GitHub Release。 [Windows 发布工作流](https://github.com/hzqmwne/msys-sandbox-compat/blob/main/.github/workflows/release.yml)

原生 PSEC 回归和 fork 压测在支持原生 PSEC 的 Windows 11 x64 宿主上进行。托管发布工作流使用普通令牌验证解压包。如需复现 v0.1.0 解压包的原生 PSEC 对照，先核对校验和，再运行以下命令。

```powershell
.\tests\release.ps1 -PackageDirectory PATH_TO_EXTRACTED_ZIP -Version 0.1.0 -Psec
.\tests\release.ps1 -PackageDirectory PATH_TO_EXTRACTED_ZIP -Version 0.1.0 -Psec -GitRoot C:\msys64
```

该测试用包内的 `psec-run` 在 PSEC 1.0 中启动 shim，检查经 `cmd.exe` 进入 Bash 的传播、管道和 fork、目标退出码及文件读取拒绝。MXC 的对照使用 `wxc-exec.exe`，记录同一策略下的原版启动与经 shim 启动的结果。 [MXC ProcessContainer 实测](mxc-compatibility.md#实测命令)

`Existing` 模式需由实际 harness 在其受限执行上下文内显式运行，不注册为普通宿主的 CTest。调用者原策略应已允许兼容产物、MSYS 安装文件、Perl 夹具的读取/执行及测试工作目录写入；缺少权限时保留拒绝。该模式只验收原上下文中的工作负载，原策略的具体拒绝路径和 ACL/token 保留情况还需按实际配置单独验证。

relay 链路要求原生桥接只存在一个创建 hook，其余入口与 MSYS 地址区保持原样。MSYS 当次设置后的后代应继承对应的默认 ACL。直接回入必须完成真实 Perl/fork/管道及退出码。挂起用例要求调用者 `ResumeThread` 看到原挂起计数 1。另用原生夹具追加零权限 ACE 改变默认 DACL，验证后代读到更新后的 ACL、relay 继续进入 Bash、父端恢复初始 ACL。

日常选择与改动相关的套件：进程创建/识别/注入/传播变化检查 fork、作用范围和相关进程链；控制台变化检查交互；文档变化检查文档即可。完整 CTest 矩阵用于涉及多个运行机制的改动或阶段验收，已有通过结果不因无关改动反复重跑。权限拒绝与策略保留检查继续随相关工作负载执行。完整性脚本独立按需运行，不加入 CTest。

常规 `verify` 默认一轮；重复 fork/shell 使用 `verify.ps1 -Repetitions 10`。进程链与 ConPTY 的线程 fork 默认一次，压力验收显式使用 `-ThreadRepetitions 10`（最多 1000）。也可通过兼容入口运行 `tests/fixtures/fork.pl 100`。测试以退出码、TAP 成败和真实工作负载为准。Perl 根与后代的回归同时检查堆窗口释放 trace。

夹具 `import-name-runtime` 只在测试输出目录生成同名 `msys-2.0.dll`，用于验证导入名约定，不替换安装目录中的运行时。

`restricted-run` 只修改带 `.restricted-fixture` 标记的测试目录及其受控文件 ACL。暂存副本包含兼容产物与测试夹具，MSYS 分发文件保持原位。非 AppContainer 受限令牌的进程链测试将同令牌下原版 Bash 的执行结果保存为 `raw-baseline.*`，并要求 `native-depth-*` 完成真实工作负载。PSEC 的 `verify` 按兼容负载和权限边界验收。两种非 AppContainer 令牌的固定 SID、对象 ACL 和能力边界见 [兼容范围](compatibility.md)。

测试设置的 ACL 是夹具初始条件，不能要求生产复制这些 ACL 操作。生产验收应使用原有策略已允许的部署位置，保留原 token、文件与对象访问限制；对只读写入、WRITE_DAC 和拒绝读取等行为同时检查拒绝。当前检查覆盖固定夹具，不能仅凭文件内容完整性或几个 canary 宣称任意生产环境的全部限制均已验证。

## PSEC fork 压测与地址采样

2026-11-24 至 25 日的对照使用 Windows 11 x64 `26300.9974`、原生 PSEC 1.0、shim 和 `C:\msys64` 的官方 MSYS2（运行时 3.6.12-1、Bash 5.3.20-3、Perl 5.44.0-1）。每轮新建 Perl 根进程并运行 `tests/fixtures/fork.pl 100`。通过条件包括退出码 0、完整 114 项 TAP（含 100 项副线程 fork）和无 fork 诊断。

| 创建窗口 | 并行轮数 | 通过 | 墙钟耗时 |
| --- | --- | --- | --- |
| `[24,64)` GiB | 4 × 100 | 399/400 | 20 分 22 秒 |
| `[24,64)` GiB | 8 × 100 | 795/800 | 28 分 30 秒 |
| `[8,64)` GiB | 8 × 100 | 800/800 | 34 分 16 秒 |
| `[8,64)` GiB，v0.1.1 复跑 | 8 × 100 | 800/800 | 35 分 58 秒 |

4 路组的失败发生在子进程为父线程栈预留地址时。8 路组两次报告父子 DLL 基址不同，一次报告 Perl XS DLL 的目标地址已被占用，两次只得到子进程退出状态 `0xc0000018`。三条已知 DLL 目标区间都落在 `[8,24)` GiB。Perl 失败轮没有在冲突时采到地址图。

扩大窗口后，两次 8 路压测均全部通过，各完成 80,000 次副线程 fork，无 fork 诊断。启动器、运行时、Perl 和夹具的文件哈希与 8 路基线相同。v0.1.1 由本地源码构建，先通过全部 32 项 Release CTest，再跑最后一轮压测。耗时按各轮宿主负载实测。

旧窗口下，独立诊断采集了 846 个到达就绪阶段的 fork 子进程。Windows 初始栈有 24 个落在 24 GiB 以下，暂留窗口内为零。窗口释放后，MSYS 的工作线程栈有 22 个落在原窗口内。受测子进程中的工作线程均在两次相关 DLL 映射和 XS DLL 目标预留之后创建。

原生 PSEC 冷启动对照为两套 Bash 的每种布局各采样 64 次。其中一次官方 MSYS2 在关闭地址布局处理时启动失败，Windows 初始栈和 PEB/TEB 保留都落在约 36.49 GiB，挡住运行时的 `[32,40)` GiB cygheap 预留。其余 255 次成功。成功样本的 Windows 初始 Bash 映像落在约 1.10–2.92 TiB，初始栈落在约 4–1023 GiB。全部是高熵 ASLR，同一次开机采样，未涉及第三方 DLL 注入。

独立探针在本机验证了至多 64 TiB 的单段创建时预留，提交量为零。已安装的非 `DYNAMIC_BASE` AMD64 DLL 在官方 MSYS2 中落在 `[14,24)` GiB，在 Git for Windows 中落在 `[8,24)` GiB。窗口与初始 EXE 相交可阻止进程创建，窗口保护的时间也止于父进程释放它。见 [ADR-0011](decisions/0011-release-heap-reservations-before-start.md)。

## 映像地址对照

早期原生 PSEC 对照使用 Windows 11 `26300.9974` 和 Git for Windows MSYS `3.6.10` 的同一套原安装文件，分别验证映像匹配范围和入参条件。

| 实验改写条件 | 结果 |
|---|---|
| `msys-2.0.dll` 且未指定基址 | Bash 常见操作及 Git init/add/status 通过。三轮 Perl 均在首次 fork 因 `msys-crypt-2.dll` 父子地址不同而失败 |
| `perl.exe` 直接静态导入的 MSYS DLL 且未指定基址 | `msys-2.0.dll` 和 `msys-perl5_42.dll` 父子同址。三轮 Perl 在同一个传递依赖上失败 |
| `perl.exe` 的全部传递静态 MSYS 依赖且未指定基址 | 最小 fork 和独立动态夹具各通过 3/3。完整 Perl fork 负载 0/3，失败发生在重载 `Time::HiRes` 或 `List::Util` 的 XS DLL 时 |
| 当时按传递导入链识别 DLL，且只在初始 `*BaseAddress` 与 `ZeroBits` 均为零时改写 | `verify` 11/11、`late-package` 及 Bash 内 Git init/add/status 通过。带追踪的回归记录 1,207 次相关 DLL 映射，两项入参均为零 |

单独加载 `Time::HiRes` 或 `List::Util` 时，传递静态依赖版各通过 1/3，同轮较宽范围的对照各通过 3/3。传递静态依赖版的成功样本中，MSYS 自行把 XS DLL 重载到了父进程的实际基址，父子都偏离 PE 首选地址。子进程使用继承的 XS 函数引用完成了调用。失败样本记录了父进程保存的函数地址和子进程多次尝试的映射位置。

当前 `late-package` 验证安装根外的晚装 DLL 也能请求首选址。Perl 父子进程都检查显式基址得到保留、启用 `DYNAMIC_BASE` 的 DLL 交给 Windows，以及首选址已占用时按原请求换址。低基址探针覆盖数量和稀疏位图允许首选址，以及数量限制禁止首选址的情况。独立探针另验证 `LoadLibraryW` 遇到首选映像区间内的一页占用时能换址，并正确应用重定位。引入该方案时，本机 Release 构建的完整 CTest 矩阵通过。见 [ADR-0012](decisions/0012-prefer-dll-image-base-at-map.md)。

在本机 Git for Windows 2.56.1 安装下检查了 352 个 EXE 的普通导入。259 个直接导入 `msys-2.0.dll`，均位于 `usr` 子树，其中 18 个位于 `usr/lib` 或 `usr/libexec`。按旧识别目录规则查找未发现只有传递依赖的 EXE。
