# 测试说明

生产构建默认不包含开发工具与测试夹具，回归前使用 `build.ps1 -Tests`。测试应从允许创建 PSEC 和受限令牌的普通 PowerShell 7 执行，默认 Git 根为 `C:\Program Files\Git`，可通过各脚本的 `-GitRoot` 修改。

```powershell
.\build.ps1 -Tests
.\tests\verify.ps1 -Repetitions 10
.\tests\scope.ps1
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
.\tests\stdio.ps1
.\tests\late-package.ps1
.\tests\acl.ps1
.\tests\acl.ps1 -Environment WriteRestricted
.\tests\acl.ps1 -Environment FullRestricted
```

| 测试 | 检查内容 |
|---|---|
| `inline-hook-test` | MinHook 计划接口、逻辑 VA/RIP 位移、指令与页面边界、已有跳转串接、批量安装/relay 范围与保护恢复 |
| `identify-test` | 直接导入快速路径、共享依赖去重、环、节点上限、深依赖链及识别/准备失败语义；无需创建 PSEC |
| `object-security-test` | ACL 最小追加、enabled groups、空/NULL、输入不变、absolute/self-relative 的 owner/group/SACL/control 保留 |
| `stream-write-test` | ConPTY 双向转发共用的写入循环，覆盖连续短写、零进展和写入失败 |
| `acl.ps1` | 真实 MSYS 内显式对象与后续默认设置；有限权限、deny、其他 token、adjust-only/query-only 句柄；-Existing 可直接使用已有受限上下文 |
| `verify.ps1` | 原版失败基线、重复 fork 和 Bash 管道、子 shell、命令替换、后台任务与 `uname`，以及读写边界、退出码、原生子进程和 Perl 根与后代的堆窗口释放 |
| `fork.pl` | PID、堆、COW、共享文件偏移、管道、EOF、信号、exec、WNOHANG、嵌套及并发 fork、线程中 fork |
| `scope.ps1` | 省略 `--runtime` 时验证原生根、改名原生程序、按导入名识别、原生子进程无补丁及显式回入。验证默认 Token DACL 保持，查询 Bash 根和 fork 子进程的两个堆原址及分配入口 |
| `process-chain.ps1` | 原生入口 → Bash → 一层/三层原生工具 → 兼容入口 → Bash/Perl；真实 fork、二级线程 fork、管道、读写边界、默认 ACL 与退出码 |
| `process-chain.ps1 -Environment WriteRestricted/FullRestricted` | 两种非 AppContainer 令牌下复用完整链路；记录无兼容基线，保持普通 MSYS 会话并存，验证实际受限令牌及文件写入/WRITE_DAC 拒绝 |
| `git-hook.ps1` | 三种隔离模式中运行真实 `git init`、`git add`、`git status`，经 `--native-relay` 触发 MSYS `pre-commit`，并检查成功与拒绝提交、暂存内容和文件权限 |
| `conpty.ps1` | TTY、120×40 尺寸、UTF-8 往返、命令替换、fork、原生子进程、Ctrl+C、STOP/bg/fg、退出码 |
| `conpty-resize.ps1` | 外层 ConPTY 调整窗口后，PSEC 内原生探针在没有键盘输入的情况下观察到内层尺寸变化，显式 80×24 会话保持固定 |
| `terminal-session.ps1` | 非 UTF-8 初始控制台中的嵌套会话，读回实际 Unicode 屏幕和光标移动，验证正常/启动失败后的状态恢复。通过 `run.ps1` 验证 Bash 中文方向键编辑、PATH、尺寸与 Ctrl+C，以及 Windows PowerShell 5.1 中文输入输出和真实 PSReadLine 交互命令的历史保存 |
| `stdio.ps1` | PSEC 下 1 MiB 二进制 stdio 往返、stdin EOF 与管道读端提前关闭。在控制台中分别重定向 stdout、stderr 到文件，并检验原始字节和未重定向流。检查 ConPTY 根进程退出后的后代输出和根退出码 |
| `conpty.ps1 -Environment WriteRestricted/FullRestricted` | 同一交互负载，加终端内 Perl 断言（含线程 fork）、可写文件、交互前后原受限令牌及文件写入/WRITE_DAC/读取拒绝 |
| `conpty.ps1 -Environment Existing` | 直接使用调用者已有受限上下文，完成交互与 Perl 负载；不创建测试 token/PSEC，不暂存或设置文件 ACL，不自动套用固定夹具的权限结论 |
| `process-chain.ps1 -NativeRelay` | 原生/MSYS 根 → 一层/三层原生工具 → 直接 MSYS，另测显式嵌套入口、保留挂起状态及默认对象策略改变时拒绝；支持三种环境参数 |
| `conpty.ps1 -NativeRelay` | 在同一 relay 模式下复用完整交互验收，可与三种环境或 Existing 组合 |
| `late-package.ps1` | 运行目标到达屏障后才放置新 EXE/DLL，验证首次识别、动态模块和 fork |
| `integrity.ps1` | 按需比较安装目录路径、长度和 SHA-256；不属于日常回归 |

完整性检查仅在安装/部署写入逻辑变化、怀疑分发文件被修改或发布验收确有需要时执行，不在每轮兼容测试或每次提交后重复运行。若需要首次建立比较基线，使用 `tests/integrity.ps1 -CaptureBaseline`；已有基线时不要先覆盖，应直接比较。基线默认位于 `unused/evidence/git-before.json`，可通过 `-Baseline` 指定单独快照。

各脚本默认输出到 `unused/evidence/current/<suite>`，也可使用 `-EvidenceDirectory` 保留不同轮次。状态和 HOME 位于 `unused/runtime`。这些文件不进入 Git 或发布包。

`git-hook.ps1` 在受测上下文内创建独立工作目录，初始化仓库、暂存文件、检查暂存与干净状态并运行提交。Git 自动拉起的 hook 也在受测上下文运行。完整受限令牌如果无法列出仓库祖先目录，文件型 ref 后端可能拒绝建立 `.git/HEAD`。用例核对该目录访问失败和 Git 诊断，再用宿主初始化夹具，继续在原令牌下检查后续命令。验证同时检查 hook 的计算结果、隔离文件访问和真实仓库状态。

`scope` 的七项场景要求实际成功。`process-chain` 从运行 MSYS 前的原生入口记录隔离启动器默认 ACL，并检查后续所有原生桥接保持同一 ACL；目标必须完成 Perl 测试、输出工作负载标记并逐层返回 37。拒绝或超时不能算作成功。

CTest 包含独立单测；找到 pwsh 后注册 PSEC、受限令牌、relay 和 ACL 集成套件，集成测试串行运行以避免共享状态冲突。CTest 使用当前构建目录的产物：

```powershell
# 在 tools/msvc-env.ps1 配置过的工具链环境中
ctest --test-dir build --output-on-failure
```

各集成脚本的 `-BinaryDirectory` 默认指向项目根目录的 `build/bin`，并从同一构建根定位 `tools/psec-run.exe` 和 `tests/bin` 下的夹具。从其他构建目录运行时显式指定该参数，CTest 会自动传入。源负载位于 `tests/fixtures`，独立单测位于 `tests/unit`。生产安装包不包含这些文件。

`Existing` 模式需由实际 harness 在其受限执行上下文内显式运行，不注册为普通宿主的 CTest。调用者原策略应已允许兼容产物、MSYS 安装文件、Perl 夹具的读取/执行及测试工作目录写入；缺少权限时保留拒绝。该模式只验收原上下文中的工作负载，原策略的具体拒绝路径和 ACL/token 保留情况还需按实际配置单独验证。

relay 链路要求原生桥接只存在一个创建 hook，其余入口与 MSYS 地址区保持原样。MSYS 当次设置后的后代默认 ACL 保持一致，允许它与首次 native 入口的启动快照不同。直接回入必须完成真实 Perl/fork/管道及退出码。挂起用例要求调用者 `ResumeThread` 看到原挂起计数 1。策略负例由原生夹具临时收紧自身默认对象 DACL，要求创建返回访问拒绝、目标未运行，随后恢复夹具初始策略。

日常选择与改动相关的套件：进程创建/识别/注入/传播变化检查 fork、作用范围和相关进程链；控制台变化检查交互；文档变化检查文档即可。完整 CTest 矩阵用于涉及多个运行机制的改动或阶段验收，已有通过结果不因无关改动反复重跑。权限拒绝与策略保留检查继续随相关工作负载执行。完整性脚本独立按需运行，不加入 CTest。

常规 `verify` 默认一轮；重复 fork/shell 使用 `verify.ps1 -Repetitions 10`。进程链与 ConPTY 的线程 fork 默认一次，压力验收显式使用 `-ThreadRepetitions 10`（最多 1000）。也可通过兼容入口运行 `tests/fixtures/fork.pl 100`。测试以退出码、TAP 成败和真实工作负载为准。Perl 根与后代的回归同时检查堆窗口释放 trace。

夹具 `import-name-runtime` 只在测试输出目录生成同名 `msys-2.0.dll`，用于验证导入名约定，不替换安装目录中的运行时。

`restricted-run` 只修改带 `.restricted-fixture` 标记的测试目录及其受控文件 ACL；两种令牌的固定 SID、对象 ACL 和能力边界见 [兼容范围](compatibility.md)。暂存副本只包含兼容产物与测试夹具，MSYS 分发文件保持原位。`raw-baseline.*` 保存同令牌下原版 Bash 的结果，`native-depth-*` 必须完成真实工作负载才通过；基线失败不能代替兼容成功。

测试设置的 ACL 是夹具初始条件，不能要求生产复制这些 ACL 操作。生产验收应使用原有策略已允许的部署位置，保留原 token、文件与对象访问限制；对只读写入、WRITE_DAC 和拒绝读取等行为同时检查拒绝。当前检查覆盖固定夹具，不能仅凭文件内容完整性或几个 canary 宣称任意生产环境的全部限制均已验证。

## 映像地址对照

Windows 11 `26300.9974`、Git for Windows MSYS `3.6.10` 的原生 PSEC 对照使用同一套原安装文件，分别验证映像匹配范围和入参条件。

| 实验改写条件 | 结果 |
|---|---|
| `msys-2.0.dll` 且未指定基址 | Bash 常见操作及 Git init/add/status 通过。三轮 Perl 均在首次 fork 因 `msys-crypt-2.dll` 父子地址不同而失败 |
| `perl.exe` 直接静态导入的 MSYS DLL 且未指定基址 | `msys-2.0.dll` 和 `msys-perl5_42.dll` 父子同址。三轮 Perl 在同一个传递依赖上失败 |
| `perl.exe` 的全部传递静态 MSYS 依赖且未指定基址 | 最小 fork 和独立动态夹具各通过 3/3。完整 Perl fork 负载 0/3，失败发生在重载 `Time::HiRes` 或 `List::Util` 的 XS DLL 时 |
| 保留当前 DLL 范围，仅在初始 `*BaseAddress` 与 `ZeroBits` 均为零时改写 | `verify` 11/11、`late-package` 及 Bash 内 Git init/add/status 通过。带追踪的回归记录 1,207 次相关 DLL 映射，两项入参均为零 |

单独加载 `Time::HiRes` 或 `List::Util` 时，传递静态依赖版各通过 1/3，同轮较宽范围的对照各通过 3/3。传递静态依赖版的成功样本中，MSYS 自行把 XS DLL 重载到了父进程的实际基址，父子都偏离 PE 首选地址。子进程使用继承的 XS 函数引用完成了调用。失败样本记录了父进程保存的函数地址和子进程多次尝试的映射位置。

这几组结果来自独立实验构建。正式回归入口仍按 [当前设计](design.md#dll-映射范围) 判定，非零基址的映射路径需要独立样本。
