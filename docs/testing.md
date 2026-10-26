# 测试说明

生产构建默认不包含开发工具与测试夹具，回归前使用 `build.ps1 -Tests`。测试应从允许创建 PSEC 和受限令牌的普通 PowerShell 7 执行，默认 Git 根为 `C:\Program Files\Git`，可通过各脚本的 `-GitRoot` 修改。

```powershell
.\build.ps1 -Tests
.\tests\verify.ps1 -Repetitions 10
.\tests\scope.ps1
.\tests\process-chain.ps1
.\tests\process-chain.ps1 -Environment WriteRestricted
.\tests\process-chain.ps1 -Environment FullRestricted
.\tests\conpty.ps1
.\tests\conpty.ps1 -Environment WriteRestricted
.\tests\conpty.ps1 -Environment FullRestricted
.\tests\late-package.ps1
.\tests\acl.ps1
.\tests\acl.ps1 -Environment WriteRestricted
.\tests\acl.ps1 -Environment FullRestricted
```

| 测试 | 检查内容 |
|---|---|
| `identify-test` | 直接导入快速路径、共享依赖去重、环、节点上限、深依赖链及识别/准备失败语义；无需创建 PSEC |
| `object-security-test` | ACL 最小追加、enabled groups、空/NULL、输入不变、absolute/self-relative 的 owner/group/SACL/control 保留 |
| `acl.ps1` | 真实 MSYS 内显式对象与后续默认设置；有限权限、deny、其他 token、adjust-only/query-only 句柄；-Existing 可直接使用已有受限上下文 |
| `verify.ps1` | 原版失败基线、重复 fork/shell、读写边界、退出码和原生子进程；10 轮共 25 项 |
| `fork.pl` | PID、堆、COW、共享文件偏移、管道、EOF、信号、exec、WNOHANG、嵌套及并发 fork、线程中 fork |
| `scope.ps1` | 原生根、改名原生程序、按导入名识别、原生子进程无补丁、原生根显式回入、MSYS 原生后代回入及默认 Token DACL 保持 |
| `process-chain.ps1` | 原生入口 → Bash → 一层/三层原生工具 → 兼容入口 → Bash/Perl；真实 fork、二级线程 fork、管道、读写边界、默认 ACL 与退出码 |
| `process-chain.ps1 -Environment WriteRestricted/FullRestricted` | 两种非 AppContainer 令牌下复用完整链路；记录无兼容基线，保持普通 MSYS 会话并存，验证实际受限令牌及文件写入/WRITE_DAC 拒绝 |
| `conpty.ps1` | TTY、120×40 尺寸、命令替换、fork、原生子进程、Ctrl+C、STOP/bg/fg、退出码 |
| `conpty.ps1 -Environment WriteRestricted/FullRestricted` | 同一交互负载，加终端内 Perl 断言（含线程 fork）、可写文件、交互前后原受限令牌及文件写入/WRITE_DAC/读取拒绝 |
| `conpty.ps1 -Environment Existing` | 直接使用调用者已有受限上下文，完成交互与 Perl 负载；不创建测试 token/PSEC，不暂存或设置文件 ACL，不自动套用固定夹具的权限结论 |
| `process-chain.ps1 -NativeRelay` | 原生/MSYS 根 → 一层/三层原生工具 → 直接 MSYS，另测显式嵌套入口、保留挂起状态及默认对象策略改变时拒绝；支持三种环境参数 |
| `conpty.ps1 -NativeRelay` | 在同一 relay 模式下复用完整交互验收，可与三种环境或 Existing 组合 |
| `late-package.ps1` | 运行目标到达屏障后才放置新 EXE/DLL，验证首次识别、动态模块和 fork |
| `integrity.ps1` | 按需比较安装目录路径、长度和 SHA-256；不属于日常回归 |

完整性检查仅在安装/部署写入逻辑变化、怀疑分发文件被修改或发布验收确有需要时执行，不在每轮兼容测试或每次提交后重复运行。若需要首次建立比较基线，使用 `tests/integrity.ps1 -CaptureBaseline`；已有基线时不要先覆盖，应直接比较。基线默认位于 `unused/evidence/git-before.json`，可通过 `-Baseline` 指定单独快照。

各脚本默认输出到 `unused/evidence/current/<suite>`，也可使用 `-EvidenceDirectory` 保留不同轮次。状态和 HOME 位于 `unused/runtime`。这些文件不进入 Git 或发布包。

`scope` 的七项场景要求实际成功。`process-chain` 从运行 MSYS 前的原生入口记录隔离启动器默认 ACL，并检查后续所有原生桥接保持同一 ACL；目标必须完成 Perl 测试、输出工作负载标记并逐层返回 37。拒绝或超时不能算作成功。

CTest 包含独立识别测试；找到 pwsh 后注册原有五个 PSEC、四个受限令牌套件，以及三个环境各两项 relay 套件，共十六项，串行运行以避免共享状态冲突。CTest 使用当前构建目录的产物：

```powershell
# 在 tools/msvc-env.ps1 配置过的工具链环境中
ctest --test-dir build --output-on-failure
```

各集成脚本的 `-BinaryDirectory` 默认指向项目根目录的 `build/bin`，并从同一构建根定位 `tools/psec-run.exe` 和 `tests/bin` 下的夹具。从其他构建目录运行时显式指定该参数，CTest 会自动传入。源负载位于 `tests/fixtures`，独立单测位于 `tests/unit`。生产安装包不包含这些文件。

`Existing` 模式需由实际 harness 在其受限执行上下文内显式运行，不注册为普通宿主的 CTest。调用者原策略应已允许兼容产物、MSYS 安装文件、Perl 夹具的读取/执行及测试工作目录写入；缺少权限时保留拒绝。该模式只验收原上下文中的工作负载，原策略的具体拒绝路径和 ACL/token 保留情况还需按实际配置单独验证。

relay 链路要求原生桥接只存在一个创建 hook，其余八个入口与 MSYS 地址区保持原样，MSYS 当次设置后的后代默认 ACL 保持一致，允许它与首次 native 入口的启动快照不同；直接回入必须完成真实 Perl/fork/管道及退出码。挂起用例要求调用者 `ResumeThread` 看到原挂起计数 1。策略负例由原生夹具临时收紧自身默认对象 DACL，要求创建返回访问拒绝、目标未运行，随后恢复夹具初始策略；生产代码只做检查，不进行此收紧/恢复操作。

日常选择与改动相关的套件：进程创建/识别/注入/传播变化检查 fork、作用范围和相关进程链；控制台变化检查交互；文档变化检查文档即可。完整二十项用于涉及多个运行机制的改动或阶段验收，已有通过结果不因无关改动反复重跑。权限拒绝与策略保留检查继续随相关工作负载执行。完整性脚本独立按需运行，不加入 CTest。

常规 `verify` 默认一轮；重复 fork/shell 使用 `verify.ps1 -Repetitions 10`。进程链与 ConPTY 的线程 fork 默认一次，压力验收显式使用 `-ThreadRepetitions 10`（最多 1000）。也可通过兼容入口运行 `tests/fixtures/fork.pl 100`。各环境、权限边界、32 个并发子进程及交互语义仍保留，减少的是常规重复次数。测试以退出码、TAP 成败和真实工作负载为准，不依赖固定 TAP 序号或 agent trace 文案。

夹具 `import-name-runtime` 只在测试输出目录生成同名 `msys-2.0.dll`，用于验证导入名约定，不替换安装目录中的运行时。

`restricted-run` 只修改带 `.restricted-fixture` 标记的测试目录及其受控文件 ACL；两种令牌的固定 SID、对象 ACL 和能力边界见 [兼容范围](compatibility.md)。暂存副本只包含兼容产物与测试夹具，MSYS 分发文件保持原位。`raw-baseline.*` 保存同令牌下原版 Bash 的结果，`native-depth-*` 必须完成真实工作负载才通过；基线失败不能代替兼容成功。

测试设置的 ACL 是夹具初始条件，不能要求生产复制这些 ACL 操作。生产验收应使用原有策略已允许的部署位置，保留原 token、文件与对象访问限制；对只读写入、WRITE_DAC 和拒绝读取等行为同时检查拒绝。当前检查覆盖固定夹具，不能仅凭文件内容完整性或几个 canary 宣称任意生产环境的全部限制均已验证。
