# 测试说明

构建默认包含测试夹具。测试应从允许创建 PSEC 和受限令牌的普通 PowerShell 7 执行，默认 Git 根为 `C:\Program Files\Git`，可通过各脚本的 `-GitRoot` 修改。

```powershell
.\build.ps1
.\tests\integrity.ps1 -CaptureBaseline
.\tests\verify.ps1 -Repetitions 10
.\tests\scope.ps1
.\tests\process-chain.ps1
.\tests\process-chain.ps1 -Environment WriteRestricted
.\tests\process-chain.ps1 -Environment FullRestricted
.\tests\conpty.ps1
.\tests\late-package.ps1
.\tests\integrity.ps1
```

| 测试 | 检查内容 |
|---|---|
| `identify-test` | 直接导入快速路径、共享依赖去重、环、遍历上限及识别/准备失败语义；无需创建 PSEC |
| `verify.ps1` | 原版失败基线、重复 fork/shell、读写边界、退出码和原生子进程；10 轮共 25 项 |
| `fork.pl` | PID、堆、COW、共享文件偏移、管道、EOF、信号、exec、WNOHANG、嵌套及并发 fork、线程中 fork |
| `scope.ps1` | 原生根、改名原生程序、按导入名识别、原生子进程无补丁、原生根显式回入、MSYS 原生后代回入及 TokenDefaultDacl 对照 |
| `process-chain.ps1` | 原生入口 → Bash → 一层/三层原生工具 → 兼容入口 → Bash/Perl；真实 fork、10 次二级线程 fork、管道、读写边界、默认 ACL 与退出码 |
| `process-chain.ps1 -Environment WriteRestricted/FullRestricted` | 两种非 AppContainer 令牌下复用完整链路；记录无兼容基线，保持普通 MSYS 会话并存，验证实际受限令牌及文件写入/WRITE_DAC 拒绝 |
| `conpty.ps1` | TTY、120×40 尺寸、命令替换、fork、原生子进程、Ctrl+C、STOP/bg/fg、退出码 |
| `late-package.ps1` | 运行目标到达屏障后才放置新 EXE/DLL，验证首次识别、动态模块和 fork |
| `integrity.ps1` | 安装目录文件路径、长度和 SHA-256 与测试前基线相同 |

基线默认位于 `unused/evidence/git-before.json`。已有历史基线时不要先覆盖，应直接比较；全新检出才需要在第一次测试前捕获。可使用 `-Baseline` 指定单独快照。

各脚本默认输出到 `unused/evidence/current/<suite>`，也可使用 `-EvidenceDirectory` 保留不同轮次。状态和 HOME 位于 `unused/runtime`。这些文件不进入 Git 或发布包。

`scope` 的八项场景要求实际成功。`process-chain` 从运行 MSYS 前的原生入口记录隔离启动器默认 ACL，并检查后续所有原生桥接保持同一 ACL；目标必须完成 Perl 测试、输出工作负载标记并逐层返回 37。拒绝或超时不能算作成功。

CTest 包含独立识别测试；找到 pwsh 后还会注册五个 PSEC 和两个受限令牌集成套件，共八项，串行运行以避免共享状态冲突。CTest 使用当前构建目录的产物：

```powershell
# 在 tools/msvc-env.ps1 配置过的工具链环境中
ctest --test-dir build --output-on-failure
```

各集成脚本的 `-BinaryDirectory` 默认指向项目根目录的 `build/bin`。从其他构建目录运行时显式指定该参数，CTest 会自动传入。

完整性测试单独运行，避免自动测试覆盖测试前基线。强度更高的线程 fork 测试可通过兼容入口运行 `fork.pl 100`，其中参数是二级线程的重复次数；默认一次，最多 1000 次。

夹具 `import-name-runtime` 只在测试输出目录生成同名 `msys-2.0.dll`，用于验证导入名约定，不替换安装目录中的运行时。

`restricted-run` 只修改带 `.restricted-fixture` 标记的测试目录及其受控文件 ACL；两种令牌的固定 SID、对象 ACL 和能力边界见 [兼容范围](compatibility.md)。暂存副本只包含兼容产物与测试夹具，MSYS 分发文件保持原位。`raw-baseline.*` 保存同令牌下原版 Bash 的结果，`native-depth-*` 必须完成真实工作负载才通过；基线失败不能代替兼容成功。

测试设置的 ACL 是夹具初始条件，不能要求生产复制这些 ACL 操作。生产验收应使用原有策略已允许的部署位置，保留原 token、文件与对象访问限制；对只读写入、WRITE_DAC 和拒绝读取等行为同时检查拒绝。当前检查覆盖固定夹具，不能仅凭文件内容完整性或几个 canary 宣称任意生产环境的全部限制均已验证。
