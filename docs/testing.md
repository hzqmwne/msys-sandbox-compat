# 测试说明

构建默认包含测试夹具。所有测试应从允许创建 PSEC 的普通 PowerShell 7 执行，默认 Git 根为 `C:\Program Files\Git`，可通过各脚本的 `-GitRoot` 修改。

```powershell
.\build.ps1
.\tests\integrity.ps1 -CaptureBaseline
.\tests\verify.ps1 -Repetitions 10
.\tests\scope.ps1
.\tests\conpty.ps1
.\tests\late-package.ps1
.\tests\integrity.ps1
```

| 测试 | 检查内容 |
|---|---|
| `identify-test` | 直接导入快速路径、共享依赖去重、环、遍历上限及识别/准备失败语义；无需创建 PSEC |
| `verify.ps1` | 原版失败基线、重复 fork/shell、读写边界、退出码和原生子进程；10 轮共 25 项 |
| `fork.pl` | PID、堆、COW、共享文件偏移、管道、EOF、信号、exec、WNOHANG、嵌套及并发 fork、线程中 fork |
| `scope.ps1` | 原生根、改名原生程序、按导入名识别、原生子进程无补丁、原生根显式回入、MSYS 原生后代启动原生目标时默认 DACL 不变、冷启动 MSYS 的 token 拒绝及 TokenDefaultDacl 对照 |
| `conpty.ps1` | TTY、120×40 尺寸、命令替换、fork、原生子进程、Ctrl+C、STOP/bg/fg、退出码 |
| `late-package.ps1` | 运行目标到达屏障后才放置新 EXE/DLL，验证首次识别、动态模块和 fork |
| `integrity.ps1` | 安装目录文件路径、长度和 SHA-256 与测试前基线相同 |

基线默认位于 `unused/evidence/git-before.json`。已有历史基线时不要先覆盖，应直接比较；全新检出才需要在第一次测试前捕获。可使用 `-Baseline` 指定单独快照。

各脚本默认输出到 `unused/evidence/current/<suite>`，也可使用 `-EvidenceDirectory` 保留不同轮次。状态和 HOME 位于 `unused/runtime`。这些文件不进入 Git 或发布包。

`scope` 包含七项成功场景与一项明确的预期拒绝。`msys-native-msys-token-boundary` 要求在 10 秒内报告恢复前 token 访问错误，且未输出目标执行标记；它验证错误边界，不表示支持 MSYS 原生桥接回入。

CTest 包含独立识别测试；找到 pwsh 后还会注册四个 PSEC 集成套件，串行运行以避免共享状态冲突。CTest 使用当前构建目录的产物：

```powershell
# 在 tools/msvc-env.ps1 配置过的工具链环境中
ctest --test-dir build --output-on-failure
```

各集成脚本的 `-BinaryDirectory` 默认指向项目根目录的 `build/bin`。从其他构建目录运行时显式指定该参数，CTest 会自动传入。

完整性测试单独运行，避免自动测试覆盖测试前基线。强度更高的线程 fork 测试可通过兼容入口运行 `fork.pl 100`，其中参数是二级线程的重复次数；默认一次，最多 1000 次。

夹具 `import-name-runtime` 只在测试输出目录生成同名 `msys-2.0.dll`，用于验证导入名约定，不替换安装目录中的运行时。
