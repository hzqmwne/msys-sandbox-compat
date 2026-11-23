# 使用说明

## 构建

在 Windows AMD64 上，用 Windows PowerShell 5 或 PowerShell 7 运行构建脚本。构建需要 Visual Studio C++ AMD64 工具和 Windows SDK。

```powershell
.\build.ps1
.\build.ps1 -Configuration Release -Install
.\build.ps1 -Tools  # 本地 PSEC 演示工具
.\build.ps1 -Tests  # 包含开发工具、测试程序和夹具
```

CMake 缓存、中间文件和二进制都在 `build`。构建保留开发 EXE/DLL，并把通过校验的 agent DLL 嵌入 `msys-sandbox-compat-shim.exe`。`-Install` 将单文件 shim、公开文档和许可整理到 `build/package`。`-Tools` 构建 `build/tools/psec-run.exe`，`-Tests` 同时构建它和 `build/tests/bin` 下的回归夹具。校验器、开发工具与测试夹具均不安装。手动 CMake 对应 `-DMSYS_SANDBOX_COMPAT_BUILD_TOOLS=ON` 和 `-DBUILD_TESTING=ON`，二者默认关闭。

## 示例入口

先执行 `build.ps1 -Tools`，然后用 Windows PowerShell 5.1 或 PowerShell 7 运行 `run.ps1`。演示每次创建独立的 PSEC 策略文件，将 Windows 与所选 Git 根目录设为只读，项目根目录设为可写，进程工作目录继承调用者，并明确拒绝测试 canary。演示使用独立的 HOME 和临时目录。

Windows PowerShell 5.1 和 PowerShell 7.0–7.2 下，演示程序直接继承调用进程的标准句柄。用 PowerShell 脚本管道捕获 `run.ps1` 的输出时，使用 PowerShell 7.3 或更新版本。

```powershell
.\run.ps1 -GitRoot 'C:\Program Files\Git'
.\run.ps1 -ConPty
.\run.ps1 -NoConPty
.\run.ps1 -ConPty -TerminalSize '120x40'
.\run.ps1 -NoNativeRelay
.\run.ps1 -Raw  # 不启用兼容层，用于失败基线对照
```

默认目标是 Git 的 `usr/bin/bash.exe`。不要将 Git 根目录或 `bin` 中的外层 Bash 壳启动器当作真实 MSYS 目标。

`run.ps1` 默认用 Bash 执行一次启动、fork 和 `uname` 检查，随后退出。它仍按标准句柄自动选择是否启用 ConPTY。`run.ps1 -ConPty` 显式启用 ConPTY，默认 Bash 入口初始化 `/usr/bin:/bin`、`TERM=xterm-256color` 和 UTF-8 locale，然后进入交互会话。显式传入 `-CommandArguments` 时使用调用者的参数。其他 `-Program` 使用其自身默认参数。其他构建目录可通过 `-BinaryDirectory` 指定该构建的 `bin` 目录。

通过 `-Program` 启动交互式 `powershell.exe` 或 `pwsh.exe`，且参数仅含 `-NoProfile`、`-NoLogo`、`-NoExit` 时，演示在首次交互读取前将 PSReadLine 历史指向演示自己的可写文件。含显式 `-Command`、`-File` 等参数的调用沿用其自定义初始化。默认用户历史文件仍受 PSEC 文件策略约束。

## 低层入口

```text
psec-run.exe --policy=FILE [--psec-version=auto|1.0|1.1] -- COMMAND [ARGUMENTS...]
psec-run.exe -h | --help
msys-sandbox-compat-shim.exe [OPTIONS] -- COMMAND [ARGUMENTS...]
msys-sandbox-compat-shim.exe -h | --help
msys-sandbox-compat-shim.exe --version
```

`psec-run.exe` 是独立的 PSEC 验证工具。它接受 MXC 形状的文件、枚举和直接网络规则，按要求选择原生 PSEC 1.0 或 1.1。原有位置参数形式也可使用。shim 可用普通令牌或在既有受限上下文中调用。`--` 后的原生命令行交给目标，显式路径按当前目录解析，裸命令名使用 Windows 原生搜索。

shim 的 `--log-level=off|error|warning|info|trace` 默认是 `off`。启用后默认写 stderr，`--log-file=FILE` 将诊断追加到独立文件。`info` 提供启动和退出摘要，`trace` 还包括模块、子进程和映射诊断。见[DLL 映射范围](design.md#dll-映射范围)。

### 兼容模块对照

MSYS 兼容模块默认全部启用。用 `--disable-modules=NAME[,NAME...]` 关闭指定模块，例如 `--disable-modules=dll-placement,exe-placement`。演示脚本对应 `-DisableModule dll-placement,exe-placement`。开关对本次启动和兼容层传播到的后代有效。

| 模块名 | 关闭时跳过的处理 |
|---|---|
| `propagation` | 子进程创建 hook 和自动传播，包括默认 relay。与显式 `--native-relay=on` 互斥 |
| `heap-window` | 创建前的磁盘导入预检、临时堆窗口及其交还 |
| `exe-placement` | 冷启动和 exec 时尝试未设置 `DYNAMIC_BASE` 的 EXE 首选基址，以及 fork 时按父进程实载地址对齐 |
| `dll-placement` | DLL 定址 hook 及其中的 section 查询 |
| `ipc` | MSYS 命名对象路径和显式 ACL 适配，以及相应的命名空间准备 |
| `process-dacl` | 受限上下文中适配创建进程和初始线程时的显式 DACL，以及 MSYS 运行时重设的自身进程 DACL |
| `token-dacl` | MSYS 主 token 默认 DACL 适配 |

关闭模块可能重现该模块处理的兼容故障。各进程使用自身主 token 决定 ACL 模块的适用性。嵌套启动器复用已有 relay 的配置，尝试关闭该树中已启用的模块会报错。`--log-level=trace` 显示启动器配置的模块，子端也会输出实际模块位掩码，位序按表格从最低位开始。

接入受限令牌启动器时，使用固定前缀 `msys-sandbox-compat-shim.exe --`。将单文件 shim 和目标程序放在原策略允许读取和执行的位置。需要强制继承三路标准句柄时，使用 `msys-sandbox-compat-shim.exe --terminal=inherit --`。已验收配置见[兼容范围](compatibility.md)。

在实际 harness 内可直接执行 `tests/conpty.ps1 -Environment Existing` 验证继承的上下文。它不创建新的隔离环境或配置文件 ACL；初始策略与拒绝边界的验收要求见 [测试说明](testing.md)。

兼容宿主通过 job 等待进程树退出并返回根进程退出码。`--terminal=auto` 分别检查 stdin、stdout 和 stderr。外层控制台可用且至少一路是控制台句柄时，启动内层 ConPTY。目标程序的控制台流接到内层，文件、管道和 `NUL` 的原句柄直接继承。三路都重定向或没有可用的外层控制台时，自动模式走直连。`--terminal=inherit` 强制直连，`--terminal=conpty` 强制启用桥。演示脚本对应 `-NoConPty` 和 `-ConPty`。见[八种组合](decisions/0014-conpty-preserve-redirected-stdio.md)。

ConPTY 模式收发 VT 字节流。自动模式按外层控制台窗口尺寸启动并跟随变化，包括部分标准流重定向的情况。`--conpty-size=COLSxROWS`（演示脚本中的 `-TerminalSize`）在启用桥时固定尺寸。列数和行数各使用 `1` 至 `32767` 的十进制整数，以小写 `x` 分隔，例如 `120x40`。无法查询控制台尺寸时默认使用 `100x30`。

`--terminal=conpty` 可以从重定向的 stdin 接收 VT 输入，目标从自己的控制台句柄读取。外部文件或管道耗尽后，桥保留终端连接，以便目标继续运行。依赖 stdin EOF 的批处理可以使用 `--terminal=inherit`。ConPTY 的下游输出写入失败时，宿主结束该会话并返回 `1`。

连接真实控制台时，终端桥启用原始 VT 输入和 VT 输出，并为相应方向设置 UTF-8 代码页。当前光标能用内层尺寸表示时，内层继承光标并保留外层已显示的内容。应用发出的清屏指令照常转发。输出排空后恢复原模式和代码页。原生等待宿主处理自身收到的 Ctrl+C 通知，前台目标继续按其控制台处理规则响应按键。

native relay 默认开启，覆盖 AMD64 和 WoW64 原生首进程及中间进程。两种位数可在同一启动链交替，后续 AMD64 MSYS 自动接入。用 `--native-relay=off` 或 `run.ps1 -NoNativeRelay` 关闭该功能。已继承 relay 的嵌套兼容入口复用原配置，显式关闭会报错。见[兼容范围](compatibility.md)和[当前设计](design.md#原生-relay)。

## 创建环境失败

若调用者已经处于禁止创建新 PSEC 的环境，创建 API 可能失败，例如返回 `0x800706d9`。这时应从允许该 API 的宿主执行测试，或在已经创建的 PSEC 内使用兼容入口。工具不会切换到普通非隔离进程。

其他集成边界见 [兼容范围](compatibility.md)。
