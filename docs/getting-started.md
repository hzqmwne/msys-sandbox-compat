# 使用说明

## 构建

在 Windows AMD64 上安装 PowerShell 7、Visual Studio 的 C++ AMD64 工具与 Windows SDK，然后运行：

```powershell
.\build.ps1
.\build.ps1 -Configuration Release -Install
.\build.ps1 -Tools  # 本地 PSEC 演示工具
.\build.ps1 -Tests  # 包含开发工具、测试程序和夹具
```

CMake 缓存、中间文件和二进制都在 `build`，不需要复制历史构建缓存。默认仅构建兼容 EXE/DLL；`-Install` 将它们、公开文档和许可整理到 `build/package`。`-Tools` 构建 `build/tools/psec-run.exe`；`-Tests` 同时构建它和 `build/tests/bin` 下的回归夹具。开发工具与测试夹具均不安装。手动 CMake 对应 `-DMSYS_SANDBOX_COMPAT_BUILD_TOOLS=ON` 和 `-DBUILD_TESTING=ON`，二者默认关闭。

## 示例入口

先执行 `build.ps1 -Tools`。仓库内的 `run.ps1` 是演示入口，每次运行创建独立的 PSEC 策略文件，将 Windows 与所选 Git 根目录设为只读，项目根目录设为可写，进程工作目录继承调用者，并明确拒绝测试 canary。HOME、临时文件和运行状态位于 `unused/runtime`。

```powershell
.\run.ps1 -GitRoot 'C:\Program Files\Git'
.\run.ps1 -ConPty
.\run.ps1 -NoConPty
.\run.ps1 -ConPty -TerminalSize '120x40'
.\run.ps1 -NativeRelay
.\run.ps1 -Raw  # 不启用兼容层，用于失败基线对照
```

默认目标是 Git 的 `usr/bin/bash.exe`。不要将 Git 根目录或 `bin` 中的外层 Bash 壳启动器当作真实 MSYS 目标。

`run.ps1 -ConPty` 的默认 Bash 入口初始化 `/usr/bin:/bin`、`TERM=xterm-256color` 和 UTF-8 locale，然后启动交互 Bash。显式传入 `-CommandArguments` 时使用调用者的参数。其他 `-Program` 使用其自身默认参数。其他构建目录可通过 `-BinaryDirectory` 指定该构建的 `bin` 目录。

通过 `-Program` 启动交互式 `powershell.exe` 或 `pwsh.exe`，且参数仅含 `-NoProfile`、`-NoLogo`、`-NoExit` 时，演示入口在首次交互读取前将 PSReadLine 历史配置到 `unused/runtime/powershell-history`，实际保存会话命令。含显式 `-Command`、`-File` 等参数的调用沿用其自定义初始化。默认用户历史文件仍受 PSEC 文件策略约束。

## 低层入口

```text
psec-run.exe policy.json program.exe [arguments...]
msys-sandbox-compat.exe [--trace] [--native-relay] [--disable-module NAME]...
    [--conpty | --no-conpty | --conpty-script input.txt] [--conpty-size WIDTHxHEIGHT]
    program.exe [arguments...]
```

`psec-run.exe` 是 PSEC 开发验证工具。`msys-sandbox-compat.exe` 可用普通令牌或在既有受限上下文中调用，并从自身目录定位 `msys-sandbox-compat.dll`。EXE 的普通导入表直接声明 `msys-2.0.dll` 即按 MSYS 处理，名称忽略大小写。旧命令中的 `--runtime DLL` 仍可传入，实际 DLL 由 Windows 加载器选择。

排查 DLL 映射时，可用 `--trace` 查看尝试的 PE 首选址、该次映射状态、成功时的实址以及失败后的重试事件。见 [DLL 映射范围](design.md#dll-映射范围)。

### 兼容模块对照

MSYS 兼容模块默认全部启用。可重复传入 `--disable-module NAME`，例如 `--trace --disable-module dll-placement`。演示脚本对应 `-DisableModule dll-placement,exe-placement`。开关对本次启动和兼容层传播到的后代有效。

| 模块名 | 关闭时跳过的处理 |
|---|---|
| `propagation` | 子进程创建 hook 和自动传播。与 `--native-relay` 互斥 |
| `heap-window` | 创建前的磁盘导入预检、临时堆窗口及其交还 |
| `exe-placement` | 保存父端实载 EXE 路径和基址、识别 fork 启动记录及按父端地址对齐 |
| `dll-placement` | DLL 定址 hook 及其中的 section 查询 |
| `ipc` | MSYS 命名对象路径和显式 ACL 适配，以及相应的命名空间与会话标记 |
| `process-dacl` | MSYS 进程和线程对象 DACL 适配 |
| `token-dacl` | MSYS 主 token 默认 DACL 适配 |

关闭模块可能重现该模块处理的兼容故障。relay 的令牌核对仍然生效，受限环境还会比较默认对象策略。嵌套启动器复用已有 relay 的配置，尝试关闭该树中已启用的模块会报错。ConPTY 继续由自己的选项控制。`--trace` 显示根进程启用的模块与后代的模块位掩码，位序按表格从最低位开始。

接入受限令牌启动器时，将其启动目标设为 `msys-sandbox-compat.exe PROGRAM ...`，保留启动器既有 token、对象和文件策略。兼容 EXE/DLL 应部署在原策略已允许读取/执行的位置；原版 MSYS 安装文件也必须已具备原策略允许的访问。兼容层不修改任何磁盘 ACL、不放宽 restricted token，也不借非受限进程代读被拒绝的文件。缺少访问时记录该配置下的兼容阻碍，不能通过补权把它算作成功。已验收配置见 [兼容范围](compatibility.md)，测试用 `restricted-run.exe` 不作为产品启动器分发。

在实际 harness 内可直接执行 `tests/conpty.ps1 -Environment Existing` 验证继承的上下文。它不创建新的隔离环境或配置文件 ACL；初始策略与拒绝边界的验收要求见 [测试说明](testing.md)。

兼容宿主通过 job 等待进程树退出并返回根进程退出码。默认用 `GetConsoleMode` 分别检查 stdin、stdout 和 stderr。三者都是 Windows 控制台句柄时，启动内层 ConPTY。任一方向重定向到文件或管道时，直接继承标准句柄。通过普通管道提供 VT 字节流的调用者可以用 `--conpty` 强制启用，或用 `--no-conpty` 强制直连。演示脚本对应 `-ConPty` 和 `-NoConPty`。桥接方式与目标命令是否以交互模式启动分别由终端选项和目标参数决定。

ConPTY 模式收发 VT 字节流。标准输入是控制台且标准输出可查询窗口尺寸时，按外层窗口尺寸启动并跟随变化。`--conpty-size`（演示脚本中的 `-TerminalSize`）在启用桥时固定整个会话的尺寸。脚本输入和无法查询交互控制台尺寸的会话默认使用 `100x30`。

`--conpty-script` 和重定向的 `--conpty` 标准输入把数据送入 conhost 的 VT 输入管道。目标从自己的控制台句柄读取。外部文件或管道耗尽后，桥保留终端连接，以便目标继续运行。受测 Windows 会在 VT 输入管道断开时向目标发送 `CTRL_CLOSE_EVENT`。运行交互 shell 的脚本可以用 `exit` 结束会话，依赖 stdin EOF 的批处理可以使用默认标准流入口。ConPTY 的下游输出写入失败时，宿主结束该会话并返回 `1`。

连接真实控制台时，终端桥启用原始 VT 输入和 VT 输出，并为相应方向设置 UTF-8 代码页。输出排空后恢复原模式和代码页。原生等待宿主处理自身收到的 Ctrl+C 通知，前台目标继续按其控制台处理规则响应按键。

`--native-relay` 是显式选择的进程树传播模式，也可由 `run.ps1 -NativeRelay` 启用，并可与 ConPTY 组合。原生进程仅保留创建 hook，直接启动后续 MSYS 时自动完成兼容准备；默认仍不注入原生进程。已处于该树中的嵌套兼容入口复用已有 relay，无需重复加选项。该模式不修改磁盘 ACL 或放宽 token，遇到安全上下文或默认对象策略变化时拒绝传播。覆盖入口和限制见 [兼容范围](compatibility.md)。`-Raw` 与 `-NativeRelay` 不能同时使用。

## 创建环境失败

若调用者已经处于禁止创建新 PSEC 的环境，创建 API 可能失败，例如返回 `0x800706d9`。这时应从允许该 API 的宿主执行测试，或在已经创建的 PSEC 内使用兼容入口。工具不会切换到普通非隔离进程。

其他集成边界见 [兼容范围](compatibility.md)。
