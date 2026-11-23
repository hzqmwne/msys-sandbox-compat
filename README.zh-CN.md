# MSYS Sandbox Compat

[English](README.md)

在已有的 Windows 沙箱中运行 MSYS2 和 Git for Windows 工具。这个 x64 shim 帮助未修改的 Bash、Perl 和 GNU 工具运行依赖 `fork`、管道、信号和交互终端的工作负载。

## 使用

构建需要 Visual Studio C++ x64 工具和 Windows SDK，可用 Windows PowerShell 5.1 或 PowerShell 7 执行。

```powershell
.\build.ps1 -Configuration Release -Install
```

将 `build\package\bin\msys-sandbox-compat-shim.exe` 放到沙箱已允许读取和执行的位置。在该环境中，从 shim 所在目录执行以下命令。

```powershell
.\msys-sandbox-compat-shim.exe -- 'C:\Program Files\Git\usr\bin\bash.exe' --noprofile --norc -c 'echo ready; (echo fork-ok)'
```

shim 内嵌 agent DLL。用 `-h` 查看选项，用 `--version` 查看版本。日志默认关闭。需要目标直接继承 stdin、stdout 和 stderr 时，使用 `--terminal=inherit`。

## 工作原理

| 兼容项 | 处理方式 |
| --- | --- |
| 运行时识别与启动 | 识别普通导入表直接声明 `msys-2.0.dll` 的 AMD64 EXE。子进程挂起时准备 agent，由 agent 在子进程首次进入 `LdrInitializeThunk` 时安装适用的 hook。 |
| 栈与堆的布局 | 创建进程时暂留 MSYS 栈和堆的地址窗口，让 Windows 把初始分配放到其他位置。父进程在子进程运行前释放窗口，MSYS 自行分配所需的堆。 |
| EXE 与 DLL 选址 | fork 子进程可以按父进程的实载地址重映射主 EXE。冷启动和 exec 期间，未启用 `DYNAMIC_BASE` 的 MSYS EXE 可尝试 PE 首选地址。符合条件的 DLL 在映射 section 时尝试首选地址，失败后回退到原 Windows 请求。 |
| 命名 IPC 与显式 DACL | 将 MSYS 命名 IPC 导向 AppContainer 命名空间，或为非 AppContainer 受限进程树使用私有目录。对可适配的显式 DACL，只补原用户或已启用组已有、受限 SID 缺少的权限，也覆盖调用者在创建时传入的进程和线程 DACL。 |
| 默认与启动期 DACL | 适配 MSYS 设置的主令牌 `TokenDefaultDacl` 和当前进程对象 DACL。各进程自行确定所用的受限 SID。 |
| 原生进程链 | 默认经原生 AMD64 和 WoW64 进程传播。原生进程只安装进程创建 hook，便于后续 MSYS 子进程接入其所需的完整兼容处理。 |
| 交互终端 | 为低完整性下的读屏幕和写控制台输入按需启动内层 ConPTY。控制台流走桥接，重定向的流直接交给目标。外层终端继续管理自己的会话。 |

hook 位于 `ntdll` 入口，使用 MinHook 的 HDE64 与适配后的指令重定位代码。文件和资源访问仍由原沙箱策略决定，MSYS 安装文件保持原样。各 hook 的适用范围和回退规则见[设计](docs/zh-CN/design.md)。

## 兼容性与限制

- 主要验收组合为 Windows x64、原生 PSEC 1.0 和 Git for Windows MSYS 3.6.10。回归也覆盖两种固定的非 AppContainer 受限令牌配置。
- 完整兼容处理针对直接导入 `msys-2.0.dll` 的 AMD64 EXE。Cygwin 不在当前支持范围内。采用不同 ASLR 设置的 MSYS2 版本需要单独验收 fork 和会话并存。
- 在受测 PSEC 配置中，Bash 继承磁盘文件 stdout 或 stderr 时可能在启动阶段崩溃。无包身份的父进程启动 Microsoft Store 版 PowerShell 也受到限制。

参阅[已验收配置和已知限制](docs/zh-CN/compatibility.md)、[使用说明](docs/zh-CN/getting-started.md)、[文档索引](docs/zh-CN/README.md)和[变更记录](CHANGELOG.zh-CN.md)。
