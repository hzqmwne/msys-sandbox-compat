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

shim 保持 MSYS fork 所需的地址布局，并适配 MSYS 用于协调进程的 Windows 对象访问。兼容准备可经过原生子进程传播，包括 WoW64 中间进程。交互会话按需创建内层 ConPTY，同时保留文件和管道重定向。文件和资源访问仍由原沙箱策略决定，MSYS 安装文件保持原样。详见[设计](docs/zh-CN/design.md)。

## 兼容性与限制

- 主要验收组合为 Windows x64、原生 PSEC 1.0 和 Git for Windows MSYS 3.6.10。回归也覆盖两种固定的非 AppContainer 受限令牌配置。
- 完整兼容处理针对直接导入 `msys-2.0.dll` 的 AMD64 EXE。Cygwin 不在当前支持范围内。采用不同 ASLR 设置的 MSYS2 版本需要单独验收 fork 和会话并存。
- 在受测 PSEC 配置中，Bash 继承磁盘文件 stdout 或 stderr 时可能在启动阶段崩溃。无包身份的父进程启动 Microsoft Store 版 PowerShell 也受到限制。

参阅[已验收配置和已知限制](docs/zh-CN/compatibility.md)、[使用说明](docs/zh-CN/getting-started.md)和[变更记录](CHANGELOG.zh-CN.md)。
