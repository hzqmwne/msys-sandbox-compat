# MSYS Sandbox Compat

让未修改的 MSYS 程序在 Windows 受限环境中运行，支持 Bash、Perl、GNU 工具及其 fork/exec、管道和信号。当前验收覆盖 AMD64 下的原生 PSEC，以及 write-restricted、完整 restricting SID 检查两种非 AppContainer 令牌；版本和边界见 [兼容范围](docs/compatibility.md)。

兼容层使用原安装位置的 EXE/DLL，不修改 MSYS 分发文件、rebase 数据或磁盘/注册表 ACL；程序的资源访问继续受既有隔离策略约束。

## 兼容方法

| 问题 | 处理方式 |
|---|---|
| 运行时识别与早期介入 | 挂起创建目标。实际 EXE 的普通导入表直接声明 `msys-2.0.dll` 时，在初始线程恢复前手工映射兼容 agent。 |
| 对象命名与显式 ACL | 将 MSYS 对象目录重定向到私有命名空间；对支持的 allow ACL，按原用户及 enabled groups 已有权限补受限 SID，保留描述符其他字段。已识别进程/线程的 DACL 同样适配。 |
| 默认对象策略 | 拦截当前主 token 的 `TokenDefaultDacl` 设置，基于本次输入补受限 SID，不恢复启动快照；该策略作用于后续采用默认 DACL 的对象。 |
| MSYS 地址布局 | 冷启动和 exec 按需尝试主 EXE 首选基址，fork 子进程按父进程的实载基址对齐。创建时暂留 MSYS 栈和堆窗口，恢复前释放。符合条件的 DLL 按 section 元数据尝试 PE 首选基址，失败后交回 Windows 选址。 |
| 子进程传播 | 在子进程恢复前准备 agent。默认在 AMD64 和 WoW64 原生进程中启用创建 relay，使后续 AMD64 MSYS 自动接入。 |
| 交互终端 | 使用公开 ConPTY API，由原生会话宿主持有初始标准句柄，向 MSYS 传递显式副本，支持交互输入、Ctrl+C 和作业控制。 |

hook 位于 ntdll 入口，采用 MinHook 的 HDE64 与适配的指令搬迁核心，搬迁受支持的入口指令并保留已有跳转路径。搬迁后端与远程安装分开封装。宿主静态链接 CRT。早期 agent 无 CRT 初始化、普通导入或 TLS 依赖。实现细节见 [当前设计](docs/design.md)及 [DLL 映射决策](docs/decisions/0012-prefer-dll-image-base-at-map.md)。

## 构建与使用

构建支持 Windows PowerShell 5 和 PowerShell 7，需要 Visual Studio C++ AMD64 工具和 Windows SDK。第三方源码已包含在仓库内。

```powershell
.\build.ps1 -Configuration Release -Install

# 在已有 PSEC 或受限令牌环境中调用
.\build\package\bin\msys-sandbox-compat-shim.exe -- `
  'C:\Program Files\Git\usr\bin\bash.exe' --noprofile --norc -c 'echo ready; (echo fork-ok)'
```

生产部署只需 `msys-sandbox-compat-shim.exe`，放在原策略允许读取和执行的位置。`--` 分隔 shim 选项与目标命令。日志默认关闭，终端模式默认自动选择，`--terminal=inherit` 强制直接继承三路标准句柄。用 `-h` 或 `--help` 查看参数，用 `--version` 查看版本。见[使用说明](docs/getting-started.md)。

本地演示可从允许创建 PSEC 的 Windows PowerShell 5.1 或 PowerShell 7 运行。

```powershell
.\build.ps1 -Tools
.\run.ps1 -ConPty
```

`run.ps1` 使用可选开发工具 `psec-run.exe` 创建演示环境；该工具不随生产包安装。回归使用 `build.ps1 -Tests` 构建夹具，覆盖真实工作负载、权限边界、进程传播和交互终端，详见 [测试说明](docs/testing.md)。

[文档索引](docs/README.md) · [架构决策](docs/decisions/README.md) · [变更记录](CHANGELOG.md)
