# MSYS Compat

让未修改的 MSYS 程序在 Windows 受限执行环境中运行。当前验证覆盖 **Windows 原生 PSEC / AMD64**，以及固定测试夹具创建的 write-restricted 和完整 restricting SID 检查两种非 AppContainer 令牌；外部 harness 尚未集成验收。

项目直接启动真实的 `usr/bin/bash.exe`、Perl 与 GNU 命令，使用原安装位置的 `msys-2.0.dll`，不修改 MSYS2/Git for Windows 分发包中的磁盘文件、安装目录 ACL 或 rebase 数据。当前验证组合为 Windows 26300.9711 x64、PSEC 1.0、MSYS 3.6.10。

生产兼容层不修改任何磁盘文件或目录的 ACL，也不放宽原 restricted token 的限制。兼容产物必须部署在原策略已允许读取/执行的位置；测试夹具配置权限不属于生产修复步骤。

兼容层在初始线程恢复前识别 MSYS 映像并准备其内存，通过 9 个有条件的 inline hook 处理对象授权、隔离环境默认对象 ACL、地址布局和子进程传播。原生进程保持原样。

## 构建与运行

需要 PowerShell 7、Visual Studio C++ AMD64 工具和 Windows SDK。构建脚本通过 vswhere 定位工具链，第三方头文件已包含在仓库内。

```powershell
.\build.ps1 -Install
.\run.ps1

# 启动内部真实 Bash
.\run.ps1 -Program 'C:\Program Files\Git\usr\bin\bash.exe' `
  -CommandArguments @('--noprofile','--norc','-c',
    'export PATH=/usr/bin:/bin; (echo fork); printf "b\na\n" | sort')

# ConPTY 交互模式
.\run.ps1 -ConPty -TerminalSize '120x40'
```

正式产物位于 `build/bin`，安装布局位于 `unused/package`：

| 文件 | 职责 |
|---|---|
| `psec-run.exe` | 从普通宿主按策略创建 PSEC |
| `msys-compat.exe` | 在既有受限环境中启动目标、识别、准备和等待进程树 |
| `msys-compat.dll` | 只映射到确认的 MSYS 进程中的兼容模块 |

兼容宿主在既有 PSEC 或受限令牌上下文中运行，不创建非隔离回退进程。受测令牌配置、版本和集成边界见 [兼容范围](docs/compatibility.md)。

## 验证

从允许创建 PSEC 的普通 PowerShell 运行：

```powershell
.\tests\integrity.ps1 -CaptureBaseline   # 第一次测试前保存安装目录快照
.\tests\verify.ps1 -Repetitions 10
.\tests\scope.ps1
.\tests\process-chain.ps1
.\tests\process-chain.ps1 -Environment WriteRestricted
.\tests\process-chain.ps1 -Environment FullRestricted
.\tests\conpty.ps1
.\tests\late-package.ps1
.\tests\integrity.ps1
```

测试覆盖 fork、线程中 fork、shell、管道、信号、exec、权限边界、原生进程范围、交互终端和运行中新出现的包。详细用例与 CTest 用法见 [测试说明](docs/testing.md)。

## 工作范围

识别依据是实际映像内存中的普通导入表：直接或间接导入 `msys-2.0.dll` 即命中，忽略大小写；不依赖目录扫描、文件指纹或安装时建立的名单。新包在第一次创建或映射时识别。

支持连续的 MSYS 子进程链，以及经过原生工具后显式调用兼容入口再次运行 Bash、Perl 和 fork。其他进程链和版本边界见 [兼容范围](docs/compatibility.md)。

## 仓库结构

```text
src/                    兼容宿主、agent、PSEC 创建代码
include/msys_compat/    Native API、识别和注入协议
tests/                  可提交的回归脚本与测试夹具
third_party/            固定的第三方头文件及许可
tools/                  构建工具链定位
docs/                   当前设计、使用、兼容范围、测试与架构决策
build/                  CMake 缓存、中间文件、二进制和测试夹具，不提交
unused/                 本地专题笔记、证据、实验、包与运行状态，不提交
```

[文档索引](docs/README.md) · [使用说明](docs/getting-started.md) · [当前设计](docs/design.md) · [兼容范围](docs/compatibility.md) · [测试说明](docs/testing.md) · [架构决策](docs/decisions/README.md) · [变更记录](CHANGELOG.md)
