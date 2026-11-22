# ADR-0014：自动 ConPTY 保留逐路重定向

Status: Accepted

Date: 2026-11-23

Related: [ADR-0002](0002-native-console-handle-owner.md)

## 背景

ConPTY 桥用于兼容 Low IL 客户端连接外层 Medium IL conhost 时受限的读屏幕和写控制台输入事件。内层会话在启动器当前的受限上下文内创建。`<`、`>` 和 `2>` 只改变指定的标准流，部分重定向仍可留下需要兼容的控制台访问。[控制台访问规则](https://learn.microsoft.com/en-us/windows/console/console-buffer-security-and-access-rights#wrong-way-verbs)

在普通令牌的传统 `conhost.exe` 中，由原生 `cmd.exe` 直接启动 Bash。官方 MSYS2 3.6.12 和 Git for Windows 的 MSYS 3.6.10 在八组对照中结果相同。`dtable::stdio_init()` 分别初始化三个标准描述符。`/dev/tty` 使用控制终端，控制台处理器打开 `CONIN$` 和 `CONOUT$`。 [描述符初始化](https://github.com/msys2/msys2-runtime/blob/master/winsup/cygwin/dtable.cc) · [控制台打开逻辑](https://github.com/msys2/msys2-runtime/blob/master/winsup/cygwin/fhandler_console.cc#L915-L950)

| `cmd` 重定向 | `isatty(0/1/2)` | stdin 读自 | 写到屏幕的标准输出流 | `/dev/tty` 可读写 | `auto` |
|---|---|---|---|---|---|
| 无 | `111` | 键盘 | stdout、stderr | 是 | ConPTY |
| `<in` | `011` | 文件 | stdout、stderr | 是 | ConPTY |
| `>out` | `101` | 键盘 | stderr | 是 | ConPTY |
| `2>err` | `110` | 键盘 | stdout | 是 | ConPTY |
| `>out 2>err` | `100` | 键盘 | 无 | 是 | ConPTY |
| `<in 2>err` | `010` | 文件 | stdout | 是 | ConPTY |
| `<in >out` | `001` | 文件 | stderr | 是 | ConPTY |
| `<in >out 2>err` | `000` | 文件 | 无 | 本次直接启动时打不开 | 直通 |

`000` 的结果限于从原生 `cmd` 直接启动。已有 MSYS 父进程时，控制终端可以经运行时状态继承。

## 决定

- 外层控制台可用且至少一路标准句柄是控制台时，`auto` 启用内层 ConPTY。三路均非控制台、或外层控制台不可用时，直接继承标准句柄。显式 `--no-conpty` 继续直连，`--conpty` 和 `--conpty-script` 继续支持调用方显式提供的 VT 数据源和输出目标。
- 启动目标时逐路选句柄。原本指向控制台的标准流使用内层控制台句柄，文件、管道和 `NUL` 保留调用方已打开的句柄及访问权。保留 `2>&1` 的共享输出目标、原字节和 EOF。重定向流不经过 VT 转码或中间转发。
- 桥从外层控制台读取键盘输入，将内层渲染写到外层控制台。必要时使用外层 `CONIN$` 和 `CONOUT$`，独立于重定向的 stdin、stdout、stderr。只剩 stderr 接着控制台时，这对端点仍要支持 `/dev/tty` 读写。只剩 stdin 时，键盘回显或 `/dev/tty` 的绘制仍可出现在屏幕上。
- 保留原生会话宿主的控制台句柄所有权。先让 Windows 为会话宿主建立内层控制台标准句柄，通过显式继承列表另外传递需要直通的句柄，再由会话宿主为实际目标设置三路标准句柄。直通副本在交给目标后关闭，避免额外持有管道写端。ConPTY 的会话输出已合并，句柄去向在创建目标时确定。 [Win32 继承列表](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) · [ConPTY 接口](https://learn.microsoft.com/en-us/windows/console/createpseudoconsole)

## 验证范围

通过 launcher 在传统 `cmd` 中启动两套 Bash，八种组合分别通过 `isatty`、标准流读写和 `/dev/tty` 对照。原生 PSEC 1.0 中，两套 Bash 另通过 `110`、`100`、`010`、`001` 的 `NUL` 重定向和实际 `/dev/tty` 键盘、屏幕测试。

PSEC 原生探针对照八种选路，覆盖混合管道的二进制数据和 EOF、`NUL`、`2>&1` 与 `--no-conpty`。进入内层的目标可读屏幕和写输入事件，直连外层的低完整性目标仍收到 `ERROR_ACCESS_DENIED`。同组回归通过无外层控制台时的普通管道、显式 ConPTY 和脚本模式。现有的 [PSEC 磁盘标准句柄问题](../compatibility.md#psec-下的磁盘文件重定向) 仍由运行时文件描述符识别路径单独跟踪。
