# ADR-0014 — Preserve redirected streams when auto ConPTY is active

[简体中文](../zh-CN/decisions/0014-conpty-preserve-redirected-stdio.md)

Status: Accepted
Date: 2026-11-23

Related: [ADR-0002](0002-native-console-handle-owner.md).

## Context

The bridge supports the console screen reads and input event writes that Low IL clients cannot perform on the outer Medium IL conhost in the tested sandbox. The inner session is created inside the launcher's restricted context. `<`, `>`, and `2>` change streams independently, so console I/O can still matter after redirection. [Windows console access rules](https://learn.microsoft.com/en-us/windows/console/console-buffer-security-and-access-rights#wrong-way-verbs)

In a traditional conhost with a normal token, native `cmd.exe` launched Bash directly. Official MSYS2 3.6.12 and Git for Windows MSYS 3.6.10 produced the same results in all eight cases. `dtable::stdio_init()` initializes each descriptor separately. `/dev/tty` uses the controlling terminal, whose handler opens `CONIN$` and `CONOUT$`. [Descriptor initialization](https://github.com/msys2/msys2-runtime/blob/master/winsup/cygwin/dtable.cc) · [Console handler](https://github.com/msys2/msys2-runtime/blob/master/winsup/cygwin/fhandler_console.cc#L915-L950)

| `cmd` redirection | `isatty(0/1/2)` | stdin source | Standard output streams on screen | `/dev/tty` | Auto mode |
|---|---|---|---|---|---|
| None | `111` | Keyboard | stdout and stderr | Read/write | ConPTY |
| `<in` | `011` | File | stdout and stderr | Read/write | ConPTY |
| `>out` | `101` | Keyboard | stderr | Read/write | ConPTY |
| `2>err` | `110` | Keyboard | stdout | Read/write | ConPTY |
| `>out 2>err` | `100` | Keyboard | None | Read/write | ConPTY |
| `<in 2>err` | `010` | File | stdout | Read/write | ConPTY |
| `<in >out` | `001` | File | stderr | Read/write | ConPTY |
| `<in >out 2>err` | `000` | File | None | Could not open in this launch | Direct |

The `000` result applies to direct launch from native `cmd`. An MSYS child can inherit its controlling terminal in the runtime state.

## Decision

Auto mode creates the inner ConPTY when an outer console is available and at least one standard handle is a console handle. With all three streams redirected or no accessible outer console, inherit handles directly. Explicit direct inheritance and forced ConPTY remain available. See [current flags](../getting-started.md#terminal-modes-and-exit-status).

Choose the target handles individually. Console streams go to the inner console. Files, pipes, and `NUL` keep the caller's existing handles and rights. This preserves `2>&1`, bytes, and EOF. Redirected streams stay outside VT conversion and forwarding.

The bridge reads the outer keyboard and writes the inner rendering to the outer console. It can open `CONIN$` and `CONOUT$` independently of the target's three handles. With only stderr attached, `/dev/tty` still needs both endpoints. With only stdin attached, echo and explicit `/dev/tty` writes can still appear on screen.

The native session host owns the Windows-created inner console handles. Pass duplicates of only the redirected handles through the explicit inheritance list. The session host selects the target's three handles and closes its passthrough copies so it does not hold a pipe writer open. ConPTY output itself is a merged stream. [Win32 handle inheritance](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) · [ConPTY API](https://learn.microsoft.com/en-us/windows/console/createpseudoconsole)

Use `PSEUDOCONSOLE_INHERIT_CURSOR` when the outer cursor fits inside the inner dimensions. The output thread answers one startup query with the position in the outer viewport. The existing screen content remains visible, including with redirected stdin. An output pipe uses the standalone VT initial frame. The bridge forwards application clear sequences and the closing output. [Cursor inheritance](https://learn.microsoft.com/en-us/windows/console/createpseudoconsole)

## Validation

Both Bash installations passed the eight `isatty`, stdio, and `/dev/tty` comparisons under traditional `cmd`. Under native PSEC 1.0, both also passed the `110`, `100`, `010`, and `001` combinations with `NUL` and actual `/dev/tty` input and output.

The PSEC probe covers all eight stream choices, binary pipe data and EOF, `NUL`, `2>&1`, and forced direct mode. The inner target can read the screen and write input events. The Low IL direct control still receives `ERROR_ACCESS_DENIED`. Plain pipes, forced ConPTY, and scripted input also pass without an outer console. [Disk-file redirection under PSEC](../compatibility.md#disk-file-redirection-under-psec) remains a separate descriptor-recognition issue.
