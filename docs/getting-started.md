# Getting started

## Build

On Windows x64, use Windows PowerShell 5.1 or PowerShell 7 with the Visual Studio C++ x64 tools and Windows SDK.

```powershell
.\build.ps1
.\build.ps1 -Configuration Release -Install
.\build.ps1 -Tools
.\build.ps1 -Tests
```

Build output, intermediate files, and the CMake cache go under `build`. The build keeps the development EXE and DLL and embeds a verified copy of the agent in `msys-sandbox-compat-shim.exe`. `-Install` stages the single EXE, public documentation, and license notices under `build/package`.

`-Tools` builds `build/tools/psec-run.exe`. `-Tests` also builds that tool and the regression fixtures under `build/tests/bin`. The validator, development tools, and test fixtures are excluded from installation. The equivalent CMake options are `MSYS_SANDBOX_COMPAT_BUILD_TOOLS` and `BUILD_TESTING`. Both default to off.

## Run the PSEC demo

Run `build.ps1 -Tools` first. `run.ps1` creates a PSEC policy for the demo. It grants read access to Windows and the selected Git installation, allows writes under the repository root, and denies access to a test canary. The working directory comes from the caller. The demo uses its own home and temporary directories.

Windows PowerShell 5.1 and PowerShell 7.0–7.2 pass their standard handles directly to the demo. Use PowerShell 7.3 or newer to capture `run.ps1` output in a PowerShell pipeline.

```powershell
.\run.ps1 -GitRoot 'C:\Program Files\Git'
.\run.ps1 -ConPty
.\run.ps1 -NoConPty
.\run.ps1 -ConPty -TerminalSize '120x40'
.\run.ps1 -NoNativeRelay
.\run.ps1 -Raw
```

The default target is Git for Windows' `usr/bin/bash.exe`. That is the MSYS executable. The Bash launcher in the Git root or `bin` directory is a separate entry point. `-Raw` starts the workload without the shim for comparison.

By default the demo runs a short Bash startup, fork, and `uname` check, then exits. It still selects the terminal mode from the standard handles. `-ConPty` opens an interactive Bash session with `/usr/bin:/bin`, `TERM=xterm-256color`, and a UTF-8 locale. Explicit `-CommandArguments` are forwarded as given. Other `-Program` targets run with their usual defaults. `-BinaryDirectory` selects another build's `bin` directory.

The demo gives interactive `powershell.exe` or `pwsh.exe` a writable PSReadLine history file when the only arguments are `-NoProfile`, `-NoLogo`, or `-NoExit`. Calls with `-Command` or `-File` keep their own initialization. The original user history remains subject to PSEC file policy.

## Command-line reference

```text
psec-run.exe --policy=FILE [--psec-version=auto|1.0|1.1] -- COMMAND [ARGUMENTS...]
psec-run.exe -h | --help
msys-sandbox-compat-shim.exe [OPTIONS] -- COMMAND [ARGUMENTS...]
msys-sandbox-compat-shim.exe -h | --help
msys-sandbox-compat-shim.exe --version
```

`psec-run.exe` creates a native PSEC 1.0 or 1.1 environment from a policy with MXC-style filesystem, enumeration, and direct network rules. Pass the policy with `--policy=FILE` and put the target command after `--`. Relative executable paths resolve from the working directory, and bare command names use Windows executable search.

Run the shim with a normal token or inside an existing restricted environment. An existing launcher can prepend `msys-sandbox-compat-shim.exe --` to the target command. The shim passes the native command line after `--` through to the target. Relative paths resolve from the working directory, and bare command names use normal Windows search. Put both the shim and the target where the existing policy already permits read and execute access.

Diagnostics default to `off`. Set `--log-level=error|warning|info|trace` to write diagnostics to stderr, or use `--log-file=FILE` to append to a separate file. `info` reports startup and exit. `trace` also reports modules, descendants, and [image mapping](design.md#dll-mapping).

### Compatibility modules

All MSYS compatibility modules are enabled by default. To compare behavior, disable selected modules with `--disable-modules=NAME[,NAME...]`, for example `--disable-modules=dll-placement,exe-placement`. The demo equivalent is `-DisableModule dll-placement,exe-placement`. The choice applies to the current launch and its prepared descendants.

| Module | What disabling it skips |
|---|---|
| `propagation` | The process creation hook and automatic propagation, including the default native relay. It conflicts with explicit `--native-relay=on` |
| `heap-window` | Pre-creation import checks on disk, temporary heap-window reservation, and release |
| `exe-placement` | An attempt to use the PE preferred base for non-`DYNAMIC_BASE` cold-start and exec images, and placement at the parent's actual base after fork |
| `dll-placement` | DLL placement hook and its section queries |
| `ipc` | MSYS named-object path and explicit ACL adaptation, including namespace preparation |
| `process-dacl` | Adaptation of caller-supplied process and initial-thread DACLs, and of the process DACL that MSYS resets at startup |
| `token-dacl` | Adaptation of the MSYS primary token's default DACL |

Disabling a module can reproduce the failure it addresses. Each process determines whether ACL adaptation applies using its own primary token. A nested shim inherits the relay configuration. It reports an error if asked to disable a module already enabled in that tree. Trace diagnostics report the launcher settings and the actual child-side bitmask, starting with the least significant bit in table order.

### Terminal modes and exit status

The shim tracks the process tree with a Windows job and returns the root process's exit code. `--terminal=auto` inspects stdin, stdout, and stderr separately. If an outer console is available and any stream is a console handle, it creates an inner ConPTY. The target's console streams go to the inner console. Files, pipes, and `NUL` retain their inherited handles. When all three streams are redirected or no outer console is available, auto mode passes the handles directly. `--terminal=inherit` forces direct inheritance. `--terminal=conpty` forces the bridge. The demo equivalents are `-NoConPty` and `-ConPty`. [Eight stream combinations](decisions/0014-conpty-preserve-redirected-stdio.md)

The bridge carries VT input and output. In auto mode it uses the outer viewport's initial dimensions and follows resizes, including when some streams are redirected. When the bridge is active, `--conpty-size=COLSxROWS` keeps its dimensions fixed. Specify two decimal integers from `1` through `32767` separated by a lowercase `x`, such as `120x40`. The demo equivalent is `-TerminalSize`. When a console size is unavailable, the default is `100x30`.

Forced ConPTY accepts VT input from redirected stdin. The target reads from a console handle. When the external file or pipe reaches EOF, the bridge keeps the console connection open. Use `--terminal=inherit` for batch jobs that rely on stdin EOF. If the ConPTY output destination closes or a write fails, the shim ends the session with exit code `1`.

The bridge sets VT modes and UTF-8 code pages for the console directions it uses. When the inner console can represent the outer cursor position, it starts there and preserves already displayed content. The bridge forwards any clear-screen sequence emitted by the application. It drains output before restoring the original console modes and code pages. The waiting host handles its own Ctrl+C notification, and the foreground application responds according to its console settings.

### Native relay

Native relay is on by default for AMD64 and WoW64 roots and intermediate processes. Both architectures can alternate in the launch chain before it reaches AMD64 MSYS. Use `--native-relay=off` or `run.ps1 -NoNativeRelay` to stop automatic propagation at a native process. A nested shim that has inherited relay state reports an error if asked to turn it off. [Native relay design](design.md#native-relay)

## Run inside an existing sandbox

Use `tests/conpty.ps1 -Environment Existing` from the actual harness to test its inherited context. The script uses that environment's policy and ACLs. See [testing](testing.md) for prerequisites and how to check the applicable access-denied cases.

Creating a new PSEC can fail from a caller that lacks access to the API, for example with `0x800706d9`. Run the demo from a host that can create PSEC, or run the shim inside an environment already created by your launcher. The demo reports failure if native PSEC creation fails.

See [compatibility](compatibility.md) for limits tied to specific Windows and MSYS versions.
