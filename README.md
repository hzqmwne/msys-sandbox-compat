# MSYS Sandbox Compat

[简体中文](README.zh-CN.md)

Run MSYS2 and Git for Windows tools inside an existing Windows sandbox. The x64 shim helps unmodified Bash, Perl, and GNU tools run workloads that rely on `fork`, pipes, signals, and interactive terminals.

## Use it

Download the Windows x64 release for the standalone shim and `psec-run.exe`, a separate launcher that creates a native PSEC environment. [Downloads](https://github.com/hzqmwne/msys-sandbox-compat/releases)

To build the same two executables, use the Visual Studio C++ x64 tools, the Windows SDK, and either Windows PowerShell 5.1 or PowerShell 7.

```powershell
.\build.ps1 -Configuration Release -Tools -Install
```

Put `msys-sandbox-compat-shim.exe` where the sandbox already allows reads and execution. A local build stages it under `build\package\bin`. From its directory inside the sandbox, put the shim before the target command.

```powershell
.\msys-sandbox-compat-shim.exe -- 'C:\Program Files\Git\usr\bin\bash.exe' --noprofile --norc -c 'echo ready; (echo fork-ok)'
```

The shim contains its agent DLL. Use `-h` for options and `--version` for the version. Diagnostics are off by default. Use `--terminal=inherit` when the target should receive stdin, stdout, and stderr directly.

## How it works

| Compatibility area | What the shim does |
| --- | --- |
| Runtime detection and startup | Recognizes AMD64 executables whose normal import table directly names `msys-2.0.dll`. It prepares the agent while the child is suspended. The agent installs the applicable hooks on the child's first entry to `LdrInitializeThunk`. |
| Stack and heap placement | Temporarily reserves the MSYS stack and heap address window during process creation so Windows places its initial allocations elsewhere. The parent releases the window before the child runs, and MSYS allocates its own heaps. |
| EXE and DLL addresses | For fork, the child can remap its main EXE at the parent's actual load address. Cold startup and exec can try the PE preferred address for a non-`DYNAMIC_BASE` MSYS EXE. Eligible DLLs can try their preferred address at section mapping and fall back to the original Windows request. |
| Named IPC and explicit DACLs | Routes named MSYS IPC to the AppContainer namespace or to a private directory for a non-AppContainer restricted tree. For supported explicit DACLs, it grants the restricted SID only missing rights already granted to the user or enabled groups. This also covers caller-supplied process and thread DACLs at creation. |
| Default and startup DACLs | Adapts the DACL that MSYS supplies for its primary token's `TokenDefaultDacl` and for the current process object. Each process resolves its own restricted SID. |
| Native process chains | Relays compatibility through native AMD64 and WoW64 processes by default. A native process installs only the process-creation hook, which lets a later MSYS descendant receive the full set of applicable hooks. |
| Interactive terminals | Starts an inner ConPTY when needed for low-integrity screen reads and console input writes. It bridges the console streams and passes redirected streams through to the target. The outer terminal keeps its session. |

The hooks are at `ntdll` entry points and use MinHook's HDE64 and adapted instruction relocation code. The sandbox's file and resource policy stays in force, and the shim leaves the MSYS installation on disk as supplied. See the [design](docs/design.md) for hook scope and fallback rules.

## Compatibility and limits

- The primary tested setup is Windows x64 with native PSEC 1.0 and Git for Windows MSYS 3.6.10. Regressions also cover two fixed non-AppContainer restricted-token configurations.
- Full compatibility applies to AMD64 executables that directly import `msys-2.0.dll`. Cygwin is outside the current support scope. MSYS2 releases with different ASLR settings need their own fork and coexistence checks.
- Under tested PSEC settings, inherited disk-file stdout or stderr can crash Bash at startup. Microsoft Store PowerShell also has restrictions when launched from a parent without package identity.

See [tested configurations and known limits](docs/compatibility.md), the [user guide](docs/getting-started.md), the [documentation index](docs/README.md), and the [changelog](CHANGELOG.md).
