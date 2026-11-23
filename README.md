# MSYS Sandbox Compat

[简体中文](README.zh-CN.md)

Run MSYS2 and Git for Windows tools inside an existing Windows sandbox. The x64 shim helps unmodified Bash, Perl, and GNU tools run workloads that rely on `fork`, pipes, signals, and interactive terminals.

## Use it

Build with the Visual Studio C++ x64 tools, the Windows SDK, and either Windows PowerShell 5.1 or PowerShell 7.

```powershell
.\build.ps1 -Configuration Release -Install
```

Put `build\package\bin\msys-sandbox-compat-shim.exe` where the sandbox already allows reads and execution. From its directory inside that environment, put the shim before the target command.

```powershell
.\msys-sandbox-compat-shim.exe -- 'C:\Program Files\Git\usr\bin\bash.exe' --noprofile --norc -c 'echo ready; (echo fork-ok)'
```

The shim contains its agent DLL. Use `-h` for options and `--version` for the version. Diagnostics are off by default. Use `--terminal=inherit` when the target should receive stdin, stdout, and stderr directly.

## How it works

The shim keeps the address layout that MSYS fork expects and adapts access to the Windows objects that MSYS uses to coordinate processes. It carries those preparations through native child processes, including WoW64 intermediaries. For interactive sessions, it creates an inner ConPTY when needed and preserves file and pipe redirection. The existing sandbox continues to govern file and resource access, and the MSYS installation stays on disk as supplied. See the [design](docs/design.md).

## Compatibility and limits

- The primary tested setup is Windows x64 with native PSEC 1.0 and Git for Windows MSYS 3.6.10. Regressions also cover two fixed non-AppContainer restricted-token configurations.
- Full compatibility applies to AMD64 executables that directly import `msys-2.0.dll`. Cygwin is outside the current support scope. MSYS2 releases with different ASLR settings need their own fork and coexistence checks.
- Under tested PSEC settings, inherited disk-file stdout or stderr can crash Bash at startup. Microsoft Store PowerShell also has restrictions when launched from a parent without package identity.

See [tested configurations and known limits](docs/compatibility.md), the [user guide](docs/getting-started.md), and the [changelog](CHANGELOG.md).
