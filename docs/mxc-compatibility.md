# MSYS compatibility in MXC ProcessContainer

MSYS Sandbox Compat uses hooks to run the installed x64 MSYS2 runtime in MXC ProcessContainer while upstream patches make their way into packaged runtimes. The shim uses the file access granted by the existing policy. [Getting started](getting-started.md) · [Download v0.1.0](https://github.com/hzqmwne/msys-sandbox-compat/releases/tag/v0.1.0)

## Tested command

Run this on the host with a ProcessContainer policy that permits reading and executing the shim and MSYS installation.

```powershell
.\wxc-exec.exe --config .\policy.json -- 'C:\tools\msys-sandbox-compat-shim.exe' -- 'C:\msys64\usr\bin\bash.exe' --noprofile --norc -c 'echo ready; (echo fork-ok); echo pipe-ok | /usr/bin/tr a-z A-Z'
```

On Windows 11 x64 `26300.9974`, with `wxc-exec.exe 1.1.0+6a89e69c` using the native `base-container` tier, stock MSYS2 `3.6.12-1` hit `STATUS_ACCESS_DENIED` (`0xC0000022`) in `NtCreateDirectoryObject` and exited with `0xC0000142`. With the same read-only policy and the v0.1.0 shim, the example printed `ready`, `fork-ok`, and `PIPE-OK` and exited with code `0`. [Original MXC report](https://github.com/microsoft/mxc/issues/1061)

## Upstream work and shim behavior

The upstream patches change the MSYS runtime itself, including its fork, spawn, and AppContainer object handling. The v0.1.0 shim leaves the installed `msys-2.0.dll` in place and handles those calls through hooks at the `ntdll.dll` layer. Its console bridge uses the Windows ConPTY API. [MSYS2 runtime PR #403](https://github.com/msys2/msys2-runtime/pull/403) · [Git for Windows runtime PR #148](https://github.com/git-for-windows/msys2-runtime/pull/148)

| Problem | Upstream work | What the v0.1.0 shim does |
| --- | --- | --- |
| **Stack and heaps.** The loader can allocate in the range MSYS needs for its stack and heaps. | Start affected fork/spawn children with `CREATE_SUSPENDED`, then use `VirtualAllocEx` to reserve cygheap at `[0x800000000, 0xA00000000)` (32–40 GiB) before resuming the child. | Pass `PS_ATTRIBUTE_MEMORY_RESERVE` with `[0x600000000, 0x1000000000)` (24–64 GiB) in the `NtCreateUserProcess` attribute list. `CreateProcessW` exposes no corresponding attribute. The creator releases its reservation before resuming the child or returning it suspended. |
| **EXE and DLL placement.** A relocated image can break fork. | Map the fork child’s EXE at the parent’s loaded base and update the PEB and startup entry. MSYS2 separately restored `DYNAMIC_BASE` for the runtime DLL in 3.6.12. [MSYS2 runtime PR #381](https://github.com/msys2/msys2-runtime/pull/381) | `prepare_exe_layout` uses the parent’s recorded EXE base for fork. On cold start or exec, it tries `ImageBase` from the PE header for EXEs without `DYNAMIC_BASE`. The `NtMapViewOfSection` hook tries `ImageBase` for eligible DLLs without `DYNAMIC_BASE` when the request leaves `BaseAddress` unset. If that mapping fails, it retries the original request. |
| **Named IPC and explicit DACLs.** `NtCreateDirectoryObject` can fail on an MSYS directory under `\BaseNamedObjects`. | Use `RtlGetAppContainerNamedObjectPath` for shared objects, add the AppContainer SID in `sec_acl()`, and retry supported pipes with the `LOCAL\` prefix. | At `NtCreateDirectoryObject`, rewrite matching MSYS names in `OBJECT_ATTRIBUTES` to the applicable IPC namespace. Handle pipe creation at `NtCreateNamedPipeFile`. Adapt supported object DACLs and the explicit process/thread DACLs passed to `NtCreateUserProcess`, using rights already granted to the user or enabled groups. |
| **Default and startup DACLs.** The DACLs MSYS sets at startup can omit the restricted SID. | Build the startup token default DACL through `sec_acl()` with the AppContainer SID. | Adapt `NtSetInformationToken(TokenDefaultDacl)` for the current primary token and DACL-only `NtSetSecurityObject` calls on the current process. |
| **Interactive consoles.** Low-integrity targets can be denied screen reads or console input writes. | MXC tracks native ProcessContainer PTY support in [MXC #1757](https://github.com/microsoft/mxc/issues/1757). | Call `CreatePseudoConsole` inside the restricted environment when needed. Bridge console handles and pass redirected files and pipes directly to the target. |

## Known gaps in v0.1.0

- **Shared DLL state and named objects.** Processes loading the same MSYS DLL file can still share its writable `.cygwin_` section after BaseNamedObjects (BNO) redirection puts their named objects in separate IPC namespaces. Matching DLL bases can avoid stale `wincap.caps` pointers in this case. The runtime still needs to give its Winsock event table and the mutexes that protect it the same sharing scope. The upstream series proposes moving the table and its serial counter into a named section alongside those mutexes. [Shared image sections](compatibility.md#shared-msys-image-sections) · [Runtime PR #403](https://github.com/msys2/msys2-runtime/pull/403)
- **Inherited disk-file stdout or stderr.** In the tested Git for Windows MSYS 3.6.10 setup, Bash can crash in `fstat` at startup after PSEC denies `QueryDosDeviceW` during descriptor setup. The runtime needs to handle that denial without crashing. DOS-volume lookups inside BaseContainer are also being tracked on the Windows/MXC side. [Disk-file redirection](compatibility.md#disk-file-redirection-under-psec) · [MXC #1464](https://github.com/microsoft/mxc/issues/1464)
- **Packaged PowerShell.** In the tested PSEC setup, an unpackaged parent already inside the container failed to launch Microsoft Store PowerShell because Windows package activation was denied. The activation path needs a Windows/PSEC fix. [Packaged PowerShell results](compatibility.md#microsoft-store-powershell-under-psec) · [MXC #1758](https://github.com/microsoft/mxc/issues/1758)
- **Input after resize.** In the tested Windows Terminal Git Bash session, typing immediately after resizing the window occasionally dropped the first character. [Compatibility notes](compatibility.md#msys-and-windows-versions)
