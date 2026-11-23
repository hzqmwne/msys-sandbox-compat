# Compatibility

The standalone shim runs with a normal token or an existing restricted token. `psec-run` is a separate test tool. The main native PSEC regression setup uses Windows x64 build `26300.9974`, PSEC 1.0, and Git for Windows MSYS `3.6.10`, with its Bash, Perl, and GNU tools.

| Area | Coverage |
|---|---|
| MSYS processes | The shim uses the original EXE and `msys-2.0.dll`. Fork, exec, pipes, signals, and fork from a secondary thread passed regression and stress runs in the tested configurations |
| Process chains | Tests cover a native root, explicit re-entry through the shim, one or three native intermediaries, and a caller that requests a suspended child |
| Native relay | The default relay installs only the process creation hook in native processes. It covers AMD64 and WoW64 roots and intermediaries, including mixed chains that return to AMD64 MSYS. Both deliverables are AMD64. Use `--native-relay=off` to disable relay |
| Runtime-loaded images | EXE recognition uses the direct import table. Eligible DLLs are handled when first mapped |
| Terminals | An existing Windows Terminal tab can host the shim. Interactive suites passed with PSEC and both fixed non-AppContainer tokens. The nested PSEC ConPTY probe covers resize, cursor inheritance, and preservation of the outer screen after exit |
| Standard streams | Traditional `cmd` keeps file, pipe, and `NUL` redirection per stream. All eight combinations were checked with MSYS2 and Git for Windows for `isatty`, stream destinations, and `/dev/tty`. `--terminal=inherit` passes handles directly, as does auto mode when all three streams are redirected. [ADR-0014](decisions/0014-conpty-preserve-redirected-stdio.md) |
| Git hooks | In an initialized worktree, native Git runs an MSYS `pre-commit` hook through the default relay. PSEC and both fixed tokens passed acceptance, rejection, and file access checks |
| Non-AppContainer tokens | Fixed write-restricted and full restricting-SID fixtures passed Bash/Perl, fork, native bridges, pipes, file access checks, and coexistence with a normal MSYS session |

These results use the default [compatibility modules](getting-started.md#compatibility-modules). Use the shim explicitly at the launch point. Compatibility depends on the effective policy, process creation path, runtime, and console handles. The fixed environments are test configurations for those conditions.

## MSYS and Windows versions

Full compatibility requires a direct, ordinary import of `msys-2.0.dll` in an AMD64 EXE. An EXE that loads MSYS later with `LoadLibrary`, uses only a delay import, or reaches MSYS through an intermediate DLL is outside early recognition. Cygwin is outside the current support scope.

Once a process is recognized as MSYS, eligible DLL mapping applies regardless of path. If the preferred base is unavailable, Windows chooses a base using the original request. Different parent and child addresses can still break fork. The current hook covers `NtMapViewOfSection`. [DLL mapping](design.md#dll-mapping)

Windows chooses the base for DLLs marked `DYNAMIC_BASE`. The official MSYS2 `msys2-runtime` package `3.6.12-1` restores that flag on `msys-2.0.dll`. In the checked package, the DLL, `bash.exe`, and `uname.exe` lacked `HIGH_ENTROPY_VA`, and the two EXEs lacked `DYNAMIC_BASE`. Verify coexistence, parent and child layout, and fork under the actual ASLR policy for such versions. [MSYS2 runtime #381](https://github.com/msys2/msys2-runtime/pull/381) · [MSYS2 packages #6820](https://github.com/msys2/MSYS2-packages/pull/6820)

The shim depends on AMD64 ntdll syscall entry points, Windows Native APIs, and the internal MSYS address layout. Temporary heap-window reservation and release were validated on Windows 11 x64 build `26300.9974` with Git for Windows MSYS `3.6.10`. Older Windows versions need their own validation of the import slot, runtime layout, and `PS_ATTRIBUTE_MEMORY_RESERVE` path.

In the tested Windows Terminal Git Bash session, typing immediately after a resize occasionally dropped the first character. The resize regression checks that the inner window receives the resize.

## Restricted-token fixtures

Native relay covers descendants created through AMD64 `NtCreateUserProcess`, including WoW64 calls that reach that entry point. Windows chooses the child token and its default DACL. Each process uses its own primary token for ACL adaptation. IPC uses the directory assigned to the launch tree and remains subject to that directory's ACL. [Native relay](design.md#native-relay) · [ADR-0018](decisions/0018-resolve-acl-context-in-each-process.md)

Both fixed token fixtures use `DISABLE_MAX_PRIVILEGE | LUA_TOKEN`, disable Administrators, and include the logon SID, Everyone, Builtin Users, and Authenticated Users as restricting SIDs. The write-restricted mode adds `WRITE_RESTRICTED`. The launcher preserves logon and SYSTEM grants and the OWNER RIGHTS restriction. Tests set ACLs on a marked workspace and stage read-only copies of the shim and fixtures. Git and MSYS load from their original installation. In full restricting-SID mode, reads must also pass the restricting SID check.

These ACLs define the fixture's initial conditions. The production shim uses the file access granted by the existing policy and leaves on-disk ACLs in place. `restricted-run.exe` is a test fixture. Its checks cover specific read-only, writable, and denied locations and Windows objects. The terminal suite also checks Perl and secondary-thread fork, TTY behavior, window size, native commands, Ctrl+C, job control, exit status, and the original access-denied cases before and after interaction.

## Disk-file redirection under PSEC

With Git for Windows MSYS `3.6.10` under the tested PSEC policy, Bash can crash before the script starts when a native launcher passes a disk file as stdout or stderr. The opening process can be inside or outside PSEC.

When MSYS reconstructs descriptors from inherited Windows standard handles, it calls `QueryDosDeviceW(NULL, …)` for disk files to resolve the drive letter. Pipes and Windows `NUL` use dedicated branches. MSYS children that inherit the parent's descriptor state skip the enumeration.

Under the tested policy, the enumeration returns `ERROR_ACCESS_DENIED`. Bash's line buffering calls `fstat` on stdout and stderr, where the inode fallback dereferences a null path. An inherited disk-file stdin can still be read directly. An explicit `fstat` reproduces the crash.

## Microsoft Store PowerShell under PSEC

On Windows x64 build `26300.9974` with PSEC 1.0, the launcher could start Microsoft Store PowerShell `7.7.0` as the first process, using either the execution alias or the packaged `pwsh.exe`. The process retained its `Microsoft.PowerShell` package identity in the AppContainer. The PSEC process creation attribute led to `processmodel!CreateProcessAsUserInsideSecurityEnvironment`. That PowerShell could then run Bash through the shim and pass the fork test.

A parent inside the same PSEC without a package identity failed to start the Store version. As a shim target, the alias returned Win32 error 1920 and the packaged EXE returned error 5. Bash reported `Permission denied` and exit code 126 for both. The native control run reproduced the Windows errors with the shim removed. A Store PowerShell parent with the same package identity could start a PowerShell child through either entry point in the same PSEC.

The file ACL grants read access to ordinary users. A conditional ACE grants execute access to tokens whose `WIN://SYSAPPID` contains the PowerShell package family. The unpackaged parent could read the file and create a `SEC_IMAGE` mapping, while direct `FILE_EXECUTE` requests were denied. A normal Windows parent obtained the package token through AppModel activation and retried with the resulting package attribute. [Conditional ACEs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-) · [MSIX command-line activation](https://devblogs.microsoft.com/insidemsix/activation-via-command-line/)

For the unpackaged PSEC parent, the first `NtCreateUserProcess` returned `STATUS_IO_REPARSE_TAG_NOT_HANDLED` for the alias and `STATUS_ACCESS_DENIED` for the packaged path. Windows then called `AicGetPackageActivationTokenForAlias` or `AicGetPackageActivationTokenForFilePath`. Both ALPC connection attempts returned `STATUS_ACCESS_DENIED`, followed by AppModel RPC error 1753 (`EPT_S_NOT_REGISTERED`). Windows did not retry process creation. The normal parent connected to the endpoint under `\RPC Control`. The PSEC parent tried the same endpoint name in its AppContainer namespace and was denied. The trace identifies the failing connection, and the specific kernel authorization check remains undetermined. [Windows system error 1753](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1700-3999-)

The packaged parent went through `processmodel!BrokerSandboxedCreateProcess`, with the child retaining its package identity and AppContainer. The unpackaged PowerShell `7.6.9` passed both `PSEC → shim → pwsh → Bash` and `PSEC → shim → Bash → pwsh`. The actual process identity and launch chain determine whether this limit applies.

## Shared MSYS image sections

In the local comparison, normal Windows Bash and Bash under native PSEC with the shim used the same installed Git for Windows MSYS `3.6.10` DLL at `0x210040000`. Both runs passed Bash pipes, command substitution, Git operations, and Perl fork. The PSEC workload returned the expected exit code 37 with the preferred image base strategy introduced by `4d9e784`. [ADR-0012](decisions/0012-prefer-dll-image-base-at-map.md)

In an earlier control, a live PSEC instance used a different DLL base. New instances succeeded 0/4 times with the same DLL file and 4/4 with a byte-identical copy. The writable shared `.cygwin_` section holds an absolute `wincap.caps` pointer. If instances use different bases, a later instance can access the earlier address in `DLL_PROCESS_ATTACH`. This remains possible when the images cannot be aligned.

Windows associates the shared image section with the file stream. Reopening the same file or loading it through an NTFS hard link still uses the same stream. The shim loads the original installation, retaining this sharing behavior. PSEC uses the OS-provided AppContainer object namespace. Non-AppContainer restricted environments use the launch tree's private directory. MSYS coordination data needs the same sharing scope as the objects that protect it. [Windows image sections and file streams](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_section_object_pointers) · [Object access design](design.md#object-access-and-hooks)

A Cygwin mailing list proposal suggested storing `wincap` in process-private storage initialized by the fork child. The MSYS2 proposal checks that the pointer falls inside the current process's image while keeping the field shared. This is upstream work. [Cygwin patch discussion](https://www.mail-archive.com/cygwin-patches@cygwin.com/msg13326.html) · [MSYS2 PR #403](https://github.com/msys2/msys2-runtime/pull/403)

Winsock's event table and slot numbering need to share the scope of the mutex that protects them and the matching MSYS object directory in the AppContainer. A Git for Windows proposal moves this state to named shared memory. The separate-file and whole-image-section variants were local experiments. Socket inheritance, event notification, and isolation across AppContainers still need validation. [Git for Windows PR #148](https://github.com/git-for-windows/msys2-runtime/pull/148)
