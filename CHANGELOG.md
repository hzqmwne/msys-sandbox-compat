# Changelog

English | [简体中文](CHANGELOG.zh-CN.md)

The [compatibility matrix](docs/compatibility.md) records where the changes have been tested.

## 0.1.0

### Compatibility modules

- Native relay is on by default and supports native WoW64 roots and mixed AMD64/WoW64 chains. Use `--native-relay=off` to disable it.
- Separate process propagation, heap-window reservation, EXE and DLL placement, MSYS IPC, and the two DACL adaptations. `--disable-modules=NAME[,NAME...]` also skips the selected modules' preflight, metadata reads, and hook installation. `--log-level=trace` reports enabled modules. [Module reference](docs/getting-started.md#compatibility-modules)

### Build and command line

- Ship `msys-sandbox-compat-shim.exe` with the agent DLL embedded. Development builds also produce a separate EXE and DLL.
- The shim uses `--` to delimit the native command, supports transparent stdio, and can write diagnostics to a separate file. Logging defaults to off.
- The shim and `psec-run.exe` accept `-h` and `--help`. The shim also accepts `--version`.
- The release includes the standalone `psec-run.exe` launcher for native PSEC 1.0 and 1.1, including MXC-style filesystem, enumeration, and direct network fields.
- `psec-run.exe` requires `--policy=FILE -- COMMAND`. The former positional policy syntax has been removed.
- Build, demo, and test scripts support Windows PowerShell 5.1 and PowerShell 7. CTest prefers PowerShell 7.
- `run.ps1` writes UTF-8 policy files without a BOM and preserves quotes and empty arguments when calling native programs from older PowerShell versions.

### MSYS memory layout

- Temporarily reserve the heap window when creating a recognized MSYS process and release it before resume. Stock MSYS reserves and commits cygheap and userheap itself. Remove the `NtAllocateVirtualMemory` hook.
- For cold startup and exec, try the PE preferred base once for eligible non-`DYNAMIC_BASE` MSYS executables. Keep the original base on failure. Fork continues to use the parent's actual base.
- Recognize a direct import of `msys-2.0.dll` from the EXE's own import table. Read DLL flags, size, and preferred base from the existing section. Eligible AMD64 DLLs without `DYNAMIC_BASE` can try their preferred base when no base is requested and the full range meets `ZeroBits`. On failure retry the original request. [ADR-0012](docs/decisions/0012-prefer-dll-image-base-at-map.md)

### Terminal I/O

- Auto ConPTY preserves file, pipe, and `NUL` redirection per stream. With an outer console and at least one console handle, it bridges the screen reads and input event writes required by Low IL targets. [ADR-0014](docs/decisions/0014-conpty-preserve-redirected-stdio.md)
- Set the appropriate UTF-8 code pages and VT modes and restore them after draining output, including after a failed launch.
- The inner ConPTY inherits the outer cursor when possible and preserves console content displayed before launch.
- The waiting shim and PSEC demo handle their own Ctrl+C notifications while the foreground application keeps its normal interrupt behavior.
- Reuse the ACL transform when MSYS sets its process DACL at startup, allowing the tested runtime to check console-owner liveness.
- Initialize GNU tool paths, TERM, and a UTF-8 locale for the default interactive Bash demo.
- Give the interactive PowerShell demo a writable PSReadLine history file and check that commands persist.
- Complete short writes in both ConPTY forwarding directions. End that direction on failure or zero progress.
- Follow the outer console's initial size and resizes. `--conpty-size` selects a fixed size.
- Share one decimal parser between the two size option spellings, removing the general-purpose scanner from the Release shim.
- Wake the resize thread as teardown begins to reduce the wait after the last output.
- Test UTF-8 round trips, mixed inherited redirection, and early downstream closure.

### Git workflows

- Test native Git invoking an MSYS `pre-commit` hook via relay with PSEC and both fixed restricted tokens, including accepted and rejected commits.

### Initialization and failure handling

- Remove full parent/child token comparisons and the root token precheck. Each process resolves its own ACL principal. The tree retains its IPC directory name. [ADR-0018](docs/decisions/0018-resolve-acl-context-in-each-process.md)
- Remove the relay's default DACL baseline, readback, and creation lock. Windows handles default DACL inheritance. A standalone cold launch passes empty parent-image data. [ADR-0016](docs/decisions/0016-drop-relay-default-dacl-baseline.md)
- Remove the built-in Git installation path from the production entry point. The legacy `--runtime DLL` argument can still be parsed and its value is ignored.
- Remove `MSYS_SANDBOX_COMPAT_SESSION`. A non-AppContainer restricted tree uses a compatibility directory named after the host PID. The agent passes the path to supported descendants.
- Initialize compatibility on the child's first loader entry. Preserve application startup context and caller-requested suspension. [ADR-0015](docs/decisions/0015-initialize-at-child-loader-entry.md)
- Terminate the suspended process on setup failure. Drop unreferenced plan fields and rollback across entry points. Apply ACL changes to a copy with reserved capacity.
- Test ACL denials separately for creation-returned handles and reopening by PID. Retain the positive control after restoring the initial policy.
- Run real workload and file-access checks under native PSEC. Retain the unmodified Bash baseline in the non-AppContainer process-chain tests.

### ntdll entry relocation

- Use MinHook HDE64 and its adapted relocation core in place of the fixed eight-byte syscall-prologue assumption. Preserve existing entry jumps.
- Keep relocation planning separate from remote installation. CMake selects the backend. The backend requires no extra runtime DLL.
- Check displacement and input bounds, verify source bytes, and test actual execution. The native relay keeps its single-entry scope. The package includes the MinHook and HDE notices.

### Object access

- Adapt caller-supplied process and initial-thread DACLs at creation. The rule also applies to equivalent native requests, without needing a target image classification or a post-creation read/write round trip. [ADR-0017](docs/decisions/0017-adapt-process-dacl-at-creation.md)
- Adapt explicit object ACLs and `TokenDefaultDacl` from the current request. Preserve owner, group, SACL, and control fields. Add only bits the user and enabled groups already have. Leave deny, empty, and complex inputs to Windows. Express an explicitly NULL DACL through Everyone and the restricted principal.
- Accept setting handles with only `TOKEN_ADJUST_DEFAULT`. Preserve Windows behavior for other tokens and query-only handles.
- Record the shared ntdll entry design and early agent's CRT, import, and TLS constraints. Add security descriptor unit tests and real MSYS regressions.

### Earlier development

- Separate the production EXE/DLL and optional PSEC tool. Move installation staging to `build/package`. Make tools and tests explicit with `-Tools` and `-Tests`. The standalone shim described above is the current production artifact.
- Separate shared host and agent code, internal headers, fixtures, and output. Use a common Windows argument quoting implementation.
- Batch trampoline initialization and page protection. A nested relay reuses existing state.
- Use the same handle loop for scripted and live ConPTY input. Separate stress repeat counts from routine workloads and keep policy checks alongside workload checks.
- Restore explicit re-entry from native tools after MSYS resets its default DACL. End-to-end regressions cover one or three native intermediaries, secondary-thread fork, initial ACL retention, denied file access, and exit status.
- Use a read-only token pseudo-handle and direct namespace queries in the host. Scope tests cover native targets with relay disabled and default ACL inheritance.
- Introduce native relay as an explicit option before making it the default. Cover nested entry, ConPTY, caller-requested suspension, and all three restricted environments.
- Add interactive tests for the fixed non-AppContainer tokens, including TTY, window size, Perl fork, native commands, Ctrl+C, job control, exit status, and access denials. Add Existing mode for a caller's own restricted context.
- Use a per-launch namespace for non-AppContainer restricted trees. Verify Bash, Perl, native re-entry, pipes, coexistence, and denied writes and WRITE_DAC, with an unmodified baseline.
- Introduce native PSEC tooling, AMD64 agent preparation in suspended MSYS processes, and ConPTY with a separate owner for the initial console handles. Add fork, scope, late-load, and installation integrity checks.
- Standardize the project, repository, output names, namespace, headers, and object prefixes. Maintain current design, usage and test documentation, and numbered ADRs. Production follows the existing token and on-disk file ACL policy.
