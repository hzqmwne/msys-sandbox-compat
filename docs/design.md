# Design

This page describes the current implementation. See the [architecture decisions](decisions/README.md) for its rationale, the [user guide](getting-started.md) for CLI behavior, and the [changelog](../CHANGELOG.md) for changes.

## Production constraints

The shim leaves disk file and directory ACLs and the existing token restrictions in place. File reads, execution, writes, and other resource access are governed by the original sandbox. The program reports access denials from that policy. Deploy the shim where the policy already permits read and execute access.

Object security descriptor adaptation covers MSYS IPC, explicit process and thread DACLs supplied at creation, and the process and primary-token default DACLs set by MSYS. Each process uses its own primary token to select the restricted principal and adapts the caller's current descriptor. Fixture file ACLs define the tests' initial policy.

## Components and dependencies

The shim treats object access, fork image layout, process propagation, and terminal I/O as separate compatibility problems. Hooks use ntdll entry points so they can see the relevant Windows calls without depending on an MSYS import slot or internal RVA. The scope of EXE recognition and process preparation remains bounded by the rules below.

The release is a single EXE with an embedded agent DLL. The development build also keeps the EXE and DLL as separate files. The host statically links the CRT. The early agent has no CRT, ordinary or delay imports, TLS, global constructors, or `DllMain`. The relocation backend uses MinHook v1.3.4's HDE64 and adapted relocation code. A bounded plan interface keeps relocation separate from installation and lets CMake select the backend. [ADR-0009](decisions/0009-minhook-relocation-backend.md)

The build uses the same PE reader as the host to verify the linked agent DLL. It checks the entry point, imports, TLS, required exports, data and executable sections, and unwind directory. At launch the host validates the agent image and matching ABI, checking the file and image ranges it accesses. Standalone launch and inherited relay use the same image size limit. The build validator is a development tool.

## Process creation and recognition

The external sandbox launcher sets the policy. The shim reads its verified DLL from a PE resource. The development EXE reads it from its own directory. The optional `psec-run` tool creates PSEC test environments. The host and agent share core sources compiled under their respective CRT and stack constraints.

The host starts the target with `CREATE_SUSPENDED`. An EXE whose normal import table directly names `msys-2.0.dll` selects the MSYS ABI, with a case-insensitive name comparison. Recognition reads only that EXE's import table. Transitive dependencies, delay imports, and renaming a native program to Bash do not match. Newly installed executables can be recognized on their first launch. The host can also start under a normal token. IPC and DACL adaptation apply only where the token calls for them.

With the heap-window module enabled, a preflight reads the EXE imports at the path given by the native creation request. A match adds `PS_ATTRIBUTE_MEMORY_RESERVE` for `[8,64)` GiB so Windows places the PEB and initial thread stack outside the window. It covers the low preferred addresses of many MSYS DLLs as well as the runtime thread stack pool, cygheap, and the start of userheap. The agent uses its process creation hook. A standalone host temporarily replaces one of its own KernelBase import slots for this launch while `CreateProcessW` sets up standard handles, environment, and console state. The inherited relay handles that call for a host already in the tree.

Recognition reports both status and match. An invalid import range or a failed read returns an error. With relay enabled, confirmed WoW64 processes use the native propagation path. Other unclassifiable or unpreparable targets are terminated on failure. With relay disabled, an unclassifiable descendant is left alone and trace logging notes the missing classification.

The suspended image determines whether to prepare the agent. A process that received a preflight reservation must still match MSYS before it can run. The parent releases only its own reservation before resuming or returning the thread to the caller. If recognition first succeeds after creation, the host still prepares the image and object compatibility and MSYS allocates its own heaps. [ADR-0011](decisions/0011-release-heap-reservations-before-start.md)

## Initialization

The host prepares the namespace and propagation settings according to the enabled modules and the token. Normal-token processes use the Windows object paths and ACLs. The host and agent use the same module settings. The process creation DACL rule uses the caller's primary token and the current request. IPC uses the directory name passed down by the launch tree. Each process resolves its own ACL principal. With all modules disabled, the host creates the root suspended, adds it to the job, and resumes it.

The parent prepares the agent and its settings and arranges for initialization on the child's first entry to `LdrInitializeThunk`. A standalone cold launch sends empty parent-image data. An agent that propagates into a child sends its recorded image data for MSYS fork. The creator can still read or update the application startup context while the child is suspended. On first resume the agent restores the loader entry, selects and installs the hooks required by the child image and token, then returns control to the loader. Initialization errors after resume surface as the child exit status. [ADR-0015](decisions/0015-initialize-at-child-loader-entry.md)

For cold startup and exec, the shim can try the PE preferred base once for an MSYS main EXE without `DYNAMIC_BASE`. It keeps the original base if the preferred address is occupied or mapping fails. Windows places images marked `DYNAMIC_BASE`. For fork, if the child base differs from the parent's actual base, the child uses the parent's image path and base to align its view. It updates the PEB and application startup context after validating the new view, and retains the original view. MSYS allocates cygheap and userheap when it starts.

## DLL mapping

A recognized AMD64 MSYS process handles subsequent DLL mappings at `NtMapViewOfSection`. When `*BaseAddress == 0`, the hook uses `NtQuerySection` to read the image type, length, PE flags, and preferred base from the caller's section. The preferred base must be nonzero and 64 KiB aligned. The image must be an AMD64 `SEC_IMAGE` DLL without `DYNAMIC_BASE`. The same rule applies to native DLLs, transitive dependencies, and runtime-loaded extensions at any path.

On the tested AMD64 path, a nonzero count-form `ZeroBits` is relative to the low 32 bits. A value of `1` requires an address below 2 GiB. In mask form the highest set bit determines the upper bound. The full preferred image range must fit under that bound. The original `ZeroBits` goes to Windows.

A failed query or ineligible section uses the original request. If the preferred-base attempt fails, the hook restores `*BaseAddress` to zero and retries once. Failure to restore that input is returned as an error. Trace logging records the requested preferred base, status, actual address on success, and any retry after restoring the input. [ADR-0012](decisions/0012-prefer-dll-image-base-at-map.md)

On fork, MSYS checks the parent and child addresses of the modules registered with its runtime. MSYS DLLs registered through `dll_dllcrt0` at startup enter `DLL_LINK`. MSYS also checks registered `DLL_NATIVE` modules after reloading them. The PE import table orders registered modules. A dynamic `DLL_LOAD` can load away from its preferred base in the parent. MSYS tries to reload it at that actual base in the child before copying data. A successful load at a different address can still break fork. [Image mapping experiments](testing.md#image-mapping-experiments)

## Object access and hooks

| Entry point | Role |
|---|---|
| `NtCreateDirectoryObject` | MSYS private object directory and access |
| `NtCreateSection` | Shared section access |
| `NtCreateMutant` | Mutex access |
| `NtCreateSymbolicLinkObject` | MSYS directory links and access |
| `NtCreateNamedPipeFile` | MSYS pipe access |
| `NtMapViewOfSection` | Preferred base for eligible `SEC_IMAGE` DLLs, with a retry of the original request |
| `NtCreateUserProcess` | Temporary heap window and explicit process/thread DACL adaptation, then suspended child preparation and reservation release |
| `NtSetInformationToken` | Adapt the current primary token's requested default DACL |
| `NtSetSecurityObject` | Adapt a DACL-only request on the current-process pseudo-handle |

For ordinary allow ACLs, the transform retains the original ACEs and adds only access bits already allowed to the current user and enabled, non-deny-only groups and still missing for the restricted principal. AppContainer uses the package SID. Otherwise the rule prefers a logon SID present among both enabled and restricting SIDs, or a single identifiable, non-broad restricting principal from the ACL. Denies and flagged or complex ACEs pass through. Empty ACLs receive no grant. A NULL DACL is represented as Everyone:GA and restricted-principal:GA to retain its open intent and allow the tested shared-section case. Windows supplies missing or default descriptors. Owner, group, SACL, and control semantics are preserved for absolute and self-relative descriptors.

With `process-dacl` active in a restricted context, `NtCreateUserProcess` applies the same transform to an explicit descriptor in `process_attributes` or `thread_attributes` before submitting the request. It changes only the descriptor pointer in a temporary copy. The target need not be classified. MSYS fork provides explicit creation DACLs and skips the cold-start DACL update when it resumes. Later signal delivery requires reopening the target by PID with `PROCESS_DUP_HANDLE`. The adaptation occurs once at creation. A standalone shim passes null process and thread security attributes and uses Windows defaults. [ADR-0017](decisions/0017-adapt-process-dacl-at-creation.md)

Default DACL updates use the ACL in the current request. Only `TokenDefaultDacl` for the current primary token matches. `NtCompareObjects` itself needs no query access on the supplied handle. The original `NtSetInformationToken` checks permission to set it. The resulting default applies to later objects that use it. Explicit object descriptors still use the creation hooks. [ADR-0008](decisions/0008-adapt-requested-object-acls.md)

MSYS cold startup separately sets the token's default DACL and the current process object's DACL. A DACL-only call on the current-process pseudo-handle uses the same transform, and the original system call checks authorization. Recent Git for Windows runtimes use a process handle to check that the console owner is still alive.

The host reads its primary token with the `GetCurrentProcessToken` pseudo-handle. For PSEC, `GetAppContainerNamedObjectPath` and the token session identify the object namespace without requiring a token reopen or a test named event. [ADR-0003](decisions/0003-read-only-security-context.md)

Non-AppContainer restricted processes use the current session's `BaseNamedObjects`. The host names a private directory by its PID, uses the launcher's default DACL, and keeps the handle until the process tree exits. Objects use the descriptors in their current requests. The agent shares the directory path within the tree. With relay off, a shim explicitly invoked beyond a native intermediary starts a new tree and directory. In default ConPTY mode, the inner host creates the directory. AppContainer uses the package namespace provided by Windows. [ADR-0005](decisions/0005-restricted-token-context.md)

## Fork and process chains

MSYS still copies, synchronizes, and restores its own fork state. The shim prepares object access, address layout, and the agent before the relevant child resumes. The caller's suspension state stays intact. The job tracks process lifetime and notifications, while creation handling controls the timing of preparation.

A native descendant created by MSYS can invoke the shim explicitly to start a native or MSYS target. The default object ACL set by MSYS at cold startup retains the access needed by native descendants and re-entered MSYS. End-to-end tests check Bash, Perl, secondary-thread fork, pipes, file access, and exit codes after one or three native intermediaries. [Compatibility](compatibility.md)

## Native relay

Relay is on by default in native roots and descendants. Use `--native-relay=off` to end automatic propagation at a native process. A native process installs the creation hook only, with the same explicit creation DACL rule as an MSYS parent. WoW64 reaches AMD64 `NtCreateUserProcess` through its Windows transition layer and uses the same AMD64 agent. Full image layout and IPC adaptation apply only to recognized AMD64 MSYS.

The creation hook prepares descendants before resume, allowing the runtime to re-enter MSYS through multiple native processes. An explicitly nested shim recognizes the existing agent from the local creation hook and reuses the module settings and IPC directory. The creation hook prepares the child. Initial mapping binds trampolines in a separate agent state copy. This also applies to the native ConPTY session host.

Entry points and trampolines are read or built for the hooks each process actually installs. Unmodified entry points remain callable so a native relay can prepare descendants. A copied agent rebinds original calls for the child's hooks. When propagation is enabled, the agent also records handler locations that descendants may use. Version markers identify the matching DLL and inherited relay state.

Each agent reads its own primary token through a read-only pseudo-handle. MSYS initializes the ACL principal when an ACL module is enabled. The native relay waits for its first explicit DACL adaptation. The SID belongs to the local process and starts empty in each new process. Windows handles default DACL inheritance and final access checks. The IPC directory name belongs to the launch tree, and the directory's ACL controls access. [ADR-0018](decisions/0018-resolve-acl-context-in-each-process.md)

## ConPTY

Auto mode starts ConPTY when an outer console is available and at least one standard handle is a console handle. In a Windows Terminal tab, Windows Terminal continues to own the outer session. The shim calls `CreatePseudoConsole` inside the existing restricted context and starts another instance of the EXE as the native session host. That instance owns the three handles Windows initializes for the inner console. The outer host sends only duplicates of redirected handles through the explicit inheritance list. The session host supplies the appropriate console or inherited handle for each target stream and closes its passthrough copies. Keeping the original console handles in the session host prevents console cleanup from closing a value MSYS has released and reused. Host diagnostics follow outer stderr in mixed mode. [ADR-0014](decisions/0014-conpty-preserve-redirected-stdio.md)

The outer bridge uses the console handles it has and opens `CONIN$` or `CONOUT$` if needed. This allows `/dev/tty` keyboard input with stdin redirected and permits console echo when both output streams are redirected. The agent itself opens neither device.

A frontend with VT pipes can use `--terminal=conpty --conpty-size=120x40 -- COMMAND`. It sends UTF-8 keystrokes to stdin and renders the inner VT stream received on stdout, bypassing the outer console's VT conversion.

With a console output handle and an outer cursor that fits the inner dimensions, the bridge starts ConPTY with `PSEUDOCONSOLE_INHERIT_CURSOR`. The output thread answers the inner startup query once with the cursor's outer viewport coordinates. The inner session starts at the existing cursor, and application VT output is forwarded as usual. With pipe output, ConPTY emits its ordinary initial frame. [Cursor inheritance](https://learn.microsoft.com/en-us/windows/console/createpseudoconsole)

In the tested PSEC configuration, an external Medium IL conhost denied the screen reads and input event writes that Low IL MSYS requires. Lowering an external conhost to Low IL still produced a process-open denial in the tested configuration, where the client DACL included the AppContainer package SID. A normal Untrusted caller also could not open the client. A conhost created inside the same PSEC could query the client token and pass console policy checks. [Windows console access rules](https://learn.microsoft.com/en-us/windows/console/console-buffer-security-and-access-rights#wrong-way-verbs)

Input and output use separate blocking I/O threads. The bridge writes bytes as soon as they are available and retries short writes. Input comes from the terminal handle or an explicit VT source. An input script is opened once. EOF ends that input pump while the target retains its console stdin. Closing conhost's VT input pipe sends `CTRL_CLOSE_EVENT` on the tested Windows versions, so the bridge keeps it open until teardown. If downstream output fails or writes zero bytes, the reader signals the job's completion port to end the process tree, then drains remaining ConPTY output. Normal teardown cancels the blocked input read and forwards the remaining output.

The initial interactive size comes from the outer output console's `srWindow`. A separate thread samples it and calls `ResizePseudoConsole` on changes, even when input is idle. Teardown wakes and joins the resize thread before closing ConPTY. An explicit size, scripted input, or forced ConPTY without an outer viewport uses a fixed size. [Console viewport](https://learn.microsoft.com/en-us/windows/console/getconsolescreenbufferinfo) · [ResizePseudoConsole](https://learn.microsoft.com/en-us/windows/console/resizepseudoconsole)

The inner application negotiates mouse tracking. UTF-8, Win32 key reports, and native VT pass directly from the read buffer. The bridge buffers only an incomplete legacy mouse report and reconstructs SGR once it confirms the wrapper, reusing its forwarding buffer. The inner console interprets that input in the application's input mode. Scripts and redirected input keep their original bytes.

When using console handles, the bridge saves the relevant modes and code pages before setting raw VT input and processed VT output in UTF-8. It drains output before restoring them, including after a failed launch. The waiting shim and `psec-run` handle their own Ctrl+C notifications so a broadcast does not close the job prematurely. The foreground target keeps its own handler. [Console modes](https://learn.microsoft.com/en-us/windows/console/setconsolemode) · [Control handlers](https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler)

Interactive tests passed under PSEC and both fixed non-AppContainer restricted tokens. They exercise Perl and secondary-thread fork, native commands, Ctrl+C, job control, and exit status, with access-denied checks before and after. The harness's integrity levels, desktop, and handles must be checked in its own environment. [Testing](testing.md)
