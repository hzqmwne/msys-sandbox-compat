# Testing

Build the development tools and fixtures with Windows PowerShell 5.1 or PowerShell 7. Integration tests need a host that permits creation of the PSEC environment or restricted token they use. Git defaults to `C:\Program Files\Git`. Use `-GitRoot` on the test scripts to select a different installation.

```powershell
.\build.ps1 -Tests
.\tests\verify.ps1 -Repetitions 10
.\tests\scope.ps1
.\tests\modules.ps1
.\tests\process-chain.ps1
.\tests\process-chain.ps1 -Environment WriteRestricted
.\tests\process-chain.ps1 -Environment FullRestricted
.\tests\git-hook.ps1
.\tests\git-hook.ps1 -Environment WriteRestricted
.\tests\git-hook.ps1 -Environment FullRestricted
.\tests\conpty.ps1
.\tests\conpty.ps1 -Environment WriteRestricted
.\tests\conpty.ps1 -Environment FullRestricted
.\tests\conpty-resize.ps1
.\tests\terminal-session.ps1
.\tests\shim.ps1
.\tests\stdio.ps1
.\tests\late-package.ps1
.\tests\acl.ps1
.\tests\acl.ps1 -Environment WriteRestricted
.\tests\acl.ps1 -Environment FullRestricted
```

| Suite | Checks |
|---|---|
| `inline-hook-test` | MinHook relocation plans, logical addresses and RIP displacements, instruction and page boundaries, chaining, batch installation, relay scope, and page protection restoration |
| `identify-test` | Direct and transitive imports, PE headers across read boundaries, and recognition results on preparation failure. Verifies that disabling EXE placement skips path queries and file reopen, and that preflight opens only the target EXE |
| `object-security-test` | Minimum ACE additions, enabled groups, empty and NULL ACLs, unchanged input, and owner/group/SACL/control preservation in both descriptor formats |
| `stream-write-test` | Consecutive short writes, zero progress, and write failure in the ConPTY forwarding loop |
| `acl.ps1` | Explicit object ACLs and subsequent defaults in real MSYS, including limited grants, deny, other tokens, and adjust-only or query-only handles. `-Existing` uses the caller's context |
| `verify.ps1` | Repeated fork, Bash pipelines, subshells, command substitution, background work, `uname`, file access boundaries, exit codes, native children, and heap-window release for Perl roots and descendants |
| `fork.pl` | PID, heap, copy-on-write, shared offsets, pipes, EOF, signals, exec, WNOHANG, nested and concurrent fork, and fork from secondary threads |
| `scope.ps1` | Native and renamed roots, import recognition, unpatched native descendants, and explicit re-entry without `--runtime`. It checks default token DACLs and the two heap bases and allocation entry in Bash and its fork child |
| `modules.ps1` | The actual hook set in a direct-import fixture, layout switches, propagation and ACL modules, inherited ConPTY and relay settings, conflict handling, and file denial with all modules disabled |
| `process-chain.ps1` | Native root, Bash, one or three native intermediaries, then explicit re-entry into Bash or Perl. It checks fork, secondary-thread fork, pipes, file access, default ACL, and exit status |
| `process-chain.ps1 -Environment WriteRestricted/FullRestricted` | The same chains with both non-AppContainer tokens, an unmodified baseline, coexistence with a normal MSYS session, and verification of the child token and write/WRITE_DAC denials |
| `git-hook.ps1` | Actual `git init`, `git add`, and `git status` in all three restricted environments. Native relay runs an MSYS `pre-commit` hook. The test checks successful and rejected commits, the index, and file access |
| `conpty.ps1` | TTY, 120×40 sizing, UTF-8 round trips, command substitution, fork, native children, Ctrl+C, STOP/bg/fg, and exit status |
| `conpty-resize.ps1` | A PSEC console probe sees outer resizes without keyboard input. It checks auto mode, fixed sizes, and direct inheritance |
| `terminal-session.ps1` | An inner session inherits a nonzero cursor position and leaves existing outer screen content readable after exit. Also checks Unicode rendering, cursor movement, normal and failed startup cleanup, Bash editing and Ctrl+C, PowerShell 5.1 arguments, and interactive history |
| `shim.ps1` | Standalone deployment, help and version output, invalid dimensions, the original native command tail, stdio, native relay, fork, ConPTY, and file logging |
| `stdio.ps1` | PSEC binary stdio round trip of 1 MiB, EOF, early downstream closure, all eight stream combinations, `2>&1`, `NUL`, mixed pipes, direct inheritance, and inner screen reads and input writes. It also checks descendant output and root status after the root exits |
| `conpty.ps1 -Environment WriteRestricted/FullRestricted` | The interactive workload plus Perl and secondary-thread fork, writable files, the original token, and write, WRITE_DAC, and read denials before and after interaction |
| `conpty.ps1 -Environment Existing` | The interactive and Perl workloads in the caller's existing context, using the caller's policy, deployment, and file ACLs |
| `process-chain.ps1 -NativeRelay` | Native or MSYS root, one or three native intermediaries, and automatic re-entry into MSYS. Also checks explicit nested entry, suspended creation, and inheritance after a native update to the default DACL. Runs in all three restricted environments |
| `conpty.ps1 -NativeRelay` | Full interactive test with relay, usable in all three restricted environments and in Existing mode |
| `late-package.ps1` | Adds EXEs and DLLs outside the install root after the target reaches a barrier. It checks first recognition, dynamic modules, fork, explicit bases, `DYNAMIC_BASE`, both `ZeroBits` encodings, and preferred-base conflicts |
| `integrity.ps1` | On-demand comparison of installed paths, lengths, and SHA-256 hashes |

## Running and interpreting the suites

CTest registers native unit tests and PSEC, restricted-token, relay, and ACL suites. It prefers PowerShell 7 and falls back to Windows PowerShell. Set the CMake cache variable `MSYS_SANDBOX_COMPAT_POWERSHELL` to choose the interpreter. Integration suites run serially because they share fixture state. After loading the toolchain environment with `tools/msvc-env.ps1`, run:

```powershell
ctest --test-dir build --output-on-failure
```

Integration scripts default to `build/bin` for `-BinaryDirectory` and find `tools/psec-run.exe` and `tests/bin` from the same build root. Supply `-BinaryDirectory` explicitly for another build. CTest does this automatically. Fixtures and source workloads live in `tests/fixtures`, and unit tests in `tests/unit`. The install layout contains only the production deliverables and documentation. Scripts with `-EvidenceDirectory` accept a separate log directory for each run.

## Release verification

The Windows release workflow builds, installs, and tests the release on Windows Server, then checks both executables from the extracted ZIP. A version tag creates a GitHub Release draft. Before publishing, verify the checksums and run the same package on a Windows 11 x64 host with native PSEC.

```powershell
.\tests\release.ps1 -PackageDirectory PATH_TO_EXTRACTED_ZIP -Version 0.1.0 -Psec
```

This launches the packaged shim through `psec-run` under PSEC 1.0. It checks relay through `cmd.exe` into Git for Windows Bash, a pipe and fork workload, the target's exit code, and a denied file read. Use `-GitRoot` to test a different Git installation.

Choose tests that exercise the change. Process creation, recognition, preparation, and relay changes need fork, scope, and relevant chain tests. Console changes need the interactive suites. Documentation changes need link and example checks. Use the full CTest matrix for cross-cutting changes or release qualification. Run access-denied controls alongside the workloads they protect.

`verify.ps1` defaults to one round. Use `-Repetitions 10` for repeated shell and fork tests. Chain and ConPTY tests default to one secondary-thread fork repetition. Use `-ThreadRepetitions 10` for stress testing, up to 1000. The Perl fixture can also run through the shim as `tests/fixtures/fork.pl 100`. Judge the result by exit status, TAP, the actual workload, and the heap-window release trace for Perl roots and descendants.

## Test boundaries

`scope` requires all seven scenarios to succeed. `process-chain` records the sandbox launcher's default ACL at the native entry before MSYS runs and checks it through the native bridge stages. The workload must run Perl, print its marker, and return exit code 37 through the chain. An access denial or timeout is a failure.

Relay tests require only the creation hook in native intermediaries and check that the other entries and the MSYS address range remain untouched. Descendants inherit the default ACL requested by MSYS. The suspended case requires `ResumeThread` to observe the original suspend count of 1. A native fixture adds a zero-access ACE, checks that descendants inherit the updated default ACL and relay still reaches Bash, then restores its original ACL.

`git-hook.ps1` initializes a test repository, stages files, checks index and worktree status, and commits under the tested context. Git launches its hook in that same context. With a full restricted token, the file-based ref backend can reject creation of `.git/HEAD` when an ancestor directory cannot be listed. The test checks the denial and Git diagnostic, initializes the fixture from the host, then runs the subsequent commands under the original restricted token. It checks hook output, file access, and actual repository state.

`restricted-run` sets ACLs only on its marked `.restricted-fixture` directory and controlled files. It stages test binaries and fixtures while leaving the installed MSYS files in place. Non-AppContainer chain tests record unmodified Bash output in `raw-baseline.*` and require `native-depth-*` workloads to succeed. The `import-name-runtime` fixture creates a test-only `msys-2.0.dll` under the test output directory. [Restricted-token configurations](compatibility.md#restricted-token-fixtures)

Run `Existing` explicitly from the actual harness. It is outside the ordinary host CTest matrix. The existing policy must permit reading and executing the shim, MSYS, and the Perl fixture and writing the test workspace. Check the harness's own deny cases and token and ACL behavior separately. Fixture grants define test conditions. Production checks use paths allowed by the original policy and verify denials for read-only writes, WRITE_DAC, and forbidden reads as applicable. A few canaries cannot establish the entire policy of another environment.

Use `integrity.ps1` if deployment writes change, if an unexpected install-tree change is suspected, or during release qualification. Use `tests/integrity.ps1 -CaptureBaseline -Baseline <FILE>` once to capture the baseline and pass the same file on subsequent comparisons. The integrity check is independent of CTest.

## Image mapping experiments

The initial PSEC comparison used Windows 11 x64 build `26300.9974` and the same Git for Windows MSYS `3.6.10` installation throughout.

| Mapping rule in the experiment | Result |
|---|---|
| `msys-2.0.dll` with no requested base | Common Bash commands and Git init/add/status passed. All three Perl runs failed on the first fork because `msys-crypt-2.dll` differed between parent and child |
| Direct static MSYS imports of `perl.exe` with no requested base | `msys-2.0.dll` and `msys-perl5_42.dll` matched. All three Perl runs failed on the same transitive dependency |
| All transitive static MSYS dependencies of `perl.exe` with no requested base | Minimal fork and a standalone dynamic fixture each passed 3/3. The full Perl workload passed 0/3, failing while reloading a `Time::HiRes` or `List::Util` XS DLL |
| Then-current import-chain classification, restricted to a zero base and zero `ZeroBits` | `verify` passed 11/11, and `late-package` and Git init/add/status within Bash passed. The traced run recorded 1,207 relevant DLL maps with both inputs zero |

With `Time::HiRes` or `List::Util` in isolation, the static-dependency approach passed 1/3 for each module. The broader mapping approach passed 3/3 for each in the same round. In passing samples of the static approach, MSYS reloaded the XS DLL at the parent's actual base, away from the preferred base, and the child called the inherited XS function reference. Failure traces captured the parent's function address and the child's repeated mapping attempts.

Current `late-package` tests eligible DLLs outside the install root. The Perl parent and child check that explicit bases are honored, `DYNAMIC_BASE` uses Windows placement, and preferred-base conflicts retry the original request. Low-address probes cover allowed count and mask limits and a count limit that rejects the preferred range. A separate `LoadLibraryW` probe relocated successfully when one page in the preferred range was occupied. The local Release CTest matrix passed when this approach was introduced. [ADR-0012](decisions/0012-prefer-dll-image-base-at-map.md)

An import scan of Git for Windows 2.56.1 checked 352 EXEs. Of these, 259 directly imported `msys-2.0.dll`, all below `usr`, including 18 under `usr/lib` or `usr/libexec`. The former directory-based search found no additional EXEs that reached the runtime only transitively.
