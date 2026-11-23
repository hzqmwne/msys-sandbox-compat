# ADR-0005 — Give restricted-token launches a private MSYS object directory

[简体中文](../zh-CN/decisions/0005-restricted-token-context.md)

Status: Accepted
Date: 2026-10-20

Extends [ADR-0001](0001-suspended-msys-preparation.md), [ADR-0003](0003-read-only-security-context.md), and [ADR-0004](0004-preserve-sandbox-object-policy.md) to non-AppContainer restricted tokens. [ADR-0008](0008-adapt-requested-object-acls.md) later changed how object ACLs are adapted.

## Context

The original host required a package SID. Stock Bash failed at signal-pipe initialization with both fixed non-AppContainer tokens. Host queries alone could not make fork or re-entry after a native process succeed.

A restricted token does not supply an AppContainer object directory. Sharing the ordinary MSYS namespace ties correctness to existing objects and their ACLs. Full restricting-SID checks also apply to file reads. The launcher must grant the file permissions the workload needs.

## Decision

Accept an AppContainer SID or a restricted token. For non-AppContainer launches, create MSYS object descriptors using the launcher's default DACL. The default DACL preservation in ADR-0004 also applies.

Use the creator host's PID to name a private directory under the current Windows session's `BaseNamedObjects`. The host holds it until the process tree exits. The agent passes the path within that tree. With relay disabled, explicit re-entry after a native process creates a new tree and directory. PSEC uses the AppContainer namespace from Windows.

The sandbox launcher owns the token and file and object policy. The production shim uses the existing token and file rights. Fixed fixtures stage read-only binaries and canaries in a marked workspace. The installed MSYS files stay in place.

## Consequences

Both tested tokens passed Bash, Perl, fork from the initial and secondary threads, several native intermediaries, pipes, and file boundary checks. A normal MSYS session could run alongside them. These results describe the fixture policies. ConPTY with the restricted tokens and integration with external launchers were outside this decision's test scope.
