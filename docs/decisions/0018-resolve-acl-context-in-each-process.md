# ADR-0018 — Resolve the ACL principal from each process's primary token

[简体中文](../zh-CN/decisions/0018-resolve-acl-context-in-each-process.md)

Status: Accepted
Date: 2026-11-23

Updates the root token precheck in [ADR-0003](0003-read-only-security-context.md) and the comparisons in [ADR-0006](0006-opt-in-native-relay.md), [ADR-0013](0013-default-relay-with-wow64.md), and [ADR-0016](0016-drop-relay-default-dacl-baseline.md).

## Context

Earlier agents carried the restricted-state flag, user SID, and compatibility SID. The creator opened the suspended child's token and compared 15 information classes on each token. ADR-0016 removed the default DACL baseline, but the root still picked the ACL principal.

## Decision

Remove parent-child token comparison, its WoW64 exception, and the root `TOKEN_QUERY` precheck. Windows determines the new token, default DACL, and access rights. The agent uses its own primary-token read-only pseudo-handle to resolve the principal according to the existing AppContainer and non-AppContainer rules.

MSYS initializes it when an ACL module is enabled. Native relay initializes it on the first explicit DACL adaptation. The result stays in the process. New agents carry startup data and begin with empty local state. A `TokenDefaultDacl` request still checks whether the supplied handle refers to the current primary token.

When IPC is enabled, the standalone launcher prepares the tree's directory and passes its name and length. Windows enforces the directory ACL. With no directory name, named objects use normal system paths, and eligible pipes can still use the DACL transform.

## Validation

Targeted regressions covered normal and WoW64 launches, chain tests with PSEC, WriteRestricted, and FullRestricted, PSEC ConPTY, and ACLs. An ordinary native relay created a FullRestricted child through Windows, and the child kept its restricted token and passed file-access controls. A `SYSTEM`-only default DACL test covered creation-returned handles, the suspend state, and Windows denying reopen by PID.
