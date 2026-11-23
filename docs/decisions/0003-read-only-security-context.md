# ADR-0003 — Read the security context without reopening the token

[简体中文](../zh-CN/decisions/0003-read-only-security-context.md)

Status: Accepted
Date: 2026-10-20

Related: [ADR-0001](0001-suspended-msys-preparation.md). Subsequent decisions added cold-start compatibility after native intermediaries and native relay. [ADR-0018](0018-resolve-acl-context-in-each-process.md) removed the root token precheck.

## Context

Native descendants of MSYS kept their AppContainer package SID in the tested PSEC, but could not reopen their own token. Anonymous native events worked. Win32 named events were denied even with an explicit private descriptor. Querying the namespace path and creating an NT event at that path worked.

Read-only samples showed a package ACE on the first Bash token object, with that ACE absent from a native descendant and the next cold-start Bash. Switching the host to a pseudo-handle and removing its event probe let the second Bash resume. It still stopped at a token query during initialization.

## Decision

Use `GetCurrentProcessToken` for the host's own read-only queries. Use `GetAppContainerNamedObjectPath` and `TokenSessionId` to obtain the object path directly. Leave the token, its object security descriptor, and its default DACL alone.

For a recognized MSYS root, check whether its actual token can be opened for `TOKEN_QUERY` before resuming the thread. On denial, use the existing failure path to terminate the target and close the handles. Native targets continue without agent preparation.

## Consequences

The host no longer depends on reopening its own token or creating a Win32 named event. Native re-entry works. The root token precheck identifies an observed MSYS initialization failure and allows early cleanup. Successful token queries or a preserved package SID are insufficient to establish that an entire MSYS chain works.
