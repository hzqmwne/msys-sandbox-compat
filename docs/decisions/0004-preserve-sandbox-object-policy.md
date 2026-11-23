# ADR-0004 — Preserve the launcher's default object DACL through MSYS startup

[简体中文](../zh-CN/decisions/0004-preserve-sandbox-object-policy.md)

Status: Superseded by [ADR-0008](0008-adapt-requested-object-acls.md)
Date: 2026-10-20

This decision extended [ADR-0001](0001-suspended-msys-preparation.md) and [ADR-0003](0003-read-only-security-context.md). It kept read-only context queries and the checks before resume.

## Context

The target workload started Bash, ran native tools, and entered Bash or Perl again. In the tested MSYS, cold startup replaced the default object DACL with an ordinary user template. That dropped the launcher-supplied package or logon access. The native descendant's token object then lacked the access needed on the next MSYS cold start. The launcher's initial DACL already supported the first MSYS startup.

## Decision

Save the initial `TokenDefaultDacl` in the host. In recognized MSYS images, intercept `NtSetInformationToken` only when the current primary token and `TokenDefaultDacl` are requested. Supply the saved initial ACL to that call. Pass through other tokens and information classes.

Preserve token identity, capabilities, restricting SIDs, privileges, and file policy. Native processes use the explicit compatibility entry point after native intermediaries and are untouched in the default mode.

## Consequences

Native descendants and later cold starts can reopen the objects they need. This added a ninth hook. The end-to-end test requires native entry, Bash, several unmodified native intermediaries, another Bash or Perl, fork, secondary-thread fork, pipes, access denials, and correct exit status. Existing object hooks still handle explicit descriptors.
