# ADR-0016 — Let Windows inherit the default DACL during relay

[简体中文](../zh-CN/decisions/0016-drop-relay-default-dacl-baseline.md)

Status: Accepted
Date: 2026-11-23

Updates default DACL comparison in [ADR-0006](0006-opt-in-native-relay.md), [ADR-0008](0008-adapt-requested-object-acls.md), and [ADR-0013](0013-default-relay-with-wow64.md). [ADR-0018](0018-resolve-acl-context-in-each-process.md) later removed the remaining parent-child token comparison.

## Decision

When MSYS sets the current primary token's default DACL through `NtSetInformationToken`, adapt the current input and let Windows authorize and execute the call. Relay relies on normal Windows inheritance so legitimate default DACL changes can reach descendants. Remove the baseline, readback after a successful set, and the creation lock that synchronized them.

At this stage, relay still carried the user SID, restricted principal, and namespace and compared parent and child contexts. The `process-dacl` module continued to handle process and initial-thread object DACLs.
