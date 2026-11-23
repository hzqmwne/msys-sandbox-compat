# Architecture decisions

[简体中文](../zh-CN/decisions/README.md)

These records describe the decisions in effect at the time. For current behavior, see the [design](../design.md) and [changelog](../../CHANGELOG.md).

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-suspended-msys-preparation.md) | Suspended preparation and import-name recognition | Accepted. Recognition and initialization were updated by 0012 and 0015 |
| [0002](0002-native-console-handle-owner.md) | ConPTY inside PSEC and a native owner for the initial handles | Accepted. Session-host relay was updated by 0013 |
| [0003](0003-read-only-security-context.md) | Read-only context queries and a root token precheck | Accepted. The precheck was removed by 0018 |
| [0004](0004-preserve-sandbox-object-policy.md) | Preserve the launcher's default object DACL | Superseded by 0008 |
| [0005](0005-restricted-token-context.md) | A private MSYS object directory per restricted-token launch | Accepted |
| [0006](0006-opt-in-native-relay.md) | Opt-in native creation relay | Accepted. Default and architecture scope were updated by 0013, token comparison removed by 0018 |
| [0007](0007-production-artifacts.md) | Separate the shim from the PSEC test tool | Accepted |
| [0008](0008-adapt-requested-object-acls.md) | Adapt the current object ACL | Accepted. The baseline and creation DACL behavior were updated by 0016 and 0017 |
| [0009](0009-minhook-relocation-backend.md) | MinHook relocation for ntdll entry points | Accepted |
| [0010](0010-reserve-cygheap-at-creation.md) | Reserve cygheap at its original address during creation | Superseded by 0011 |
| [0011](0011-release-heap-reservations-before-start.md) | Release temporary reservations before MSYS starts | Accepted |
| [0012](0012-prefer-dll-image-base-at-map.md) | Prefer the PE base for eligible DLL mappings | Accepted |
| [0013](0013-default-relay-with-wow64.md) | Default native relay across AMD64 and WoW64 | Accepted. The token comparison exception was removed by 0018 |
| [0014](0014-conpty-preserve-redirected-stdio.md) | Preserve redirected streams in ConPTY auto mode | Accepted |
| [0015](0015-initialize-at-child-loader-entry.md) | Initialize at the child's loader entry | Accepted |
| [0016](0016-drop-relay-default-dacl-baseline.md) | Let Windows inherit the default DACL during relay | Accepted |
| [0017](0017-adapt-process-dacl-at-creation.md) | Adapt explicit process and thread DACLs at creation | Accepted |
| [0018](0018-resolve-acl-context-in-each-process.md) | Resolve the ACL principal in each process | Accepted |

Use a new ADR for a changed decision and link the superseded record. Minor implementation changes belong in the changelog and Git history.
