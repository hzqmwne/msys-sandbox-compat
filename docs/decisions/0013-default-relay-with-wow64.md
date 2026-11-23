# ADR-0013 — Enable native relay by default and cover WoW64 intermediaries

Status: Accepted
Date: 2026-11-23

Updates the default and architecture scope in [ADR-0006](0006-opt-in-native-relay.md). [ADR-0016](0016-drop-relay-default-dacl-baseline.md) later removed default DACL comparison. [ADR-0018](0018-resolve-acl-context-in-each-process.md) removed token comparison and the WoW64 exception.

## Context

A native root or intermediary can be AMD64 or WoW64. Default propagation needs to cover chains that alternate between them and preserve the caller's suspend request.

## Decision

Enable native relay by default. Turning off relay or the propagation module stops it. The inner ConPTY host inherits the outer settings. An explicitly nested shim reuses the existing relay.

WoW64 uses the same AMD64 agent through the AMD64 process creation entry in its transition layer. Native processes install only the creation hook. Full MSYS runtime adaptation continues to apply to AMD64 MSYS images.

At this stage, token comparison across WoW64 accepted a difference only in the UAC virtualization bit confirmed by `TokenVirtualizationEnabled`. Other access flags, token fields, and restricted default DACLs were still compared.

## Validation

Normal-token and native PSEC 1.0 tests passed Bash fork and exit status with a WoW64 root, AMD64-to-WoW64 re-entry, and alternating AMD64 and WoW64 processes. Both caller architectures retained their requested suspend state.

See the [command-line reference](../getting-started.md#native-relay) for the current flag.
