# ADR-0006 — Add an opt-in process creation relay for native intermediaries

[简体中文](../zh-CN/decisions/0006-opt-in-native-relay.md)

Status: Accepted
Date: 2026-10-20

Partially supersedes [ADR-0001](0001-suspended-msys-preparation.md). Related: [ADR-0004](0004-preserve-sandbox-object-policy.md), [ADR-0005](0005-restricted-token-context.md). [ADR-0013](0013-default-relay-with-wow64.md) changed the default and added WoW64. [ADR-0016](0016-drop-relay-default-dacl-baseline.md) and [ADR-0018](0018-resolve-acl-context-in-each-process.md) removed the DACL baseline and token comparison.

## Context

Propagation originally stopped when MSYS started a native tool. A later MSYS launch worked through an explicit shim call, which required changing the intermediate command. An opt-in relay could carry compatibility through a native intermediary under the existing file and token policy.

## Decision

Add `--native-relay` for the current launch tree. Map the same CRT-free agent, installing only `NtCreateUserProcess` in native images. Confirmed MSYS images use the full set of nine hooks. Classify and prepare descendants while suspended and retain the caller's requested suspend state.

The initial relay compared parent and child security context and the default object policy using read-only queries. A mismatch, failed query, or failed preparation returned an error. The supported path was the AMD64 creation entry. A nested shim recognized the existing relay and reused that context, including for the native ConPTY session host.

## Consequences

PSEC and both fixed tokens passed native and MSYS roots, one or three native intermediaries, automatic Bash and Perl re-entry, fork, secondary-thread fork, pipes, exit status, and ConPTY. The native tests verified that only the creation entry changed and that the other eight entries and MSYS address range stayed intact.

Opting in adds compatibility code and checks to native child creation. Calls outside the supported entry, pre-existing processes outside the tree, and native programs that dynamically load MSYS were outside scope.
