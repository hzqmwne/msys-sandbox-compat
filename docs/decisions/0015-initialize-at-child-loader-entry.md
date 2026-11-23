# ADR-0015 — Initialize compatibility at the child's loader entry

Status: Accepted
Date: 2026-11-23

Updates initialization timing and parent-child responsibilities from [ADR-0001](0001-suspended-msys-preparation.md).

## Context

The creator can request that the child stay suspended so it can inspect or update application startup context. MSYS needs its layout preparation and hooks before the loader uses the program image and runtime.

## Decision

While the child is suspended, the parent handles creation attributes, maps the agent and its matching `ParentStartData`, and arranges initialization on first entry to `LdrInitializeThunk`. The structure carries the parent's actual EXE base and native path. The child uses these when needed. The parent releases its own creation-time reservation before resuming or returning the suspended child. [Heap-window lifetime](0011-release-heap-reservations-before-start.md)

The child restores the loader entry, selects modules from its actual image and token, applies the EXE layout and hooks, and returns to the loader. Application startup context and the loader entry are handled separately. Early initialization uses the agent's existing CRT, import, TLS, and global-constructor constraints. The startup context changes only after validating the new EXE view. The original view remains mapped.

## Validation and consequences

The creator's suspend semantics remain intact. Errors before resume are reported by the creation call. Later initialization errors surface as the child exit status. Normal-token and native PSEC 1.0 tests verified the context observed by suspended callers. Unmapping the original EXE view caused a Perl fork child to fail startup in the tested PSEC, so the original view stays mapped. Combining this implementation with [MSYS2 PR #403](https://github.com/msys2/msys2-runtime/pull/403) still requires validation.
