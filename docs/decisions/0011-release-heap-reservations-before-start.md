# ADR-0011 — Release temporary reservations before MSYS starts

Status: Accepted
Date: 2026-11-18

Supersedes [ADR-0010](0010-reserve-cygheap-at-creation.md).

## Context

The previous design kept cygheap reserved until startup, when MSYS committed pages. Userheap needs its own reservation to succeed, so that design still needed an allocation hook.

## Decision

Reserve `[0x600000000, 0x1000000000)` at the creation of a recognized AMD64 MSYS image. This covers the 24–32 GiB thread stack pool, the 32–40 GiB cygheap range, and the initial userheap range up to the 64 GiB lower bound of the mmap pool. After suspended preparation, the parent checks and releases its own reservation with `MEM_RELEASE` before resuming the thread or returning it to the caller. The caller retains ownership of any reservation it provided.

Stock MSYS reserves and commits both heaps. Remove the `NtAllocateVirtualMemory` hook and its mapping state. A post-creation match still gets image and object preparation without an additional reservation.

## Consequences

The window consumes virtual address space only. An earlier image mapping can still conflict during creation. After release, user-mode loader activity can still occupy an address that MSYS requires.

Matching DLL addresses are a separate fork requirement. Disabling image mapping under the same PSEC and ASLR settings caused Bash and Perl fork failures. Retain the mapping hook for eligible `SEC_IMAGE` sections.
