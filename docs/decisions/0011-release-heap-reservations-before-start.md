# ADR-0011 — Release temporary reservations before MSYS starts

Status: Accepted
Date: 2026-11-18

Supersedes [ADR-0010](0010-reserve-cygheap-at-creation.md).

## Context

The previous design kept cygheap reserved until startup, when MSYS committed pages. Userheap needs its own reservation to succeed, so that design still needed an allocation hook.

## Decision

Reserve `[0x200000000, 0x1000000000)` (`[8,64)` GiB) at the creation of a recognized AMD64 MSYS image. The original `[24,64)` GiB window covered the runtime thread stack pool, cygheap, and the initial userheap range up to the lower bound of the mmap pool. The 2026-11-25 expansion covers low preferred DLL addresses observed in the tested MSYS2 and Git for Windows installations. After suspended preparation, the parent checks and releases its own reservation with `MEM_RELEASE` before resuming the thread or returning it to the caller. The caller retains ownership of any reservation it provided. [Fork stress and layout measurements](../testing.md#psec-fork-stress-and-address-sampling)

Stock MSYS reserves and commits both heaps. Remove the `NtAllocateVirtualMemory` hook and its mapping state. A post-creation match still gets image and object preparation without an additional reservation.

## Consequences

The window consumes virtual address space only. Windows establishes the initial image mappings before the reservation on the tested build, so an overlapping image mapping can cause process creation to fail. The reservation precedes PEB and initial thread allocation. After release, the loader or a newly created thread can still occupy an address that MSYS requires.

Matching DLL addresses are a separate fork requirement. Disabling image mapping under the same PSEC and ASLR settings caused Bash and Perl fork failures. Retain the mapping hook for eligible `SEC_IMAGE` sections.
